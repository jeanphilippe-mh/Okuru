package main

// Source: https://echo.labstack.com/guide
// Source: https://echo.labstack.com/cookbook/http2/
// Source: https://github.com/verybluebot/echo-server-tutorial/

import (
	"context"
	"crypto/tls"
	"fmt"
	stdlog "log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeanphilippe-mh/Okuru/router"
	"github.com/jeanphilippe-mh/Okuru/routes"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"
)

var DebugLevel bool

func Flags() {
	pflag.BoolVar(&DebugLevel, "debug", false, "--debug")
	defer pflag.Parse()
}

func configureLogging() {
	// Keep severity visible before each structured JSON payload.
	log.SetFormatter(NewAuditJSONFormatter())

	// Output to stdout instead of the default stderr.
	// Can be any io.Writer, see below for File example.
	log.SetOutput(os.Stdout)

	if DebugLevel {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	// Go libraries that use the standard logger share the structured output.
	// Logrus writes to stdout, never back to the standard logger.
	stdlog.SetFlags(0)
	stdlog.SetPrefix("")
	stdlog.SetOutput(NewStandardDiagnosticWriter(log.StandardLogger()))
	LogConfiguration()
}

type httpTimeouts struct {
	read, write, idle, transferIdle time.Duration
}

func positiveDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("Invalid positive duration in %s", name)
	}
	return duration, nil
}

func loadHTTPTimeouts() (httpTimeouts, error) {
	var result httpTimeouts
	var err error
	if result.read, err = positiveDuration("OKURU_HTTP_READ_TIMEOUT", 2*time.Hour); err != nil {
		return result, err
	}
	if result.write, err = positiveDuration("OKURU_HTTP_WRITE_TIMEOUT", 2*time.Hour); err != nil {
		return result, err
	}
	if result.idle, err = positiveDuration("OKURU_HTTP_IDLE_TIMEOUT", 90*time.Second); err != nil {
		return result, err
	}
	if result.transferIdle, err = positiveDuration("OKURU_HTTP_TRANSFER_IDLE_TIMEOUT", 2*time.Minute); err != nil {
		return result, err
	}
	return result, nil
}

// Keep Go's default key exchange groups so supported Go versions can offer
// hybrid post-quantum key exchange without pinning a fixed group list.
func newServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--internal-log-supervisor" {
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] {\"msg\":\"Could not locate executable\",\"event\":\"logging.supervisor_failed\",\"level\":\"error\",\"time\":%q}\n", time.Now().UTC().Format(time.RFC3339Nano))
			os.Exit(1)
		}
		workerArgs := append([]string{"--internal-worker"}, os.Args[2:]...)
		status, err := RunLogSupervisor(executable, workerArgs, "/var/log/okuru.log", os.Stdout)
		if err != nil {
			// RunLogSupervisor reports the classified failure to every
			// destination that remains available before returning.
			os.Exit(1)
		}
		os.Exit(status)
	}
	supervisedWorker := len(os.Args) >= 2 && os.Args[1] == "--internal-worker"
	if supervisedWorker {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	Flags()
	configureLogging()
	if err := run(supervisedWorker); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func run(supervisedWorker bool) error {
	rand.Seed(time.Now().UnixNano())
	timeouts, err := loadHTTPTimeouts()
	if err != nil {
		return err
	}

	stopTracking := StartArchiveDirectoryTracking()
	defer stopTracking()
	stopRetention := StartArchiveRetention()
	defer stopRetention()

	defer CloseRedisPool()
	defer CloseShortLinkPool()
	health := NewRuntimeHealth()
	serviceContext, stopService := context.WithCancel(context.Background())
	var background sync.WaitGroup
	background.Go(func() { health.Run(serviceContext) })
	background.Go(func() { maintainArchiveStorage(serviceContext, health) })
	defer func() {
		stopService()
		background.Wait()
	}()

	e := router.NewWithTimeouts(timeouts.transferIdle, timeouts.read, timeouts.write)
	routes.RuntimeHealth(e, health)

	ex, err := os.Executable()
	if err != nil {
		return err
	}
	router.ConfigureErrorHandler(e, filepath.Join(filepath.Dir(ex), "views"))

	// Start and force TLS 1.3 server with HTTP/2 and ALPN.
	certFile := "cert.pem"
	keyFile := "key.pem"
	tlsConfig := newServerTLSConfig()

	// Shutdown can time out while a finalizer still owns staging files. Interrupt
	// its request and join handlers before releasing any disk owner or Redis pool.
	requests, cancelRequests := context.WithCancel(context.Background())
	var serving sync.RWMutex
	closed := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serving.RLock()
		defer serving.RUnlock()
		if closed {
			http.Error(w, "Server shutting down", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path != "/ping" && r.URL.Path != "/ready" && !health.CanServe(router.NeedsArchiveCapacity(r)) {
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("Retry-After", "5")
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"unavailable","message":"Service temporarily unavailable"}`))
			} else {
				http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		e.ServeHTTP(w, r)
	})
	s := &http.Server{
		Addr:              ":" + APP_PORT,
		ErrorLog:          NewHTTPDiagnosticLogger(log.StandardLogger()),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       timeouts.read,
		WriteTimeout:      timeouts.write,
		IdleTimeout:       timeouts.idle,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         tlsConfig,
		Handler:           handler,
		BaseContext:       func(net.Listener) context.Context { return requests },
	}

	defer func() {
		cancelRequests()
		_ = s.Close()
		serving.Lock()
		closed = true
		serving.Unlock()
	}()

	if err := http2.ConfigureServer(s, &http2.Server{
		MaxConcurrentStreams: 32,
		IdleTimeout:          timeouts.idle,
		ReadIdleTimeout:      time.Minute,
		PingTimeout:          15 * time.Second,
		WriteByteTimeout:     timeouts.transferIdle,
	}); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	listener = netutil.LimitListener(listener, 128)
	defer listener.Close()
	geoPath, geoPathErr := GeoIPAutoDatabasePath()
	if geoPathErr != nil {
		MarkGeoIPDatabaseUnavailable()
		log.WithField("event", "geoip.cache_unavailable").Warn("Local GeoIP cache unavailable")
	} else {
		geoContext, stopGeo := context.WithCancel(context.Background())
		geoDone := StartGeoIPCountryUpdater(geoContext, geoPath)
		defer func() {
			stopGeo()
			<-geoDone
			_ = CloseGeoIPCountry()
		}()
	}
	// Restore Echo's original startup artwork without fabricating audit events.
	fmt.Fprint(os.Stdout, EchoStartupOutput(supervisedWorker))
	serverDone := make(chan error, 1)
	go func() {
		log.WithFields(log.Fields{"event": "server.start", "address": s.Addr, "echo_version": echo.Version, "tls_min": "1.3"}).Info("HTTPS server starting")
		serverDone <- s.ServeTLS(listener, certFile, keyFile)
	}()

	// Wait for interrupt signal to gracefully shutdown the server with a 5 seconds timeout.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	select {
	case <-quit:
	case err := <-serverDone:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
	health.SetStorageReady(false)
	log.WithField("event", "server.shutdown").Info("Server shutdown requested")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Shutdown(ctx)
	if err != nil {
		_ = s.Close()
		return err
	}
	log.WithField("event", "server.stopped").Info("Server stopped gracefully")
	return nil
}

// Keep Echo responsive while Redis or startup reconciliation is unavailable.
// After recovery, preserve the owner generation across temporary Redis outages.
func maintainArchiveStorage(ctx context.Context, health *RuntimeHealth) {
	wait := time.NewTimer(0)
	defer wait.Stop()
	retrying := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-wait.C:
		}
		if !health.RedisReady() {
			wait.Reset(time.Second)
			continue
		}
		// Establish the archive root once at startup. Subsequent probes only
		// recognize this same directory, including after a mount is restored.
		var monitor *ArchiveStorageMonitor
		var stopUploads func()
		err := InitializeArchiveDirectory(FILEFOLDER)
		if err == nil {
			monitor, err = OpenArchiveStorageMonitor(FILEFOLDER)
		}
		if err == nil {
			stopUploads, err = StartPreparedUploads(ctx)
		}
		if err != nil {
			if monitor != nil {
				_ = monitor.Close()
			}
			if !retrying && ctx.Err() == nil {
				log.WithField("event", "storage.recovery_pending").Warn("Archive storage recovery will retry")
			}
			retrying = true
			wait.Reset(5 * time.Second)
			continue
		}
		defer monitor.Close()
		defer stopUploads()
		health.SetStorageReady(true)
		defer health.SetStorageReady(false)
		log.WithField("event", "storage.ready").Info("Archive storage ready")
		cleanupDone := make(chan struct{})
		go func() { defer close(cleanupDone); RunFileCleanup(ctx) }()
		health.RunStorage(ctx, monitor)
		<-cleanupDone
		return
	}
}
