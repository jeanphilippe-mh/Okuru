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
	"syscall"
	"time"

	"github.com/jeanphilippe-mh/Okuru/router"
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
			fmt.Fprintf(os.Stderr, "[ERROR] {\"event\":\"logging.supervisor_failed\",\"level\":\"error\",\"time\":%q,\"msg\":\"Could not locate executable\"}\n", time.Now().UTC().Format(time.RFC3339Nano))
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
	if len(os.Args) >= 2 && os.Args[1] == "--internal-worker" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	Flags()
	configureLogging()
	if err := run(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func run() error {
	rand.Seed(time.Now().UnixNano())
	timeouts, err := loadHTTPTimeouts()
	if err != nil {
		return err
	}

	countryDB := os.Getenv(GeoIPCountryDatabaseEnv)
	if err := ConfigureGeoIPCountry(countryDB); err != nil {
		log.WithField("event", "geoip.database_unavailable").Warn("Local GeoIP country database unavailable")
	} else if countryDB == "" {
		log.WithField("event", "geoip.disabled").Info("Local GeoIP country lookup is not configured")
	} else {
		entry := log.WithField("event", "geoip.database_loaded")
		if built, ok := GeoIPCountryBuildTime(); ok {
			entry = entry.WithField("database_built_at", built.Format(time.RFC3339))
		}
		entry.Info("Local GeoIP country database loaded")
	}
	defer CloseGeoIPCountry()

	pool := NewPool()
	defer CloseRedisPool()
	defer CloseShortLinkPool()
	c := pool.Get()
	redisReady := Ping(c)
	_ = c.Close()
	if !redisReady {
		return fmt.Errorf("Redis is unavailable")
	}

	cleanupContext, stopCleanup := context.WithCancel(context.Background())
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		RunFileCleanup(cleanupContext)
	}()
	defer func() {
		stopCleanup()
		<-cleanupDone
	}()

	e := router.NewWithTimeouts(timeouts.transferIdle, timeouts.read, timeouts.write)

	ex, err := os.Executable()
	if err != nil {
		return err
	}
	router.ConfigureErrorHandler(e, filepath.Join(filepath.Dir(ex), "views"))

	// Start and force TLS 1.3 server with HTTP/2 and ALPN.
	certFile := "cert.pem"
	keyFile := "key.pem"
	tlsConfig := newServerTLSConfig()

	s := &http.Server{
		Addr:              ":" + APP_PORT,
		ErrorLog:          NewHTTPDiagnosticLogger(log.StandardLogger()),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       timeouts.read,
		WriteTimeout:      timeouts.write,
		IdleTimeout:       timeouts.idle,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         tlsConfig,
		Handler:           e,
	}

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
	// Restore Echo's original startup artwork without fabricating audit events.
	fmt.Fprint(os.Stdout, EchoStartupBanner())
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
