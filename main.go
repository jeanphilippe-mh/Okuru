package main

// Source: https://echo.labstack.com/guide
// Source: https://echo.labstack.com/cookbook/http2/
// Source: https://github.com/verybluebot/echo-server-tutorial/

import (
	"context"
	"crypto/tls"
	"fmt"
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
	"github.com/labstack/echo/v4"
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
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr.
	// Can be any io.Writer, see below for File example.
	log.SetOutput(os.Stdout)

	if DebugLevel {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

}

const (
	// Version of Echo.
	version = echo.Version
	website = "https://echo.labstack.com"
	banner  = `
   ____    __
  / __/___/ /  ___
 / _// __/ _ \/ _ \
/___/\__/_//_/\___/ %s
High performance, minimalist Go web framework
%s
____________________________________O/_______
                                    O\
`
)

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
		return 0, fmt.Errorf("invalid positive duration in %s", name)
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

func main() {
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

	pool := NewPool()
	defer CloseRedisPool()
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
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}

	s := &http.Server{
		Addr:              ":" + APP_PORT,
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

	// Print the banner message to the log.
	fmt.Printf(banner, version, website)

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	listener = netutil.LimitListener(listener, 128)
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		fmt.Printf("Starting https server at %s\n", s.Addr)
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
	fmt.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Shutdown(ctx)
	if err != nil {
		_ = s.Close()
		return err
	}
	fmt.Println("Server gracefully stopped")
	return nil
}
