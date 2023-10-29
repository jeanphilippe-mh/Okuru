package main

// Source: https://echo.labstack.com/guide
// Source: https://echo.labstack.com/cookbook/http2/
// Source: https://github.com/verybluebot/echo-server-tutorial/

import (
        "math/rand"
        "context"
        "os"
        "os/signal"
        "syscall"
        "time"
        "fmt"
        "crypto/tls"
        "net/http"

        "github.com/jeanphilippe-mh/Okuru/router"
        . "github.com/jeanphilippe-mh/Okuru/utils"
        log "github.com/sirupsen/logrus"
        "github.com/labstack/echo/v4"
        "github.com/spf13/pflag"
        "golang.org/x/net/http2"
)

var DebugLevel bool

func Flags() {
        pflag.BoolVar(&DebugLevel, "debug", false, "--debug")
        defer pflag.Parse()
}

func init() {
        Flags()

        pool := NewPool()
        c := pool.Get()
        defer c.Close()
        if !Ping(c) {
                log.Panic("Redis issue is detected")
        }

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

        go CleanFileWatch()
}

const (
        // Version of Echo.
        version = echo.Version
        website = "https://echo.labstack.com"
	banner = `
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

func main() {
        rand.Seed(time.Now().UnixNano())

        e := router.New()

	// Custom error handler for "Internal Server Error", "Not Found", "Forbidden" and "Bad Request".
    	errorPages := map[int]string{
        http.StatusInternalServerError: "views/500.html",
        http.StatusNotFound:           "views/404.html",
        http.StatusForbidden:          "views/403.html",
	http.StatusBadRequest:         "views/400.html",
    	}

    	// Custom error handler
    	e.HTTPErrorHandler = func(err error, c echo.Context) {
        code := http.StatusInternalServerError
        if he, ok := err.(*echo.HTTPError); ok {
            code = he.Code
        }

        if page, exists := errorPages[code]; exists {
            // Render the custom error page
            if err := c.File(page); err != nil {
                c.Logger().Error(err)
            }
        } else {
            e.DefaultHTTPErrorHandler(err, c)
        }
    	}

        // Start and force TLS 1.3 server with HTTP/2 and ALPN.
        certFile := "cert.pem"
        keyFile := "key.pem"
        tlsConfig := &tls.Config{
                MinVersion: tls.VersionTLS13,
                MaxVersion: tls.VersionTLS13,
                NextProtos: []string{"h2"},
        }

        s := &http.Server{
                Addr:       ":" + APP_PORT,
		ReadHeaderTimeout: 3 * time.Second,
                TLSConfig:  tlsConfig,
                Handler:    e,
        }

        http2.ConfigureServer(s, &http2.Server{})

        // Print the banner message to the log.
        fmt.Printf(banner, version, website)

        go func() {
                fmt.Printf("Starting https server at %s\n", s.Addr)
                err := s.ListenAndServeTLS(certFile, keyFile)
                if err != nil && err != http.ErrServerClosed {
                        e.Logger.Fatal(err)
                }
        }()

        // Wait for interrupt signal to gracefully shutdown the server with a 5 seconds timeout.
        quit := make(chan os.Signal, 1)
        signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
        <-quit
        fmt.Println("Shutting down server...")
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        err := s.Shutdown(ctx)
        if err != nil {
                e.Logger.Fatal(err)
        }
        fmt.Println("Server gracefully stopped")
}
