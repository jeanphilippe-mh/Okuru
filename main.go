package main

// Source: https://echo.labstack.com/guide
// Source: https://echo.labstack.com/cookbook/http2/
// Source: https://github.com/verybluebot/echo-server-tutorial/

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/jeanphilippe-mh/Okuru/router"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
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

	// Log as JSON instead of the default ASCII formatter
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	if DebugLevel {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	go CleanFileWatch()
}

func main() {
	rand.Seed(time.Now().UnixNano())

	e := router.New()

	// Start and force TLS 1.3 server with HTTP/2
	certFile := "cert.pem"
	keyFile := "key.pem"
	tlsConfig := &tls.Config{}

	server := &http.Server{
		Addr:      ":+APP_PORT",
		TLSConfig: tlsConfig,
		Handler:   e,
	}

	http2.ConfigureServer(server, nil)

	e.Server = server

	e.Logger.Fatal(e.StartTLS(":+APP_PORT", certFile, keyFile))

}
