package main

// Source: https://echo.labstack.com/guide
// Source: https://echo.labstack.com/cookbook/http2/
// Source: https://github.com/verybluebot/echo-server-tutorial/

import (
	"crypto/rand"
	"crypto/tls"
	"math/big"
	"math/rand"
	"net/http"
	"os"

	"github.com/jeanphilippe-mh/Okuru/router"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	log "github.com/sirupsen/logrus"
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
	// Generate a secure random seed value for the random number generator
	seed, err := rand.Int(rand.Reader, big.NewInt(1<<62-1))
	if err != nil {
		log.Fatalf("Error generating secure random seed value: %v", err)
	}

	// Create a new rand.Rand object using the generated seed
	rng := rand.New(rand.NewSource(seed.Int64()))

	// Generate a random integer between 0 and 999
	randomInt := rng.Intn(1000)

	// Print the generated random integer
	log.Printf("Random integer: %d", randomInt)

	e := router.New()

	// Start and force TLS 1.3 server with HTTP/2 and ALPN
	certFile := "cert.pem"
	keyFile := "key.pem"
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}

	server := &http.Server{
		Addr:      ":" + APP_PORT,
		TLSConfig: tlsConfig,
		Handler:   e,
	}

	http2.ConfigureServer(server, &http2.Server{})

	e.Server = server

	e.Logger.Fatal(e.StartTLS(":"+APP_PORT, certFile, keyFile))
}
