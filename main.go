package main

//https://echo.labstack.com/guide
//https://github.com/verybluebot/echo-server-tutorial/

import (
	"math/rand"
	"os"
	"time"
	"context"

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
		log.Panic("Redis problem")
	}

	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	if DebugLevel {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	go CleanFileWatch(ctx context.Context, redisServerAddr string,
	onStart func() error,
	onMessage func(channel string, data []byte) error,
	channels ...string)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	e := router.New()

	e.Logger.Fatal(e.StartTLS(":"+APP_PORT, "cert.pem", "key.pem"))
}
