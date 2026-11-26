package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
)

const redisConnectTimeout = 3 * time.Second

type redisPoolConfig struct {
	host, port, password, database string
	tlsMode, tlsCAFile             string
}

func currentRedisPoolConfig(database string) redisPoolConfig {
	return redisPoolConfig{
		host: REDIS_HOST, port: REDIS_PORT, password: REDIS_PASSWORD, database: database,
		tlsMode: os.Getenv("REDIS_TLS"), tlsCAFile: os.Getenv("REDIS_TLS_CA_FILE"),
	}
}

// Tests can replace redisDialContext. Production uses Redigo.
var redisDialContext = redis.DialContext

func (config redisPoolConfig) dial(ctx context.Context, readTimeout, writeTimeout time.Duration) (redis.Conn, error) {
	db, err := strconv.Atoi(config.database)
	if err != nil || db < 0 {
		return nil, errors.New("Invalid Redis database")
	}
	transport, err := config.transport()
	if err != nil {
		return nil, err
	}
	options := []redis.DialOption{
		redis.DialContextFunc(transport.dial),
		redis.DialReadTimeout(readTimeout),
		redis.DialWriteTimeout(writeTimeout),
		redis.DialDatabase(db),
	}
	if config.password != "" {
		options = append(options, redis.DialPassword(config.password))
	}
	// Redigo sends AUTH and SELECT after the transport has connected and, for
	// TLS, verified the peer. It closes the connection if initialization fails.
	return redisDialContext(ctx, "tcp", net.JoinHostPort(config.host, config.port), options...)
}

type redisTransport struct {
	localhost bool
	tls       *tls.Config
}

func (config redisPoolConfig) transport() (redisTransport, error) {
	port, err := strconv.Atoi(config.port)
	if err != nil || port < 1 || port > 65535 {
		return redisTransport{}, errors.New("Invalid Redis port")
	}
	ip, ipErr := netip.ParseAddr(config.host)
	if config.host == "" || config.host == "." || strings.ContainsAny(config.host, " \t\r\n/\\%[]") || (ipErr != nil && strings.Contains(config.host, ":")) {
		return redisTransport{}, errors.New("Invalid Redis host")
	}
	name := strings.TrimSuffix(config.host, ".")
	transport := redisTransport{localhost: strings.EqualFold(name, "localhost")}
	switch config.tlsMode {
	case "", "false":
		if config.tlsCAFile != "" {
			return redisTransport{}, errors.New("REDIS_TLS_CA_FILE requires Redis TLS")
		}
		if !transport.localhost && !ip.Unmap().IsLoopback() {
			return redisTransport{}, errors.New("Redis TLS is required for non-loopback connections")
		}
	case "true":
		transport.tls = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
		if config.tlsCAFile != "" {
			pem, err := os.ReadFile(config.tlsCAFile)
			if err != nil {
				return redisTransport{}, errors.New("Unable to read the Redis TLS CA file")
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return redisTransport{}, errors.New("Redis TLS CA file contains no PEM certificates")
			}
			transport.tls.RootCAs = roots
		}
	default:
		return redisTransport{}, errors.New("REDIS_TLS must be true or false")
	}
	return transport, nil
}

func (transport redisTransport) dial(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, redisConnectTimeout)
	defer cancel()
	dialer := net.Dialer{KeepAlive: 5 * time.Minute}
	var conn net.Conn
	var err error
	if transport.localhost {
		// Numeric addresses keep localhost on loopback even if a resolver or
		// hosts file is misconfigured, while preserving IPv6-only installations.
		_, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		conn, err = dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		if err != nil && ctx.Err() == nil {
			conn, err = dialer.DialContext(ctx, network, net.JoinHostPort("::1", port))
		}
	} else {
		conn, err = dialer.DialContext(ctx, network, address)
	}
	if err != nil || transport.tls == nil {
		return conn, err
	}
	tlsConn := tls.Client(conn, transport.tls)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
