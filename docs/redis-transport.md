# Redis transport

The main connection pool, dedicated short-link pool, archive reconciliation
and Redis expiry subscription use the same transport policy. The Redis
password and commands are sent over the established connection. When TLS is
configured, Okuru completes certificate verification before sending Redis
commands.

## Redis on the same host

The default connection is `localhost:6379`. With `REDIS_TLS=false` or an
unset `REDIS_TLS`, Okuru allows only `localhost` and literal loopback
addresses. `localhost` connects to `127.0.0.1` and falls back to `::1` if the
IPv4 connection fails. Okuru selects those addresses directly. Redis can keep
its current password and database settings on this deployment. Configure Redis
to listen on loopback if only applications on that host use it.

## Remote Redis or TLS on loopback

Configure Redis to accept TLS and set the endpoint in the Okuru service
environment:

```sh
REDIS_HOST=redis.internal.example
REDIS_PORT=6380
REDIS_TLS=true
```

Okuru supports TLS 1.2 and later and checks the certificate chain and the
`REDIS_HOST` identity. Use a DNS name listed in the certificate's Subject
Alternative Name (SAN), or an IP address listed as an IP SAN. The same
verification applies to TLS on loopback. The example uses the platform trust
store. If Redis uses a private CA, install its root in that store or set
`REDIS_TLS_CA_FILE` to the absolute path of a PEM bundle that the Okuru service
account can read. When specified, that bundle is the complete set of trust
anchors for Redis. An unreadable file or a bundle with no certificates causes
the connection to fail.

Keep the Redis password in the service's existing protected configuration.
TLS settings apply to Redis alone. The HTTPS settings for the public share
site and the Redis database numbers are independent.

After restarting Okuru with the connection settings, check that its `/ready`
endpoint returns HTTP 200. If readiness fails, check reachability of the TLS
port, the endpoint name or IP in the certificate, service access to the CA
bundle, and Redis credentials. If short links are enabled, create and resolve
one to verify the separate Redis database. Redis host, TLS mode and CA path
are included in the pool configuration, so changing the configuration replaces
the previous pool.
