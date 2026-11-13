# Upload admission

Okuru admits at most four concurrent multipart uploads across processes using the same Redis database and prefix. Public client addresses have one slot each; a shared or private peer, including a loopback Apache reverse proxy, shares the global four-slot limit. By default forwarded client-address headers are not trusted. A busy upload receives HTTP 429; an unavailable admission store fails closed with HTTP 503.

Each upload must maintain an average of at least 32 KiB/s after a 30-second grace period, in addition to the existing idle and absolute timeouts. The rate is measured as the application reads the request body. If Apache or ModSecurity buffers a request before forwarding it, this limit does not protect those upstream components; they need their own limits.

Leases expire after the longer configured read or write timeout plus ten minutes so a crashed process cannot retain a slot indefinitely. If a handler remains stuck beyond that duration the lease can expire while it is still running; it is therefore an admission bound, not a guarantee of exclusive execution after expiry. All cooperating processes must use the same Redis service and prefix.

Deploy this version to all cooperating processes; older versions do not honor these leases. The Redis account needs `EVAL`/`EVALSHA`, `EXISTS`, `SET`, `GET`, and `DEL` on the configured prefix. An interrupted reservation or release can keep a slot occupied until its TTL expires. The keys use the same Redis Cluster hash slot, but a real cluster has not been tested.

With clients grouped behind a proxy, a single client can consume the shared capacity. The limits mitigate resource exhaustion but cannot provide per-visitor fairness without an authenticated client identity or a correctly configured trusted proxy.
