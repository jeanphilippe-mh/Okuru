# Runtime health and recovery

Okuru exposes two health endpoints on its HTTPS listener. Each accepts GET and HEAD, sends `Cache-Control: no-store` and can respond even when the application's normal request slots are occupied. A GET returns a small JSON object. HEAD returns the same status code with an empty body.

| Path | What a monitoring client sees | Intended use |
| --- | --- | --- |
| `/ping` | HTTP 200 with `{"status":"alive"}` when Echo can answer | Check whether the HTTPS worker is responding. |
| `/ready` | HTTP 200 with `{"status":"ready"}` after Redis and initial archive recovery are ready and a recent disk probe confirms upload capacity, otherwise HTTP 503 with `{"status":"unavailable"}` | Decide whether to direct application traffic to this instance. |

## Redis and startup recovery

The worker listens even if Redis is offline at startup. It probes the application Redis database immediately and every five seconds with a two-second deadline. It sends PING, then verifies a write, read and deletion on a new, randomly named key under `<REDIS_PREFIX>runtime_health_*`. The Lua script uses SET NX so it cannot overwrite an existing key. It gives the key a ten-second expiry before reading it. Redis ACLs for the application account must allow PING, EVAL, SET, GET and DEL on the appropriate keys in addition to the application's existing permissions.

A failed probe closes admission as soon as its result is known. The last success also expires after fifteen seconds if the monitor stops updating. New application requests receive HTTP 503 with `Retry-After: 5`. Health checks read the most recent result in memory. Polling the HTTP endpoints adds no Redis commands.

On startup, Okuru waits for a successful Redis probe, then reconciles the upload publication journal and initializes storage before admitting requests. It retries failed storage initialization every five seconds while Redis is ready. The independent [seven-day archive sweep](archive-cleanup.md#seven-day-disk-deadline) starts even if Redis is offline.

After initialization, a temporary Redis failure leaves the upload worker in place. When Redis is writable again, admission reopens on a successful probe. A resumable client can query its last committed offset if the Redis data and local staging files survived. A process replacement creates a new upload generation, and an unpublished upload can require a fresh start. Disk capacity and per-transfer errors continue to be handled by the individual operations.

## Continuous archive-storage checks

After startup recovery, a ten-second probe verifies the directory identity against a held reference, reads at most one directory entry, and checks the volume’s free bytes using the upload quota primitive. Above `OKURU_STORAGE_MIN_FREE_BYTES` it creates, synchronizes and removes a private one-byte file in that directory. It has one outstanding operation and uses one exclusive random canary name per process. It neither scans the archive tree nor uses Redis. The last disk sample expires after thirty seconds if filesystem operations stall. Initial state and transitions are logged.

New archive writes also check directory identity at request admission. Concurrent admissions can share one lookup and each waits at most two seconds. The original upload reservations still check the exact size of each transfer, the configured logical quota and archive count. Reads use the last sample and can remain admitted until a missing or replaced directory is detected, normally within ten seconds. If the filesystem probe stalls, the previous sample expires after thirty seconds. A readable directory with insufficient space or a failed write test closes admission only for archive uploads, preparation and finalization. Existing share reads, downloads, deletion and cancellation can still reach the worker. `/ready` returns 503 in either degraded state, and `/ping` remains available. An upstream that removes every unready backend may need separate routing for reads and cleanup. Both HTTP diagnostics read only memory, including while the mount is stalled. Disk activity at upload admission runs outside those paths.

The first trusted directory opened by startup or the independent retention sweep establishes the process’s storage identity. For a dedicated filesystem, the intended mount must therefore be present **before the process starts**. On Debian, set the actual archive path in a systemd service drop-in, for example:

```ini
[Unit]
RequiresMountsFor=/srv/okuru/data
```

The seven-day sweep, Redis expiry cleanup, archive deletion, and removal of prepared-upload journals and block directories act through directory handles checked against this identity. If the original mount is absent, cleanup of its contents resumes after it returns. Operations already admitted can still encounter filesystem errors. Some upload I/O, journal reads and quota housekeeping use pathnames between checks. The orphan staging collector, collision-marker creation and directory synchronization also resolve pathnames. If the mount changes during one of these operations, verification at the start of the sweep does not bind those later lookups to the original volume. Drain uploads and stop the service for a planned mount replacement. A fresh process can then adopt the intended new directory.

## Unresponsive Echo worker on systemd

In the supplied unit the parent process checks the worker through the loopback interface by sending a real HTTPS request to `/ping`. It requires TLS 1.3, the local certificate and its DNS or IP subject alternative name, HTTP/2, and the expected JSON reply. The check runs every ten seconds with a three-second deadline. It bypasses the public proxy and has a startup grace period of up to thirty seconds.

The parent sends systemd watchdog notifications while Echo answers. If Echo or the parent stalls, missing notifications trigger the unit's 90-second watchdog. systemd signals the supervisor, allows up to fifteen seconds for termination, and restarts the unit after five seconds. The unit allows four starts in fifteen minutes to limit repeated attempts. These are supervised recovery deadlines, so service can remain unavailable longer than a single probe interval.

Before each probe the supervisor reads the configured certificate from `cert.pem`. It reuses the HTTP/2 connection while that certificate matches and is valid. If the file changes, it establishes a new connection and verifies the certificate presented by the worker. A missing, malformed, expired or mismatched certificate prevents a successful probe. Check `systemctl status okuru.service` for the TLS verification status and confirm that the worker serves the certificate from `cert.pem`.

After the startup grace period, only a verified HTTP/2 response from `/ping` with the expected body keeps the watchdog active. A persistent certificate error, a stalled handshake or a hanging handler therefore triggers the same systemd restart policy. Correct the certificate or its deployment if restarts reach the unit's rate limit. A Redis outage alone leaves the HTTP worker running. Direct execution of the binary provides the health endpoints and Redis retries. Recovery from a fully stalled process requires an external supervisor.

On Debian, inspect the current watchdog status and recent service events with:

```sh
systemctl status okuru.service
systemctl show okuru.service -p StatusText -p Result -p NRestarts
journalctl --namespace=okuru -u okuru.service --since '15 minutes ago'
```
