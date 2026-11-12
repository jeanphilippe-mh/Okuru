# Network and Redis resource limits

These are application defaults. Review the effective reverse proxy, service and
Redis configuration separately before deployment; the checked-in service file
does not prove which configuration is active.

- A single process-wide Redis pool permits at most 64 active and eight idle
  connections. Pool acquisition fails immediately at capacity rather than
  waiting without a deadline. The application returns an ordinary dependency
  error when a connection cannot be acquired. Connect operations have a
  three-second timeout; Redis reads and writes each have a five-second timeout.
  Idle connections expire after one minute and connections older than one hour
  are retired on reuse. The pool is closed after active HTTP requests and the
  archive-cleanup worker have been stopped.
- The application no longer runs Redis `CONFIG SET` for every new connection.
  Configure keyspace notifications in Redis if immediate expiry events are
  desired. The existing periodic reconciliation remains necessary to recover
  missed events and is independent of notification delivery; it conservatively
  retains archives when Redis is unavailable.
- At most 128 client connections are accepted, 64 requests are processed, and
  four multipart file uploads are processed concurrently per process. At
  capacity, requests receive HTTP 503. HTTP/2 is limited to 32 concurrent
  streams per connection.
- Bodies other than multipart `POST /file` are limited to 64 KiB before CSRF
  form extraction, including when the request has an unknown content length.
  Multipart `POST /file` retains the existing global HTTP body limit of 1024M;
  that limit includes multipart framing, not just the selected files. The
  separate controller-level file and field limits still apply.
- TLS header reading has a three-second deadline. HTTP keep-alive defaults to
  90 seconds. A request has a two-hour absolute read and write budget and a
  two-minute inactivity limit for each body read or response write. Small
  non-upload request bodies additionally have 30 seconds to arrive. A transfer
  that reaches a deadline can fail; operators supporting slower large transfers
  must choose higher positive durations and ensure their proxy permits them.

Durations use Go's `time.ParseDuration` syntax. Empty values select the defaults;
invalid, zero and negative values cause startup to fail rather than silently
disabling protection:

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `OKURU_HTTP_READ_TIMEOUT` | `2h` | Maximum request reading time. |
| `OKURU_HTTP_WRITE_TIMEOUT` | `2h` | Maximum response time, measured from the request. |
| `OKURU_HTTP_IDLE_TIMEOUT` | `90s` | Idle keep-alive connection timeout. |
| `OKURU_HTTP_TRANSFER_IDLE_TIMEOUT` | `2m` | Maximum inactivity between transfer operations. |

Before multipart parsing, upload admission reserves a conservative budget for
the encrypted multipart staging, final encrypted archive and overhead. It
recounts the storage directory and checks available space on its filesystem.
This path does not spill to the system temporary directory. Cooperating
processes using the same resolved storage directory coordinate admission through
the private `.okuru-quota` registry. An admission lock makes counting and
reservation atomic; each reservation holds its own file lock until the upload
finishes. A later admission reclaims records whose owning process has exited.
A full budget or an unavailable storage check rejects the upload with HTTP 507.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `OKURU_STORAGE_QUOTA_BYTES` | `8589934592` | Maximum accounted bytes in the storage directory. |
| `OKURU_STORAGE_MIN_FREE_BYTES` | `1073741824` | Minimum free bytes to retain on the storage filesystem. |
| `OKURU_STORAGE_MAX_ARCHIVES` | `1000` | Maximum accounted ZIP filenames and in-flight reservations. |

These settings must be positive decimal integers. The archive allowance is an
estimate tied to the current ZIP writer, filename and file-count limits, not a
filesystem-enforced write limit. It can reject uploads conservatively. All
instances must use the same resolved root and the same quota settings, with
reliable cross-process filesystem locks, trusted directory ownership and ACLs.
Instances using other roots, external writers and changes in filesystem space
after admission are not governed by this registry. Apply a filesystem quota and
upstream rate/bandwidth limits when those actors must also be controlled. An
admission lock held by an unresponsive process causes rejection after a bounded
wait rather than disabling accounting. Recognized abandoned staging is
reconciled before admission; unmarked or pre-marker remnants require coordinated
manual cleanup as described in `upload-safety.md`.

An inactive subscriber may remain connected while waiting for Redis expiry
events: it uses a separate connection and does not inherit the short pool read
deadline. Connection and request concurrency limits remain per process; an
upstream proxy may enforce aggregate limits across instances.
