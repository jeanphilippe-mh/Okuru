# Archive deletion and expiration

Redis expiry immediately removes the access metadata. Okuru subscribes to expiration events for the configured Redis database and reconciles disk archives with Redis at startup and once a minute. A separate Go worker enforces a seven-day disk deadline even if the subscription, the Redis server or the Redis expiry is unavailable.

After a successful download, Okuru can remove an archive early only when no views remain and all tracked reservations and continuation sessions are complete or no longer resumable. Redis atomically checks the authenticated file record, active operations and session index before removing the file record, related session records and any associated password record. The archive is then unlinked; reconciliation retries if that removal fails. Downloads with views remaining are preserved. Incomplete transfers remain resumable until their session or link expires. If Okuru cannot establish that all activity has finished, it retains the archive until expiry.

A completed response means the application handed the verified bytes to its HTTP writer without error; it does not prove that a browser received or saved them, especially behind a buffering proxy. A failed write alone, incomplete range coverage, concurrent active transfer, changed representation or Redis error must not establish successful completion. Expiration of the link remains authoritative even for a transfer already open; an open file may continue to be read subject to operating system and filesystem behavior.

Reconciliation examines only regular `<canonical UUID>.zip` files directly inside `OKURU_FILE_FOLDER`. It skips symlinks, directories and unrelated names. It removes files whose Redis metadata is absent, and retries eligible completed downloads when records are present. A Redis error leaves this reconciliation pending and is logged.

## Seven-day disk deadline

The disk worker begins as the Go process starts, before it connects to Redis. It scans the configured archive directory and its private publication journal in batches of 128 entries and repeats once a minute. An archive becomes eligible when its last modification time is at least 168 hours old. Okuru stamps the sealed ciphertext once when it links it directly for publication or creates its private journal witness. Publication retries, Redis recovery, reads and download resumes preserve that timestamp. For existing or restored archives the timestamp already on disk determines the deadline.

The worker unlinks an eligible regular `<canonical UUID>.zip` even if its Redis key still exists or has lost its TTL. It checks file identity and modification time again before unlinking. For a pending publication it checks the private journal, session ID and witness. An active publishing session keeps its lock until it finishes. Without a local publishing instance the worker uses the process-wide ownership lock to exclude concurrent publishers. If another instance owns publication, that instance performs the check.

At expiry the worker durably renames a proven journal so publication recovery cannot replay it. It removes the public link only when it identifies the same regular file as the witness. It then removes the private ciphertext and intent, including a witness never made public. Following an interruption the next scan completes the retirement. A different public file retains a collision marker. Unrecognizable journals and symbolic links remain available for inspection. Redis handles share metadata, password records and download-session expiry separately. A stale record cannot supply bytes after unlinking.

The first scan catches up after downtime. While the service and filesystem are available, allow approximately one scan interval plus the duration of a pass. Filesystem errors are logged and retried on the following pass. An open download may continue to read through its existing file descriptor on a platform that supports it. An independently scheduled Debian cron job can run alongside Okuru. If it also deletes archives, restrict it to the same dedicated directory and eligible published files, respecting the journal exclusions.

The data directory must be dedicated to Okuru; a UUID filename alone does not identify files owned by some other application. A startup scan may discover old expired archives left by the previous bug. Before enabling catch-up deletion, take a backup appropriate to the data policy and review the inventory in dry-run mode:

```ini
# Temporary service environment setting for deployment validation:
Environment=OKURU_CLEANUP_DRY_RUN=true
```

Both the Redis reconciliation and the independent disk worker honor dry-run. Immediate cleanup after a successful download and deliberate user deletion still operate. It records eligible expired archive basenames without logging decryption keys or contents. Remove the setting or set it to false after reviewing the inventory. The default is actual cleanup, since expiration must normally be enforced.

Shorter configured lifetimes still use Redis. An outage can delay physical cleanup beyond such a lifetime until Redis recovers or the seven-day disk deadline is reached. Local unlinking cannot erase backups, snapshots, swap or copies already held by recipients.

If a crash occurs before the intent is fully written, the worker can retire the old private witness once it excludes a live writer for that file ID. Independent uploads continue. It also collects an overdue `archive.tmp` in an abandoned upload staging directory after authenticating the staging marker and obtaining its lock. This removes the original hard link left by a crash before normal request cleanup. Active uploads and incomplete resumable sessions retain their own ownership locks and lifecycle.
