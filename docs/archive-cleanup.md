# Archive deletion and expiration

Redis expiry immediately removes the access metadata. Physical ZIP cleanup uses two paths: an expiry subscription for prompt deletion, plus a reconciliation at startup and every minute to repair missed events, restarts and outages. The old shared wildcard subscription could stop permanently when a password expired; the new subscriber ignores unrelated records, scopes notifications to the configured database, reconnects and stops with the application context.

After a successful download, Okuru can remove an archive early only when no views remain and all tracked reservations and continuation sessions are complete or no longer resumable. Redis atomically checks the authenticated file record, active operations and session index before removing the file record, related session records and any associated password record. The archive is then unlinked; reconciliation retries if that removal fails. Downloads with views remaining are preserved. Incomplete transfers remain resumable until their session or link expires. Legacy or mixed-version records whose activity cannot be proved safe remain until expiry.

A completed response means the application handed the verified bytes to its HTTP writer without error; it does not prove that a browser received or saved them, especially behind a buffering proxy. A failed write alone, incomplete range coverage, concurrent active transfer, changed representation or Redis error must not establish successful completion. Expiration of the link remains authoritative even for a transfer already open; an open file may continue to be read subject to operating system and filesystem behavior.

Reconciliation examines only regular `<canonical UUID>.zip` files directly inside `OKURU_FILE_FOLDER`. It skips symlinks, directories and unrelated names. It removes files whose Redis metadata is absent, and retries eligible completed downloads when records are present. A Redis error retains the file and logs the failure.

The data directory must be dedicated to Okuru; a UUID filename alone does not identify files owned by some other application. A startup scan may discover old expired archives left by the previous bug. Before enabling catch-up deletion, take a backup appropriate to the data policy and review the inventory in dry-run mode:

```ini
# Temporary service environment setting for deployment validation:
Environment=OKURU_CLEANUP_DRY_RUN=true
```

This makes background reconciliation retain archives and metadata it would otherwise delete; it does not disable immediate cleanup after a successful download or deliberate user deletion. It records eligible expired archive basenames without logging decryption keys or contents. Remove the setting or set it to false after reviewing the inventory. The default is actual cleanup, since expiration must normally be enforced.

During healthy operation the fallback may retain a ZIP for up to roughly one minute after Redis expiry, plus scan duration. A Redis outage can extend retention, because deletion fails closed. Monitoring and a post-outage catch-up check remain necessary. No guarantee of secure erasure from SSD, snapshots, backups or swap is implied.

The upload staging path and Go's system temporary directory are unchanged. Crash-left staging directories are not deleted by this ZIP reconciliation; that would require a separately defined ownership and in-progress upload policy. No filesystem-wide cleanup is attempted.
