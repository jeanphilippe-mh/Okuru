# Reliable archive expiration

Redis expiry immediately removes the access metadata. Physical ZIP cleanup uses two paths: an expiry subscription for prompt deletion, plus a reconciliation at startup and every minute to repair missed events, restarts and outages. The old shared wildcard subscription could stop permanently when a password expired; the new subscriber ignores unrelated records, scopes notifications to the configured database, reconnects and stops with the application context.

Reconciliation examines only regular `<canonical UUID>.zip` files directly inside `OKURU_FILE_FOLDER`. It skips symlinks, directories and unrelated names. It removes a ZIP only when Redis confirms that the matching file metadata is absent. A Redis error retains the file and logs the failure. Exhausted but unexpired file metadata is retained, preserving the last reserved download.

The data directory must be dedicated to Okuru; a UUID filename alone does not identify files owned by some other application. A startup scan may discover old expired archives left by the previous bug. Before enabling catch-up deletion, take a backup appropriate to the data policy and review the inventory in dry-run mode:

```ini
# Temporary service environment setting for deployment validation:
Environment=OKURU_CLEANUP_DRY_RUN=true
```

This records the basename of archives that would be removed and keeps them. It does not log decryption keys or contents and does not disable deliberate user deletion. Remove the setting or set it to false after reviewing the inventory. The default is actual cleanup, since expiration must normally be enforced.

During healthy operation the fallback may retain a ZIP for up to roughly one minute after Redis expiry, plus scan duration. A Redis outage can extend retention, because deletion fails closed. Monitoring and a post-outage catch-up check remain necessary. No guarantee of secure erasure from SSD, snapshots, backups or swap is implied.

The upload staging path and Go's system temporary directory are unchanged. Crash-left staging directories are not deleted by this ZIP reconciliation; that would require a separately defined ownership and in-progress upload policy. No filesystem-wide cleanup is attempted.
