# Echo v5 migration

Okuru uses Echo v5.4.6 with Go 1.27.4. The migration keeps the existing request limits, secure multipart processing before CSRF, cookie attributes, error formats and token-safe logging. The Go server continues to require TLS 1.3 and retains Go's default key-exchange groups. Changing the Echo version does not change the TLS policy of a separate Apache reverse proxy.

The error handler uses Echo's status-code interface, including router-generated 404 and 405 errors, and does not append an error after a response has begun. If the response state cannot be determined, it aborts the response rather than returning an implicit success. The multipart handler also recognizes Echo v5's body-limit sentinel and retains HTTP 413. The transfer deadline middleware uses the underlying Echo response writer. The static middleware is explicitly rooted at the `public` directory next to the executable; its filesystem root must not depend on the service working directory. A local pre-routing middleware retains v4's handling of trailing slashes and encoded paths.

Two Echo v5 behavior changes need particular attention when validating clients. CSRF checks only the first value from each configured source: for example, a request whose first form token is wrong and second form token is valid is rejected instead of accepting the later value as v4 could. Clients should send a single token per source. Echo v5's static HTML fallback is used for an unmatched route, not to replace a 404 deliberately returned by a matching handler; Okuru's distributed `public` directory does not currently contain an `index.html` fallback. The migration tests cover these distinctions, but deployments with locally added assets should also check their own behavior.

Echo v5 normally rejects state-changing `Sec-Fetch-Site: same-site` requests before checking a CSRF token. Okuru explicitly retains the v4 behavior: same-site requests must pass the existing token check, and cross-site or unrecognized values are rejected. This does not treat sibling origins as trusted and does not bypass token validation.

## Verification

The Go tests are maintained under `tests/go` and projected into packages by the test runner. Use an isolated Redis instance and the commands in [tests/README.md](../tests/README.md), in particular:

```sh
go mod verify
go run ./tests/cmd/okurutest tidy -diff
go run ./tests/cmd/okurutest vet
go run ./tests/cmd/okurutest test -race -count=1
node --test tests/*.test.js tests/*.test.cjs
```

The suite includes router-generated errors, CSRF, static asset routing, HTTP/2 transfer limits, resumed downloads and an in-memory TLS handshake with both `X25519MLKEM768` and `X25519`. The TLS test checks the Go server configuration, not Apache or any deployed endpoint. It assumes hybrid TLS support has not been disabled by the execution environment. Run the TLSA and Apache checks documented in the test README when validating a release.

Before deployment, repeat the suite with the actual target Go toolchain and test a staging setup with the intended Apache, TLS certificates, WAF and Redis configuration. Check uploads, downloads and resumptions, share links, API errors and logs. Test each TLS hop independently; see [Apache hybrid TLS](apache-tls-hybrid.md). `govulncheck` must use an available, current vulnerability database; a failed database download is not a clean result.

Keep the previous v4 binary and its configuration available for rollback. On a failed staging or production health check, restore that binary and configuration using the installation's established procedure, restart or reload as appropriate, and verify the same HTTP and TLS checks. This change does not prescribe a Redis data migration; compatibility with live data and the actual operational rollback must be verified in the target environment.
