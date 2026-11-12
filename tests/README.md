# Test suite

This directory contains Okuru's Go tests, grouped by the source package they exercise, and tests for browser assets and Apache integration. Go tests keep the original package names so they can exercise package-private behavior and share test helpers without exposing production internals.

| Suite | Source package | Scope |
| --- | --- | --- |
| [root](_suites/root/README.md) | repository root | application HTTP timeout configuration |
| [controllers](_suites/controllers/README.md) | `controllers` | sharing, uploads, downloads, archives, API and forms |
| [router](_suites/router/README.md) | `router` | middleware, request limits, HTTP and end-to-end uploads |
| [utils](_suites/utils/README.md) | `utils` | storage, encryption, Redis, tokens and platform-specific guards |
| `upload-preflight.test.cjs` | browser upload form | selection validation, error handling and safe text rendering |
| `branding.test.js` | public assets | preview metadata, icons and robots policy |
| `service_worker.test.js` | service worker | registration, Trusted Types and cache behavior |
| `apache_error_contract.py` | Apache configuration | local proxy and error response contract |

The `_suites` directory keeps test source files outside production package directories. The test runner uses a temporary Go overlay to project those files into their original Go packages, so tests retain their package-private access and original working directories. Keep each Go test's original filename, including platform suffixes and build constraints. When adding or removing a Go test, update `tests/suites.manifest` as well; the runner refuses missing or unlisted tests and rejects Go tests discovered outside `tests/` in project source directories. It excludes common generated, dependency and hidden directories from that check.

## Running Go tests

From the repository root, run all Go suites with:

```sh
go test -count=1 ./...
```

The required `-count=1` prevents Go's test cache from returning a stale successful result when the projected test sources or fixtures change. `go test ./...` without that flag deliberately fails in the suite harness. The harness forwards `-race` and common execution options to the projected suites.

Use the dedicated runner to select a package or invoke Go's vet on the projected tests:

```sh
go run ./tests/cmd/okurutest vet
go run ./tests/cmd/okurutest test -race
go run ./tests/cmd/okurutest test -v '-run=TestUploadValidation' -- ./controllers
```

Put package paths after `--`, and use `-flag=value` for flags taking a value. For example, `-- ./utils` runs the utility suite. Use the dedicated runner for `-run` or `-skip` filters, benchmarks, fuzzing, listing tests and coverage; the generic harness rejects these options instead of producing misleading results. Plain `go test -count=1 ./utils` or `go vet ./...` does not by itself include the Go tests stored under `_suites`.

Tests requiring Redis use `OKURU_TEST_REDIS_ADDR`; without it they are skipped. Use an isolated loopback-only Redis instance with no production data: some tests create and remove temporary users and keys. The CI workflow provides a disposable service. Tests also use temporary directories and some launch subprocesses. TLSA script tests require `bash` and `jq`.

Windows-specific tests must run on a real Windows system and intended filesystem. Cross-compilation alone does not validate locks, access control lists or open handles. A cross-compiled test harness invoked with `-exec` also cannot execute its nested runner, so it does not establish that the projected suites ran. See [Windows verification](../docs/windows-verification.md).

## Browser and Apache tests

Run all JavaScript tests from the repository root with Node.js 18 or later:

```sh
node --test tests/*.test.js tests/*.test.cjs
```

The restored Apache contract test runs a disposable local Apache instance and mock backend. It requires Python 3, Apache and its modules; it does not emulate ModSecurity. Use paths appropriate to the host, for example:

```sh
# Debian
python3 tests/apache_error_contract.py --apache /usr/sbin/apache2 --module-dir /usr/lib/apache2/modules
# macOS
python3 tests/apache_error_contract.py --apache /usr/sbin/httpd --module-dir /usr/libexec/apache2
```

See [security verification](../docs/security-verification.md) for the full check sequence. Never treat skipped integration tests as passed tests.
