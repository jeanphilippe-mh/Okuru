# Security verification and build requirements

The module specifies Go 1.27.4 and Echo v5.4.6. Go 1.27.4 fixes GO-2026-6859, and age is used for encrypted file storage. Rebuild the executable: editing go.mod does not patch a deployed binary. Check the active executable with `go version -m <actual ExecStart binary>` on a host with the Go toolchain installed.

The workflow runs module verification, go vet, race-enabled tests and govulncheck v1.9.0 with a fresh public database. Redis is a disposable test service without production credentials. All GitHub actions are pinned to verified release commit SHAs; token permissions are read-only and checkout credentials are not persisted. Existing CodeQL remains separate.

The logging changes use formatting methods where formatting was intended, fix inconsistent placeholder counts, and use generic retrieval-failure messages instead of printing secret-bearing errors. They restore normal go vet execution; checks are not disabled to hide findings.

Earlier local validation used Go 1.27.3 and Echo v4; its results and advisories are historical and do not establish the status of the rebuilt v5 binary. Echo's [v5.4.5](https://github.com/labstack/echo/releases/tag/v5.4.5) and [v5.4.6](https://github.com/labstack/echo/releases/tag/v5.4.6) release notes describe fixes to its Redirect and Proxy middleware. Okuru does not register those middleware components, although an independent test exercises the Echo proxy. Review the effective deployment and any local extensions separately. CI uses the live vulnerability database; a failed scan or database download is not a clean result.

Recommended local checks:

```sh
go mod verify
go run ./tests/cmd/okurutest tidy -diff
go run ./tests/cmd/okurutest vet
# Supply an isolated Redis address to run integration tests rather than skip them:
OKURU_TEST_REDIS_ADDR=127.0.0.1:6379 REDIS_HOST=127.0.0.1 REDIS_PORT=6379 go run ./tests/cmd/okurutest test -race
node --test tests/*.test.js tests/*.test.cjs
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The Go runner projects the centralized tests into their source packages, including for vet and module maintenance. A plain `go vet ./...` does not vet the projected test sources, and a plain `go mod tidy` can remove dependencies used only by those tests. Use the runner's `tidy -diff` to check without writing, or its `tidy` command to apply module changes. The equivalent general Go test entry point is `go test -race -count=1 ./...`; omitting `-count=1` intentionally fails the suite harness to prevent stale cached results. Package selection, benchmarks and coverage use the dedicated runner; see the [test suite guide](../tests/README.md).

No runtime HTTP/2 denial-of-service exploit is required to validate the dependency fix, and none was attempted in production. Recheck before release: advisories and maintained versions change over time. A Go/toolchain rollback can reintroduce known vulnerabilities; use a forward fix instead.
