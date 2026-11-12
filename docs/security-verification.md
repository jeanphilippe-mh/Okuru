# Security verification and build requirements

The minimum Go version is 1.27.4, which fixes GO-2026-6859. This tree preserves the versions in master, including Echo v4.16.4, and adds age for encrypted file storage. Rebuild the executable: editing go.mod does not patch a deployed binary. Check the active executable with `go version -m <actual ExecStart binary>`.

The workflow runs module verification, go vet, race-enabled tests and govulncheck v1.9.0 with a fresh public database. Redis is a disposable test service without production credentials. All GitHub actions are pinned to verified release commit SHAs; token permissions are read-only and checkout credentials are not persisted. Existing CodeQL remains separate.

The logging changes use formatting methods where formatting was intended, fix inconsistent placeholder counts, and use generic retrieval-failure messages instead of printing secret-bearing errors. They restore normal go vet execution; checks are not disabled to hide findings.

Earlier local validation used Go 1.27.3 and a snapshot of the official Go vulnerability database; its results are historical. A later GitHub scan reported GO-2026-6859 in Go 1.27.3 and GO-2026-6872 / GO-2026-6875 in Echo v4. The Go update addresses GO-2026-6859 after rebuilding; the Go vulnerability database lists all Echo v4 versions as affected by the other two advisories. Echo v4.16.4 is not claimed to resolve them. Deployment-specific exposure needs review and the scanner may still fail. The CI uses the live database; never treat an old clean result as proof of current safety.

Recommended local checks:

```sh
go mod verify
go vet ./...
# Supply an isolated Redis address to run integration tests rather than skip them:
OKURU_TEST_REDIS_ADDR=127.0.0.1:6379 REDIS_HOST=127.0.0.1 REDIS_PORT=6379 go test -race -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

No runtime HTTP/2 denial-of-service exploit is required to validate the dependency fix, and none was attempted in production. Recheck before release: advisories and maintained versions change over time. A Go/toolchain rollback can reintroduce known vulnerabilities; use a forward fix instead.
