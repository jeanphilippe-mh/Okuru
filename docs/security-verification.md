# Security verification and build requirements

The minimum Go version is 1.27.3. The dependency update pins golang.org/x/net to 0.62.0 and updates its required x/crypto, x/sys and x/text dependencies in go.mod/go.sum. Rebuild the executable: editing go.mod does not patch a deployed binary. Check the active executable with `go version -m <actual ExecStart binary>`.

The workflow runs module verification, go vet, race-enabled tests and govulncheck v1.9.0 with a fresh public database. Redis is a disposable test service without production credentials. All GitHub actions are pinned to verified release commit SHAs; token permissions are read-only and checkout credentials are not persisted. Existing CodeQL remains separate.

The logging changes use formatting methods where formatting was intended, fix inconsistent placeholder counts, and use generic retrieval-failure messages instead of printing secret-bearing errors. They restore normal go vet execution; checks are not disabled to hide findings.

Local validation used Go 1.27.3 and a fresh HTTPS copy of the official Go vulnerability database, because direct database connections from the scanner timed out. The full module index and all advisory records for the project's modules were preserved in the review workspace with provenance. The symbol scan found no called vulnerabilities and no imported-package vulnerabilities. One required-module-only advisory remains without an application call path; this is not a claim that every installed dependency is universally free of vulnerabilities. The CI uses the live database again.

Recommended local checks:

```sh
go mod verify
go vet ./...
# Supply an isolated Redis address to run integration tests rather than skip them:
OKURU_TEST_REDIS_ADDR=127.0.0.1:6379 REDIS_HOST=127.0.0.1 REDIS_PORT=6379 go test -race -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

No runtime HTTP/2 denial-of-service exploit is required to validate the dependency fix, and none was attempted in production. Recheck before release: advisories and maintained versions change over time. A Go/toolchain rollback can reintroduce known vulnerabilities; use a forward fix instead.
