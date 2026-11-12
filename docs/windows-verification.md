# Windows verification before deployment

The Windows storage and lock implementations must be executed and checked on a
real Windows system and filesystem before deployment. Cross-compilation alone
cannot validate NTFS ACL inheritance, `LockFileEx`, or deletion and renaming of
open handles. Use a disposable checkout and a temporary test directory; do not
run these checks against production storage.

From PowerShell, with the Go version specified in `go.mod` and the dependencies
available, first run the local filesystem and interprocess tests:

```powershell
go test -count=1 -v -run 'TestWindows|TestStorageGuard|TestQuotaMultiprocessAdmissionAndCrashRecovery' ./utils
```

The tests create temporary directories, set test-only ACLs and start or terminate
child processes. Review any skipped or failed test rather than treating compilation
as a pass. Test the same filesystem and service-account ACL model intended for
production, including `FILE_SHARE_DELETE`, inherited DACLs, concurrent processes,
free-space exhaustion and recovery after a forced stop. A locally successful test
does not establish the behavior of network shares or other filesystems.

The prepared Windows implementation retains handles from the local drive root
to the storage directory during operations and checks each handle's DACL and
reparse attributes. Archive and multipart-part opens are relative to anchored
directory handles. UNC shares, device namespaces, reparse points and ambiguous
DOS names or trailing dots/spaces are intentionally refused. This can reject
an existing installation using such a path. `OBJ_DONT_REPARSE` failures have no
insecure fallback; its behavior and support must be checked on the actual
Windows version and filesystem.

Some creation, publication and removal operations still use absolute paths.
Held handles deny incompatible delete/rename access, but do not revoke existing
rights to modify attributes, DACLs or reparse data. Ensure untrusted accounts
have no such pre-existing handles, and that path ownership and ACLs are trusted
before starting the service. A complete guarantee against those capabilities
requires handle-relative operations throughout. Test all assumptions on the
actual NTFS configuration; do not infer them from cross-compilation.

To include the complete application and download-session tests, start a separate
Redis instance bound only to loopback, with persistence disabled and no production
data. The isolated instance must allow the test suite to create and remove
short-lived test ACL users. Substitute its actual address below:

```powershell
$env:OKURU_TEST_REDIS_ADDR = '127.0.0.1:53740'
go test -p 1 -count=1 -timeout=8m ./...
Remove-Item Env:OKURU_TEST_REDIS_ADDR
```

Stop the disposable Redis instance afterwards. Record Windows version,
architecture, filesystem, Go version, effective service identity and ACLs, and
complete test output. This document prepares a validation; it does not claim it
has already been performed.
