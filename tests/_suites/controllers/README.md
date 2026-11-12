# Controller tests

This suite exercises the `controllers` package, including private helpers used by the application. Its coverage includes:

- API contract, request validation, token isolation and deletion behavior.
- Upload validation, filename handling, encrypted archive creation and multiple-file archives.
- New and historical archive formats, download authorization, range requests and resumable transfers.
- Error messages, form rendering and the upload form's accessibility attributes.
- Archive encryption benchmarks, with operating-system-specific peak-memory helpers.

The API, download and multi-file integration tests require an isolated Redis instance configured with `OKURU_TEST_REDIS_ADDR`; they skip when it is absent. Tests use temporary storage, not the configured production directory. The original platform suffixes and build constraints on benchmark helpers must be preserved.

See the [test suite guide](../../README.md) for the test runner and shared prerequisites.
