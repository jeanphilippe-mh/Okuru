# Router tests

This suite exercises the `router` package and its HTTP middleware. It covers request-size and concurrency limits, encrypted multipart parsing and CSRF, bounded HTTP/2 transfers, error responses, safe logging, sharing links and recovery of abandoned staging files. It also contains regression tests for specific Echo advisory behaviors.

The end-to-end upload test requires a disposable Redis instance via `OKURU_TEST_REDIS_ADDR`; it skips when the address is absent. Other cases use local test HTTP servers, simulated clients and subprocesses. The advisory regression tests cover their stated configurations only; they do not establish the behavior of a deployed proxy.

See the [test suite guide](../../README.md) for the test runner and shared prerequisites.
