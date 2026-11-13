# Password-protected archive admission

The scrypt work factor is unchanged. Expensive password-derived archive work is admitted without an unbounded wait, including both initial downloads and range continuations. Busy or rate-limited requests return 503 or 429 before consuming a view or continuation budget. The single-worker limit applies to cooperating processes sharing the same protected storage root; independent hosts with different roots need additional coordination. Passwordless age X25519 archives do not perform scrypt.

The new fixed-window budgets are 6 initial KDF operations per public client per minute, 4 per file share per minute, 8 continuation operations per public client and per share per minute, and 24 combined KDF operations globally per minute. Unidentified shared proxies use the global limit for their common identity. These limits can affect clients that generate many range requests; `Retry-After` is advisory and a continuation session may expire before a client retries. They cannot prevent a sustained attacker from consuming a shared global budget.


Redis admission counters require access to the configured prefix and the `EVAL`/`EVALSHA`, `GET`, `SET` and `PTTL` commands. Admission fails closed when Redis is unavailable. Deploy all cooperating processes with the same Redis database, prefix and protected storage root. Never delete the persistent `.okuru-archive-kdf.lock` file while an instance is running: replacing it can create independent locks.
