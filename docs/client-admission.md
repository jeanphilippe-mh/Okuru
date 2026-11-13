# Client admission primitives

The admission helpers provide an address bucket and Redis-backed, fixed-window counters for callers. This change introduces the helpers; it does not itself enable a limit on any route.

By default, client-provided forwarding headers are ignored. `OKURU_TRUSTED_PROXY_CIDRS` may list only reverse proxies known to overwrite or append the actual client's address to `X-Forwarded-For`. Use explicit `/32` or `/128` proxy addresses, never untrusted client ranges. Validate the deployed proxy's forwarding behavior before enabling trust: a trusted proxy that forwards an unmodified header makes its value forgeable. Malformed configuration and forwarded chains fail closed. IPv6 client addresses are grouped by `/64`.

Without independently trusted forwarding, a loopback, private, link-local or carrier-grade NAT identity may represent multiple visitors. The admission helper therefore uses its global budget instead of imposing a smaller per-visitor budget on the whole group. This does not provide fairness between those visitors or prevent a distributed attack from exhausting a global budget.

Counters use the configured Redis database and prefix. They expire after their window; an atomic per-client and global check bounds accepted admissions and the number of newly created identity keys. A SHA-256 digest rather than a raw address is used in the key. This is pseudonymisation, not anonymity: an IPv4 address may be guessed from its hash. Redis errors fail admission closed. Processes must share the same Redis database and prefix for their counters to coordinate.
