# Client admission primitives

The admission helpers provide address buckets and Redis-backed, fixed-window counters to the routes that enforce upload, archive and secret-creation limits.

By default, client-provided forwarding headers are ignored. `OKURU_TRUSTED_PROXY_CIDRS` may list only reverse proxies known to overwrite or append the actual client's address to `X-Forwarded-For`. Use explicit `/32` or `/128` proxy addresses, never untrusted client ranges. Validate the deployed proxy's forwarding behavior before enabling trust: a trusted proxy that forwards an unmodified header makes its value forgeable. Malformed configuration and forwarded chains fail closed. IPv6 client addresses are grouped by `/64` for admission; logs retain the validated full address.

## Direct Apache reverse proxy

The following is an example for a topology where external visitors connect **directly** to Apache and Apache alone proxies to Okuru on `127.0.0.1`. It is not suitable as written for a CDN, load balancer, another proxy in front of Apache, or a deployment where another local process may reach Okuru. Inspect the effective virtual-host, included files, Apache version and loaded modules first. In particular, `mod_remoteip` can replace Apache's client address from an inbound header; an unsafe `RemoteIPHeader` configuration can therefore falsify the value forwarded to Okuru. Confirm that `RemoteIP*`, `RequestHeader` and `ProxyAddHeaders` directives from all included configurations have the intended effects before any change.

With `mod_headers` loaded and the deployment's request processing verified, a reviewed virtual-host configuration can remove inbound client-supplied forwarding values before proxying, while asking Apache to append the address it actually sees:

```apache
RequestHeader unset X-Forwarded-For
ProxyAddHeaders On
```

Verify the deployed `mod_proxy_http2` version actually adds the address for the configured `h2://` backend; the Apache 2.4.65 implementation does this, but its behavior on another distribution or configuration must be checked independently. Do not rely on a forwarded header merely because it is present. Validate syntax with `apache2ctl configtest` before applying a reviewed configuration, and verify behavior against the actual running proxy. Sources: [mod_headers](https://httpd.apache.org/docs/2.4/mod/mod_headers.html#requestheader), [mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html), and [Apache 2.4.65 HTTP/2 proxy implementation](https://github.com/apache/httpd/blob/2.4.65/modules/http2/h2_proxy_session.c).

Only after that verification, an operator may explicitly set the immediate Apache peer in Okuru's service environment, for example:

```dotenv
OKURU_TRUSTED_PROXY_CIDRS="127.0.0.1/32"
```

This example does not enable trust by default. If Apache actually connects over IPv6 loopback, `::1/128` must be considered separately. Restart the Okuru service after changing its environment. Trusting loopback authenticates an address, not an Apache process: **any local process that can reach the backend using the trusted address can forge the header**. Restrict backend access through appropriate process/network isolation or an authenticated proxy connection; a firewall for external traffic alone does not authenticate local processes.

Enabling this variable changes **both** the client address recorded in the request/action logs and the identity used for upload and rate-limit admission. Validate the effect on client and shared budgets before production use. Check at least one request from a known external IPv4 client and, where applicable, IPv6; compare `client_ip` with the independently known egress address while `peer_ip` remains the Apache address and `client_ip_source` is `forwarded`. Repeat with a deliberately forged inbound `X-Forwarded-For` header: the logged client must still be the actual test client's address, not the injected value. Avoid sending tokens or secrets during this test. A VPN, NAT, network relay or upstream gateway may legitimately mean the observed IP differs from a user's device address.

Without independently trusted forwarding, a loopback, private, link-local or carrier-grade NAT identity may represent multiple visitors. The admission helper therefore uses its global budget instead of imposing a smaller per-visitor budget on the whole group. This does not provide fairness between those visitors or prevent a distributed attack from exhausting a global budget.

Counters use the configured Redis database and prefix. They expire after their window; an atomic per-client and global check bounds accepted admissions and the number of newly created identity keys. A SHA-256 digest rather than a raw address is used in the key. This is pseudonymisation, not anonymity: an IPv4 address may be guessed from its hash. Redis errors fail admission closed. Processes must share the same Redis database and prefix for their counters to coordinate.


## Optional local country lookup

`OKURU_GEOIP_DATABASE` may point to a locally installed country-capable MMDB, such as a GeoLite Country or DB-IP Country database. The database is not included in Okuru and must be obtained, attributed and updated according to its provider's license. [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) requires attribution; [GeoLite](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) requires an account and license key for downloads. Select a provider independently and install the data in a directory writable only by administrators and readable by the service.

When configured, Okuru loads a bounded snapshot on startup and performs lookups locally; it does not transmit visitor IP addresses to a third-party service. Replace the database atomically and restart the service to load an update. A missing or invalid database does not block requests: `client_country_status` reports the failure and the country is omitted. Private, loopback, selected non-globally-reachable special-use and unvalidated addresses are never assigned a country.

A country is an estimate for the observed IP, not proof of a person's location or identity. VPNs, proxies, mobile networks, database coverage and stale allocations can cause inaccuracies. `client_country_code` uses ISO alpha-2, and `client_country_name` is a French name when available, otherwise English. The `geoip.database_loaded` startup event records the database build time.
