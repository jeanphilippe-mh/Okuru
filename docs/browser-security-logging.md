# Browser security observations

Okuru's HTML installs a nonce-authorized observer before its other scripts. It
can record CSP violations reported to the document and loading failures for
scripts. A script load failure has an unknown cause: an SRI mismatch, a network
failure, a CSP decision, an extension, or another problem can all look alike.
Do not treat it as proof of an attack or a confirmed integrity mismatch.

The observer sends only a fixed event kind and category to
`/.well-known/okuru-browser-security`. It does not send the page or resource
URL, query, fragment, CSP nonce, original policy, code sample, cookies or
referrer. It uses same-origin `fetch` with `credentials: 'omit'`,
`referrerPolicy: 'no-referrer'`, no redirects and a bounded queue. If the
browser cannot verify those privacy settings, or a report fails, the observer
stops sending. At most five reports are attempted per page.

The endpoint retains the existing CSRF protection. It accepts only a small JSON
object with an allowlisted kind and category, up to 1,024 bytes. Invalid fields,
duplicate fields, unsupported content types and oversized bodies are rejected.
It admits at most 60 requests per minute per server process, including invalid
and blocked requests, before reading the body. There is no unbounded per-client
state and no normal per-request application log for this POST endpoint. The
first request rejected for exceeding the limit in each window emits a bounded
rate-limit warning. A later accepted observation includes a bounded count of
previously suppressed reports.

Accepted observations use the existing `security.browser_report` warning event.
The `kind`, `browser_category`, `source: untrusted_browser` and `suppressed`
fields are bounded values. The existing audit system may additionally include a
request ID and client-address/country metadata according to the configured
trusted-proxy policy. Browser reports can be forged, and a shared rate budget
can be exhausted: these logs are diagnostic signals, not authenticated facts.

The service configuration in this repository sends Okuru logs to
`/var/log/okuru.log` and to the `okuru` systemd journal namespace. For example:

```sh
sudo grep 'security.browser_report' /var/log/okuru.log
sudo journalctl --namespace=okuru -u okuru.service --no-pager | grep 'security.browser_report'
```

Check the actual deployed unit and log configuration before relying on those
paths. Apache and ModSecurity have independent logging and rate controls; review
their configuration in staging, including logs of rejected or malformed requests.
The observer's own requests contain no raw page information, but arbitrary
third-party clients can submit arbitrary HTTP requests to the endpoint.

## Coverage and limitations

The browser makes the CSP and SRI decisions; the server cannot infer them from
a successful HTTP response. Reporting is best effort. It may miss events that
occur before the observer runs, violations in a service worker, an observer
blocked by policy or an extension, navigation/termination, unsupported browser
features, lack of connectivity, WAF blocking, a saturated budget or a failure
to deliver. Browsers that do not send Fetch Metadata cannot use this anonymous
reporting route without satisfying the existing token-based CSRF check, so their
observations can be lost. The service worker's own script is not covered by SRI.

Okuru deliberately does not enable native CSP `report-uri` or `report-to` in
this configuration: native report bodies can include the share URL and original
policy containing the nonce, and a proxy or WAF may log them before application
filtering. A CSP report also does not prove or cover every SRI failure. Browser
integrity-reporting mechanisms have separate compatibility and coverage limits.

Test in staging with the real reverse proxy and ModSecurity rules: open `/` and
`/file`, verify normal interactions, trigger a controlled CSP violation and
script-load error with test assets, and check that only bounded records appear.
Check that POST requests have no cookie or referer, and that ordinary sharing
and upload CSRF protection still works. Never inject a fault into production to
test reporting and never use an actual share link as a test marker.
