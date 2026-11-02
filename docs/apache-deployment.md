# Apache and ModSecurity deployment proposal

These are reviewable templates, not an automatic deployment or a replacement for the complete current virtualhost. Preserve the existing certificate configuration, reverse-proxy TLS verification, CSP hashes, security headers and upload limits. No JavaScript or slider changes are required.

## Capture and validate the active configuration

```sh
sudo apache2ctl -t
sudo apache2ctl -S
sudo apache2ctl -M
sudo apache2ctl -t -D DUMP_INCLUDES
sudo grep -RniE 'LogLevel|LogFormat|CustomLog|GlobalLog|ErrorDocument|ProxyErrorOverride|REQBODY_ERROR|SecAudit|SecDebug' /etc/apache2 /etc/modsecurity
```

Review included files and per-module `debug` overrides. Do not paste live share tokens or passwords from logs. A second access log or ModSecurity audit log may still retain secrets even after changing the main access format.

## Serve the existing error views locally

From the checked-out repository, install static copies of the existing HTML pages and the supplied JSON files. `/var/www/errors` is the requested location; no `/var/www/okuru-errors` directory is used.

```sh
sudo install -d -m 0755 /var/www/errors/api
sudo install -m 0644 views/[45][0-9][0-9].html /var/www/errors/
sudo install -m 0644 deploy/apache/errors/api/*.json /var/www/errors/api/
```

Include `deploy/apache/share-errors.conf` inside the TLS virtualhost **before** `ProxyPass / ...`. Replace the old `LogLevel debug`, `CustomLog ... vhost_combined` and absolute-URL ErrorDocument directives instead of keeping duplicate definitions. Review the complete resulting virtualhost before reload.

- `/errors/` is excluded from the proxy and mapped to `/var/www/errors/`.
- Go-generated responses pass through with `ProxyErrorOverride Off`.
- Apache-generated browser errors keep the existing HTML appearance through local error documents; 502 pages remain available while Go is unavailable.
- Apache-generated API errors use local JSON documents, retain their HTTP error status and do not issue external 302 redirects.
- The access log omits request paths, query strings, Referer and cookies, while keeping method, status, bytes, duration and request ID. This does **not** sanitize module-generated error messages or ModSecurity audit logs.

Check file permissions and the existing rotation rule; do not add a second rule for the same log path:

```sh
sudo stat -c '%a %U:%G %n' /var/log/apache2 /var/log/apache2/*share.jeanphilippe.io.log
sudo cat /etc/logrotate.d/apache2
sudo logrotate --debug /etc/logrotate.conf
```

## Handle malformed JSON in ModSecurity

Keep the WAF and JSON parsing enabled. The official recommended configuration checks `REQBODY_ERROR` at the start of phase 2 with `deny,status:400`, normally in rule 200002. Inspect the rule already loaded and its actions first.

If necessary, adapt `deploy/modsecurity/api-body-errors.conf` for this vhost and include it before competing phase-2 rules. Verify that local rule ID 1001201 is unused. It deliberately avoids logging the parser's error text, which can include body fragments. It does not disable other WAF logging or sanitise their messages.

The production logs established a JSON parse failure, but did not establish which component generated the initial 500. Consequently this template's final status must be verified on the actual Apache/ModSecurity stack; native parser failures before phase 2 may require a ModSecurity maintenance update rather than another rule. Do not change SecInterceptOnError or disable CRS blindly.

Test syntax, then apply only after approval:

```sh
sudo apache2ctl configtest
# Only after successful validation and deployment approval:
sudo systemctl reload apache2
```

Verify malformed JSON gives HTTP 400 and JSON, no Location; a real WAF refusal remains 403, not 302; application errors retain their status; and a controlled backend outage in staging returns the local 502 HTML page. Do not stop production to test it.

## Service isolation and PGP follow-up

`deploy/systemd/okuru-hardening.conf` is an optional drop-in. It keeps the current paths and account, adds a private system temporary directory, umask 0077 and privilege restrictions. This does not change Go's default temporary-file flow to data/tmp and does not create an in-memory filesystem. It is not equivalent to migrating from the administrative freebox account to a dedicated non-sudo account; that migration requires checking file ownership and the active unit.

Deploy the drop-in only after reviewing `systemctl cat` for the actual service and confirming access to its certificate/key, environment file, data and log files. It requires a service restart. Umask does not retroactively change old ZIP permissions.

The security.txt Encryption key is not its signing key. Publish the signing **public** key with fingerprint `521F8D84F35CA57C269DE63153F91DA3DB1CDC6A`, or re-sign with a key whose public counterpart is already published. Never publish a private key. No replacement key or signature has been fabricated in this proposal.

References:
- https://httpd.apache.org/docs/2.4/mod/core.html#errordocument
- https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxyerroroverride
- https://github.com/owasp-modsecurity/ModSecurity/blob/v2/master/modsecurity.conf-recommended
