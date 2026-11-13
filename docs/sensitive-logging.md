# Logs for secret-sharing endpoints

The application logs route patterns such as `/:password_key` and `/file/:file_key`, never concrete URLs or query strings. Error categories replace raw error messages in the request log. Redis passwords and generated deletion links are not logged. Client-controlled request metadata is truncated by byte length on UTF-8 boundaries before JSON encoding (host 255 bytes, user agent 256 bytes, remote IP 64 bytes, method and content-length 32 bytes each). This bounds each field, but truncation does not redact secrets that a client places near the beginning of a header; restrict log access accordingly.

The supplied `okuru.service` sends stdout and stderr to a dedicated systemd journal namespace, rather than appending indefinitely to `/var/log/okuru.log`. It limits the logging rate; bursts may be dropped. Install `deploy/systemd/journald@okuru.conf.d/20-retention.conf` at `/etc/systemd/journald@okuru.conf.d/20-retention.conf` before activating the updated service. The configuration requests persistent retention with a 128 MiB namespace budget, smaller per-file rotation and a 30-day retention target. Journald rotates and removes archived files, so limits and time retention are not an exact instantaneous disk cap. The quota applies only to this namespace; Apache, ModSecurity, the default journal and other applications still need their own policies.

Review the deployed unit and its drop-ins with `systemctl cat okuru.service`, as well as any existing logging/rotation configuration, before applying changes. After installing the namespace configuration and unit, reload systemd and restart the relevant namespace and Okuru service during an appropriate maintenance window. Verify with `journalctl --namespace=okuru -u okuru.service` and `journalctl --namespace=okuru --disk-usage`. Namespace support and the effective configuration must be verified on the actual host. The former `/var/log/okuru.log` is not removed or truncated by this change: preserve or rotate it separately under the site's retention policy. See the systemd documentation for [journal namespaces](https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html) and [journal limits](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html).

Apache runs separately and must also avoid recording URLs containing UUIDs and encryption keys. Apply an access-log format without the request line, path, query, Referer or user agent in the share virtual host, for example:

```apache
LogFormat "%h %t \"%m\" %>s %b" okuru_private
CustomLog ${APACHE_LOG_DIR}/okuru-access.log okuru_private
```

Remove or replace other `CustomLog` directives for this virtual host that still use `%r`, `%U`, `%q`, Referer or other URL-bearing fields. Check global/inherited logging too. Review Apache errors, ModSecurity audit logs and upstream proxy logs independently: this application change does not redact those logs. Audit/body logging can contain secret values even when access logs omit URLs. Limit access and retention, and treat historical logs containing live share URLs as sensitive. Do not disable WAF protections as a logging workaround.
