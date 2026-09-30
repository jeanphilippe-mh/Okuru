# Logs for secret-sharing endpoints

The application logs route patterns such as `/:password_key` and `/file/:file_key`, never concrete URLs or query strings. Error categories replace raw error messages in the request log. Redis passwords and generated deletion links are not logged.

Apache runs separately and must also avoid recording URLs containing UUIDs and encryption keys. Apply an access-log format without the request line, path, query, Referer or user agent in the share virtual host, for example:

```apache
LogFormat "%h %t \"%m\" %>s %b" okuru_private
CustomLog ${APACHE_LOG_DIR}/okuru-access.log okuru_private
```

Remove or replace other `CustomLog` directives for this virtual host that still use `%r`, `%U`, `%q`, Referer or other URL-bearing fields. Check global/inherited logging too. Review Apache errors, ModSecurity audit logs and upstream proxy logs independently: this application change does not redact those logs. Audit/body logging can contain secret values even when access logs omit URLs. Limit access and retention, and treat historical logs containing live share URLs as sensitive. Do not disable WAF protections as a logging workaround.
