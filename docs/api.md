# API contract

All API responses containing tokens, passwords, or errors use `Cache-Control: no-store`.
Browser forms keep their existing `_csrf` field. API clients use the same CSRF protection through `X-CSRF-Token` plus the matching secure cookie. No route is exempted from CSRF checks.

## Create a secret with curl

Use a private working directory for the cookie jar and response files. The examples use fictitious secrets.

```sh
umask 077
mkdir -p api-example
cd api-example
curl --fail-with-body -sS -c cookies.txt -D bootstrap.headers \
  https://share.jeanphilippe.io/api/v1 -o help.txt
csrf_token=$(awk 'tolower($1)=="x-csrf-token:" {gsub("\r", "", $2); print $2}' bootstrap.headers)
curl --fail-with-body -sS -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $csrf_token" \
  -H 'Content-Type: application/json' \
  --data-binary '{"password":"example-only","ttl":3600,"views":1,"deletable":true}' \
  https://share.jeanphilippe.io/api/v1 -o created.json
```

Expect HTTP 201, with `link` and `link_api`. Creation does not echo the password. Internal fields such as `token`, `views_count`, and storage identifiers cannot be set through the creation DTO.

TTL is in seconds (300–604800); views are 1–100. For compatibility, omitted or zero values use defaults 3600 and 1. Negative or excessive values, malformed JSON, missing passwords, and invalid field types return HTTP 400 JSON through the Go error handler. Apache/WAF errors require the separate deployment templates.

`application/x-www-form-urlencoded` also accepts the ordinary field names `password`, `ttl`, `views`, `deletable` and `_csrf`. The form DTO has proper literal tags; Redis and response model tags are not reused as an input schema.

## Read and delete

`GET /api/v1/<token>` now returns the decrypted `password` and consumes one attempt. A second read after a single-use secret returns HTTP 404 JSON. **This intentionally replaces the previous broken metadata-only behavior.** Do not use this endpoint for previews; the browser's ordinary secret page still previews without consuming the secret.

`DELETE /api/v1/<token>` requires the cookie/header pair, a deletable resource, and its valid key after the access-control PR is applied. Invalid keys must not delete or consume the resource. Existing browser deletion links are handled by the access-control PR's confirmation form.

Do not put CSRF tokens, passwords, or share tokens in query parameters. Do not follow redirects to hide failed API statuses. Integration tests exercise the real routing, CSRF middleware, static-file skipper, JSON responses, defaults and single-use semantics.
