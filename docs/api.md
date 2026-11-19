# Text secrets API

Use HTTPS. A share permits a fixed number of reads until its expiration. The browser share page lets the recipient preview the settings. Fetching the secret through the API immediately consumes one read. Files use the [file transfer API](file-transfer-api.md).

| Method | Path | Response |
|---|---|---|
| GET | `/api/v2/secrets/bootstrap` | HTTP 200. Retain the secure cookie and the `X-CSRF-Token` response header. JSON supplies the creation path and the maximum secret size in bytes. |
| POST | `/api/v2/secrets` | HTTP 201. JSON returns `link` for the browser, `api_link` for programmatic access, `ttl_seconds`, `views` and `deletable`. Resolve relative links against the origin you called. |
| GET | `/api/v2/secrets/{token}` | HTTP 200. JSON returns `password`, remaining `ttl_seconds`, remaining `views` and `deletable`. An unavailable secret returns HTTP 404. |
| DELETE | `/api/v2/secrets/{token}` | HTTP 204 for a successful deletion. Deletion requires the original capability and a deletable share. |

POST and DELETE require both the bootstrap cookie and matching header. The cookie is host-only, Secure, HttpOnly and SameSite=Strict. Secret responses and error responses carry cache controls. Handle the HTTP status before decoding the response. Okuru supplies `code` and `message` for JSON errors. Reverse proxies may supply a different body.

## Create a secret

Send one UTF-8 JSON object with `Content-Type: application/json`. The required `password` is a nonempty string of up to 32 KiB in UTF-8. Optional `ttl_seconds` is an integer from 300 to 604800 and defaults to 3600. Optional `views` is an integer from 1 to 100 and defaults to 1. Optional `deletable` is a boolean and defaults to false. The JSON request limit is 64 KiB. Unknown properties, duplicates, null values and trailing JSON are rejected.

The following example uses a temporary private directory for the cookie, headers and creation result. Point `okuru_origin` at your instance.

```sh
umask 077
okuru_example=$(mktemp -d)
curl --fail-with-body -sS -c "$okuru_example/cookies" -D "$okuru_example/headers" \
  "$okuru_origin/api/v2/secrets/bootstrap" -o "$okuru_example/bootstrap.json"
okuru_csrf=$(awk 'tolower($1) == "x-csrf-token:" { sub("\r$", "", $2); print $2 }' "$okuru_example/headers")
curl --fail-with-body -sS -b "$okuru_example/cookies" \
  -H "X-CSRF-Token: $okuru_csrf" -H 'Content-Type: application/json' \
  --data-binary @- "$okuru_origin/api/v2/secrets" > "$okuru_example/created.json" <<'JSON'
{"password":"example secret","ttl_seconds":3600,"views":2,"deletable":true}
JSON
```

The links and creation result are sensitive. A lost network response after creation can leave the outcome unknown. A GET whose reply was lost may already have consumed a read.
