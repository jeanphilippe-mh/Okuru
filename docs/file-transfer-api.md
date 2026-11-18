# Direct file uploads

Enable `OKURU_FILE_API=true` at startup to offer a single-request upload on an HTTPS origin. The historical web form uses `POST /file`. Text secrets use `/api/v1`.

## Send files and metadata together

1. Call `GET /api/v2/uploads/bootstrap` and retain the secure cookie and the `X-CSRF-Token` response header. The JSON response gives the direct upload path and the size limits in bytes. Reuse the cookie and token across uploads.
2. Send `POST /api/v2/files/direct` as `multipart/form-data`, with the cookie and the token in the `X-CSRF-Token` request header. Place the `metadata` part first, give it the media type `application/json`, then send one binary `files` part for each manifest entry, in order. The required manifest fields are `ttl_seconds` (300–604800), `views` (1–100) and `files` (name and exact byte length of each file). Optional fields are `deletable` and `password`. A browser can append the JSON as a `Blob` of type `application/json`; let `FormData` set the request boundary.
3. On success, HTTP 201 returns `link` and UTC `expires_at`, with `delete_link` for deletable shares and `password_link` when a password was supplied. Resolve relative links against the HTTPS origin you called. Treat all returned links as private. A failed connection after the body was sent can leave the outcome unknown. Repeating the direct POST can create another share.

Example using a private temporary directory and a six-byte file. Set `okuru_origin` to the HTTPS origin of a server running this endpoint.

```sh
umask 077
okuru_example=$(mktemp -d)
printf 'hello\n' > "$okuru_example/hello.txt"
curl --fail-with-body -sS -c "$okuru_example/cookies" -D "$okuru_example/headers" \
  "$okuru_origin/api/v2/uploads/bootstrap" -o "$okuru_example/bootstrap.json"
okuru_csrf=$(awk 'tolower($1) == "x-csrf-token:" { sub("\r$", "", $2); print $2 }' "$okuru_example/headers")
curl --fail-with-body -sS -b "$okuru_example/cookies" \
  -H "X-CSRF-Token: $okuru_csrf" \
  -F 'metadata={"ttl_seconds":3600,"views":1,"files":[{"name":"hello.txt","size":6}]};type=application/json' \
  -F "files=@$okuru_example/hello.txt;type=text/plain" \
  "$okuru_origin/api/v2/files/direct"
```

The metadata limit is 64 KiB. The direct request limit is 90,000,000 bytes including all MIME headers and boundaries. The configured file limit and any lower proxy limit also apply. HTTP 400 signals invalid metadata or a manifest mismatch, 403 rejects the CSRF credentials, 413 reports a size limit, and 415 requires a multipart request. This direct endpoint sends the body as one request and therefore does not resume a partial upload.

Read the HTTP status first. Okuru's JSON errors contain `code` and `message`. Apache or another proxy may supply a different body, including HTML. If two tabs bootstrap simultaneously before either receives the first cookie, a tab may have an older token. On a CSRF rejection from Okuru, bootstrap again with the current cookie before submitting again.
