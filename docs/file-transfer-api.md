# File transfers over HTTPS

The v2 file API is available by default on an HTTPS origin. The HTML form uses `POST /file`. Text secrets use [the secrets API](api.md).

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

## Choose a transport

| Path | What the client sends | What happens after an interruption |
| --- | --- | --- |
| HTML form, `POST /file` | One multipart body. Works with JavaScript disabled. | Select the files and send the form again. |
| Direct API, `POST /api/v2/files/direct` | One multipart body with JSON options and binary parts. | A lost success response can leave the result unknown. |
| Prepared multipart, `POST /api/v2/files` | A JSON manifest followed by one multipart request containing the binary files. | Query the result first. An incomplete body can be sent again against the same session. |
| Resumable, `PATCH /api/v2/uploads/{id}/files/{index}` | A JSON manifest followed by bounded binary requests to each prepared resource. | Read the server offset with HEAD and continue from that byte. |

On the upload page the ordinary submit button uses the browser's upload events to show actual request progress when JavaScript is enabled. The resumable option shows the bytes acknowledged by Okuru across all selected files. After transfer the page shows the archive preparation state. The existing Go confirmation page opens when the share receipt is available.

## Prepare, transfer and obtain a result

1. Bootstrap as above. The `modes` array advertises the modes open to new uploads. For resumable sessions, read `max_patch_bytes`. Generate a random UUID v4 and a 32-byte cryptographically random string encoded as unpadded base64url. Use the UUID as `Idempotency-Key` and the string in `Authorization: Bearer <value>`. Keep the creator credential private.
2. `POST /api/v2/uploads` with the bootstrap cookie, CSRF header, idempotency key, bearer and `Content-Type: application/json`. For example, send `{"mode":"blocks","files":[{"name":"hello.txt","size":6}]}`. Prepared manifests accept the direct options above. TTL defaults to 3600 seconds and the view limit to one. The first successful request returns 201 with the file URLs, status URL, separate status-only credential, result URL and expiration. Repeating the same ID, credential and manifest returns 200. Reusing the ID with a different manifest returns 409.
3. For `multipart`, send binary `files` parts in manifest order to `POST /api/v2/files`, with the cookie, CSRF header, creator bearer and `Upload-Id`. Do not repeat the metadata part here. The request must pass the size limit of every proxy.
4. For `blocks`, use the prepared file URLs. `OPTIONS` advertises tus 1.0.0. Send the creator bearer and `Tus-Resumable: 1.0.0` with HEAD and PATCH. HEAD returns `Upload-Length` and `Upload-Offset`. Send the next raw bytes in a PATCH with that offset in `Upload-Offset`, the cookie, CSRF header and `Content-Type: application/offset+octet-stream`. A successful 204 returns the next confirmed offset. After a lost response or a stale offset (409), issue HEAD again. Empty files need no PATCH. Once every file is complete, send `POST /api/v2/uploads/{id}/complete` with cookie, CSRF header and creator bearer.
5. Publication returns 201 and canonical share links. The resumable confirmation page uses these same links. The ordinary web form supports the configured short aliases. After an ambiguous completion, use `GET /api/v2/uploads/{id}/result` with the creator bearer. A repeat completion after publication returns the existing result. The receipt is available until share expiry or 24 hours after publication, whichever comes first. Use `GET /api/v2/uploads/{id}` with either credential for state and counters. The status-only bearer cannot retrieve links. To abandon an unfinished session, use DELETE on its status URL with the creator bearer, cookie and CSRF header.

An open session expires after 30 minutes of inactivity or four hours from creation. A status or HEAD request does not extend it. The browser keeps the creator credential and selected files in memory. A network interruption can resume in the same tab. Closing the tab or reloading the page requires a new selection and session. Restarting the upload owner interrupts unpublished transfers that have not entered durable publication. Already published shares and recoverable receipts live on disk and in Redis.

## Fresh installation and proxy limits

Use an empty private archive directory and fresh, dedicated Redis storage for this installation. Start Okuru on HTTPS. The example environment sets `OKURU_UPLOAD_CHUNKS=true` to offer resumable uploads. The following Redis command opens prepared sessions and the resumable option on a running upload owner. Run the command against the configured application database and substitute its prefix if it differs from the example.

```redis
HSET okuru_upload_v2_admission api open blocks open
```

To stop new resumable sessions while draining existing work, set `blocks` to `closed`. Set `api` to `closed` to stop all new prepared sessions. Direct multipart uploads stay available. Route session traffic to one process that owns the storage directory. Disk reservations, available space, file count, Redis admission and the application's aggregate file-size limit are enforced independently. An insufficient reservation returns 507. Session or rate capacity returns 429.

Set `OKURU_UPLOAD_CHUNKS_SIZE` to a whole number from 1 to 100 in decimal MB. The default of `100` allows 100,000,000 bytes per tus PATCH. An invalid size closes admission for new resumable uploads. The server advertises a valid limit in bytes as `max_patch_bytes`. The browser uses the advertised size, sends the exact remainder for the last chunk, and checks the confirmed offset before retrying with a smaller chunk after HTTP 413. Each session accepts at most 2,048 positive-length chunks.

Choose a chunk size that fits every proxy on the upload path. Cloudflare documents a per-request limit of 100 MB on Free and Pro, and zone administrators can lower it. An HTTPS proxy that terminates TLS can read file contents and metadata. Okuru applies age encryption when it receives the bytes at the origin. Allow HEAD, PATCH and OPTIONS through the proxy, preserve tus headers, and bypass caching for the API and confirmation routes. [Cloudflare request limits](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/)

The loopback integration test uses a capped HTTPS proxy, drops an upstream acknowledgement, extracts the downloaded ZIP and checks its file digest and single-view limit. Run it with a dedicated test Redis and sufficient local temporary disk space.

```sh
OKURU_TEST_LARGE_UPLOADS=1 OKURU_TEST_REDIS_ADDR=127.0.0.1:6379 go run ./tests/cmd/okurutest test -v -count=1 -run=TestUploadClientLargeProxy -- ./router
```
