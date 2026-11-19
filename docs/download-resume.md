# Download continuation

The download form submits a POST to the share URL. Okuru checks the link and any required password, opens the archive, and reserves one view. A successful POST returns a `303 See Other` redirect to a session-specific download URL. The browser follows it with a GET and receives the ZIP as an attachment. The form works without JavaScript. To continue the same view, use the browser’s resume action on the existing download. Submitting the form again requests a new view. The original share URL offers confirmation while another view remains available.

The redirect also sets a `Secure`, `HttpOnly`, `SameSite=Strict` cookie scoped to the exact download path. The download URL contains a digest that identifies the session. The cookie holds its random key and is required on every GET. The first GET starts the full response. To continue an interrupted transfer, the browser normally requests the same URL with a single `Range: bytes=…` header. An ordinary continuation with a matching validator (or no validator) receives `206 Partial Content` and the session's ETag.

New ZIP URLs use a file identifier and an unpadded URL-safe encoding of the share key. Their path contains only letters, digits, hyphens, underscores and slashes. This keeps the exact cookie path stable when a native download manager serializes the URL again. Sessions opened on an earlier version can still use their original ZIP URL.

A native download manager can also restart at byte zero. After an interrupted initial transfer, Okuru accepts one full restart on the same URL with the same cookie and no `Range` header. It returns `200 OK` with the complete ZIP. The restart requires an idle session, the full ZIP size available in its continuation budget and time remaining on both deadlines. It uses the view already reserved by the POST. A completed initial response cannot be replayed this way. An interruption recorded before the upgrade remains eligible for the previous range mechanism until its session expires. [Apple's URLSession download delegate](https://developer.apple.com/documentation/foundation/urlsessiondownloaddelegate/urlsession(_:downloadtask:didresumeatoffset:expectedtotalbytes:))

For both supported archive formats, Okuru authenticates the age header and final chunk before using the length, then authenticates each chunk as it reads it. If writing or authentication fails after response headers are sent, Okuru aborts the response.

A second interruption can lead a native client to restart without a range or request a position beyond the bytes Okuru has sent. If the initial response and first validated, interrupted continuation covered a prefix and used at most one ZIP's byte allowance, Okuru can send the complete ZIP with `200 OK` in either case. Both requests require the session cookie. A request with a range must also present a matching validator. Okuru checks that the session is idle, unexpired and within its byte allowance. A valid continuation at the expected position still receives `206 Partial Content`.

An authenticated GET without `Range` may wait up to 150 milliseconds for Redis to record the outcome of the previous transfer. This wait leaves the request count, byte allowance and deadlines untouched. If the previous transfer is still active when the wait expires, Okuru returns `404`.

Each session allows up to 32 continuation requests. The total amount handed to the HTTP writer is bounded by twice the ZIP size. Ordinarily the initial response has one ZIP's allowance and all subsequent responses share another. For a restart after the first interrupted continuation, the initial partial response and the first partial continuation can share the first allowance. The replacement and any further ranges then share the second. Overlapping bytes count each time they are sent. Reservations are atomic, and unwritten bytes are refunded after an interruption. A crash or a Redis failure can leave a reservation charged. The server can measure bytes handed to its own writer, while delivery to the device also depends on the proxy and the connection.

## Download timeouts

Both settings in `.env.dist` use seconds. Okuru checks both deadlines and the remaining share lifetime before accepting a continuation.

| Setting | Default | What it controls |
| --- | --- | --- |
| `OKURU_DOWNLOAD_SESSION_TIMEOUT` | `900` (15 minutes) | Total time from the successful download POST during which the browser may start the ZIP or request more bytes. Resuming does not reset this clock. |
| `OKURU_DOWNLOAD_RESUME_TIMEOUT` | `300` (5 minutes) | Time to reconnect after Okuru detects an interruption. A subsequent accepted transfer can start a fresh resume window within the original session. |

For example, if a transfer stops 4 minutes after authorization, the browser has 5 minutes to resume. If it stops at minute 12, only 3 minutes remain. A ZIP that is still downloading when minute 15 passes can finish on the open connection. If that connection drops at minute 16, a new GET cannot resume it. A share that expires sooner brings the applicable deadline forward. The existing HTTP transport limits and bounds on range requests still apply.

The cookie lasts at most as long as the original session or the share, whichever expires first. Redis also enforces the idle deadline, so an expired continuation is refused even if the browser still has the cookie. Use positive whole seconds in both settings. Values above 86,400 seconds are capped at 24 hours. For existing installations, the session setting also accepts the previous Go duration format (for example, `15m`). An invalid timeout is rejected before the POST reserves a view.

Redis stores separate `download_session_<file UUID>_<SHA-256 of cookie key>` hashes. The hash contains the archive secret encrypted with the random cookie key, never the cookie key itself. The parent file record stores only a bounded index of session-key digests. The session hashes expire independently within the applicable session or resume window, subject to the parent TTL. An authenticated deletion removes the file record, any separately shared password and its indexed sessions using one Redis `DEL`; ACL denial for any key fails the operation before any of those records is removed. File expiration also prevents future continuation; sessions have their own expiry as a backstop. Never log or expose the share link or cookie.

The Redis account must be authorized for the session key pattern and for `EVAL`/`EVALSHA`, `HGET`, `HGETALL`, `HEXISTS`, `HKEYS`, `HSET`, `HDEL`, `HINCRBY`, `EXISTS`, `TIME`, `TTL`, `PTTL`, `PEXPIRE` and `DEL` on the applicable file, password and download-session keys, in addition to the existing commands. Redis is needed when creating and continuing a session. A Redis failure after a view has been reserved can prevent the redirect from being sent; this fails closed rather than exposing an unlimited download.

The server supplies a session-specific ETag for `If-Range`. It derives the archive validator from the ciphertext size, its first 4 KiB and its last 65,552 bytes, bounded by the actual file length. Okuru checks file identity, size and modification time before and after streaming and authenticates each age chunk it returns.

On the dedicated download URL, full and partial ZIP responses also advertise `Last-Modified` when the immutable archive has a known modification time no later than the response date. A browser that did not receive an ETag can use that date in `If-Range`. An exact match to the HTTP second allows the requested range. A stale validator falls back to a complete response within the session's remaining byte budget. ZIP responses send `Cache-Control: private, no-store, no-transform` so intermediaries preserve the representation to which the offsets refer. Verify the initial response at the client as well as at the origin when diagnosing a proxy deployment.

## Apple's native download requirements

Apple documents five conditions for resuming an interrupted download. [Foundation download task requirements](https://developer.apple.com/documentation/foundation/urlsessiondownloadtask/cancel%28byproducingresumedata%3A%29)

1. The resource must remain unchanged between the initial request and the continuation. Okuru pins the ZIP representation to its download session.
2. The bytes must be downloaded using an HTTP or HTTPS GET. Okuru uses the POST only to authorize the view, then redirects the browser to the ZIP.
3. The server must send an `ETag`, a `Last-Modified` date, or both. Apple prefers the ETag. Okuru supplies a strong session-specific ETag, including when a future file timestamp prevents it from sending `Last-Modified`.
4. The server must support byte ranges and advertise `Accept-Ranges: bytes`. When the browser asks for the next bytes with a valid `Range` and matching `If-Range`, Okuru returns `206 Partial Content` with the corresponding `Content-Range` and ZIP bytes. [Apple's WWDC session on resumable transfers](https://developer.apple.com/videos/play/wwdc2023/10006/?time=394)
5. The device must still have the partial file. Its operating system can remove that file under disk space pressure.

WebKit can produce resume data when the user stops a download. Use the resume control in Safari's Downloads window. A native continuation uses the resume data and the local partial file. Okuru also requires the original session cookie. If Safari retries without it, the ZIP endpoint returns `404`. [WebKit download cancellation](https://developer.apple.com/documentation/webkit/wkdownload/cancel%28_%3A%29) and [WebKit download resumption](https://developer.apple.com/documentation/webkit/wkwebview/resumedownload%28fromresumedata%3Acompletionhandler%3A%29)

### Responses during a retry

| What Okuru receives or detects | Result |
| --- | --- |
| An authenticated request for the next available bytes | `206` with the matching byte interval and its exact length. |
| A plain GET or a verified forward gap after the first validated, interrupted continuation, with enough time and bytes left | `200` with the entire ZIP and its exact length. The existing view covers this request. |
| A missing or incorrect cookie, or an expired session | `404` with an empty body. A URL, range or validator alone never authorizes a download. |
| The cookie matches its selector, but Okuru loses its Redis connection during the initial read-only check | Empty `503` with `Retry-After: 1`. The check leaves the view, request count and byte allowance intact. |
| Okuru loses the Redis connection while admitting the transfer or reserving bytes | Empty `503`. The write may already have succeeded. Okuru keeps any charge and does not automatically repeat the operation. |
| A matching validator but a range outside the archive, without a verified recovery case | `416` with `Content-Range: bytes */<size>`. |
| A stale `If-Range` for a syntactically valid range on the dedicated URL | Okuru ignores the range and sends the whole pinned ZIP if the session has enough bytes left. An insufficient byte budget prevents the transfer. [HTTP conditional range requests](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5) |
| A different archive detected before the dedicated GET starts streaming | `412` when the opened representation differs from the one pinned to the session. |
| A read, integrity or transport failure after response headers have been sent | Okuru aborts the stream. The response is incomplete and its remaining bytes may only be requested under the session's existing rules. |

## Diagnosing a native retry

For the session ZIP route, Okuru's request journal includes `download_range_present` and `download_if_range_present`. After the cookie check, `download_cookie` is `missing`, `mismatch`, or `matched`. A match means that the cookie value corresponds to the digest in the URL. Okuru still checks the share, active operations, deadlines and remaining budget in Redis. These fields contain no raw cookies, URLs or validators.

To compare what Debian Apache receives with what Okuru receives, temporarily include [download-resume-diagnostic.conf](../deploy/apache/download-resume-diagnostic.conf) inside the site's HTTPS virtual host. Check the configuration with `sudo apache2ctl configtest` and reload it with `sudo systemctl reload apache2`. Watch `/var/log/apache2/okuru-resume-diag.log` while stopping and resuming one test download. Apache's cookie marker means that a download cookie was present. The Go journal checks the specific cookie for this session. Remove the include and repeat the configuration check and reload after the test.
