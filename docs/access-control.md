# Resource boundaries and authenticated deletion

Share URLs retain the format `<canonical UUID>~<Fernet key>` and the existing Redis schema. No record migration or token rotation is required. UUID validation applies before connections are opened, preventing a secret identifier such as `file_<UUID>` from selecting a file record through the secret routes. All new records already use canonical UUIDs.

Password previews verify the key without decrypting the password into the rendered model or consuming a view. Revelations and downloads retain the existing atomic attempt reservation: an incorrect non-empty key or wrong file password still consumes a read attempt. Deletion authentication is read-only and does not consume attempts.

Deletion verifies the cryptographic key before checking the deletable flag or deleting Redis/file data. Invalid keys return not found and leave both counters and content intact. Non-deletable records remain protected even with a valid key.

Existing browser deletion URLs remain valid, but GET now displays a confirmation. A native HTML form POSTs to the same URL with the existing CSRF token. It adds no JavaScript and does not modify the file-upload form or sliders. Deploy the new `views/confirm_delete.html` with the binary. API clients should use the existing DELETE route with CSRF protection; scripts that previously used GET to delete need updating.

An exhausted but unexpired archive can still be confirmed for deletion without reopening a download. The confirmation and mutation each authenticate the supplied key; the POST does not rely on a previous GET.

The fix closes the additional-password disclosure through secret routes; it does not add ZIP encryption or change the accepted storage design. Existing protected links remain usable. It cannot revoke a password already disclosed before deployment. If a sensitive archive's password was exposed, remove that archive and distribute a fresh protected link/password according to the owner's policy.

Do not roll back to the vulnerable binary to resolve a deployment issue. Keep a backup for operational recovery, but use a forward fix for the authorization checks. Tests cover cross-resource HTTP requests with the real CSRF middleware, valid legacy-format links, invalid keys, non-deletable resources, counters, confirmation POSTs and file integrity.
