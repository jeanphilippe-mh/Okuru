# Resource boundaries and authenticated deletion

Share URLs retain the format `<canonical UUID>~<Fernet key>` and remain compatible with existing records. New records include an archive format field; no record migration or token rotation is required. UUID validation applies before connections are opened, preventing a secret identifier such as `file_<UUID>` from selecting a file record through the secret routes. All new records already use canonical UUIDs.

Password previews verify the key without decrypting the password into the rendered model or consuming a view. Revelations and downloads authenticate the bearer key before reserving an attempt atomically against the same encrypted record; an incorrect bearer key does not consume a view. A wrong additional file password still consumes a download attempt after the bearer key is authenticated. Deletion authentication is read-only and does not consume attempts.

Deletion verifies the cryptographic key before checking the deletable flag or deleting Redis/file data. Invalid keys return not found and leave both counters and content intact. Non-deletable records remain protected even with a valid key.

File deletion reports an error if the archive cannot be removed or associated password metadata cannot be deleted. The file's Redis metadata may already have been removed at that point; the periodic archive reconciler retries physical cleanup when Redis and the filesystem are available. Do not treat an error response as proof that all related resources were removed.

New password and file hashes are created with expiry in one Redis script. Before writing, the script checks that the key is absent and that `EXPIRE` and `DEL` are allowed on it; otherwise creation fails without a new hash. The Redis account must allow the existing read and write commands as well as `EVAL`, `EVALSHA`, `EXISTS`, `HMSET`, `EXPIRE`, and `DEL` for Okuru's keys. Review ACLs before deployment. A fatal Redis failure cannot be ruled out by source review alone.

Existing browser deletion URLs remain valid, but GET now displays a confirmation. A native HTML form POSTs to the same URL with the existing CSRF token. It adds no JavaScript and does not modify the file-upload form or sliders. Deploy the new `views/confirm_delete.html` with the binary. API clients should use the existing DELETE route with CSRF protection; scripts that previously used GET to delete need updating.

An exhausted but unexpired archive can still be confirmed for deletion without reopening a download. The confirmation and mutation each authenticate the supplied key; the POST does not rely on a previous GET.

The fix closes the additional-password disclosure through secret routes. Existing protected links and legacy unencrypted archives remain usable. It cannot revoke a password already disclosed before deployment. If a sensitive archive's password was exposed, remove that archive and distribute a fresh protected link/password according to the owner's policy.

Do not roll back to the vulnerable binary to resolve a deployment issue. Keep a backup for operational recovery, but use a forward fix for the authorization checks. Tests cover cross-resource HTTP requests with the real CSRF middleware, valid legacy-format links, invalid keys, non-deletable resources, counters, confirmation POSTs and file integrity.

New uploads are ZIP archives protected at rest with an authenticated age v1 envelope. A user-supplied password uses age scrypt; without a password the server generates a random age X25519 identity. The server decrypts the archive during download, so the downloaded ZIP is unencrypted and this is not end-to-end encryption. The legacy absence of an archive format denotes a plaintext archive; any unknown nonempty format is rejected.

New password-protected archives use scrypt work factor 18, with at most one derivation active in each application process. Each derivation needs roughly 256 MiB of working memory, and consecutive requests can retain more process memory until garbage collection; multiple server processes each have their own limit. Multipart file parts are encrypted in a private staging directory, rather than intentionally spilled in plaintext by the application. Plaintext may still appear in memory, swap, dumps, or intermediary infrastructure. Deletion is not secure erasure. See `upload-safety.md` for the current staging guarantees and limits.

Encrypted downloads support bounded continuation through authenticated sessions and HTTP Range as described in `download-resume.md`. Authentication is checked while streaming; if a later chunk is corrupt or truncated, previously transmitted bytes cannot be retracted and the server aborts the HTTP response. Actual client and proxy behavior must be verified in the target deployment.
