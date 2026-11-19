# Resource boundaries and authenticated deletion

By default, share URLs contain a canonical UUID and a Fernet key separated by `~`. Okuru validates the UUID before opening a Redis connection. A secret identifier such as `file_<UUID>` therefore cannot select a file record through the secret routes. Each file record identifies the encryption format of its archive.

Password previews verify the key without decrypting the password into the rendered model or consuming a view. Revelations and downloads authenticate the bearer key before reserving an attempt atomically against the same encrypted record; an incorrect bearer key does not consume a view. A wrong additional file password still consumes a download attempt after the bearer key is authenticated. Deletion authentication is read-only and does not consume attempts.

For protected downloads, the password field identifies an existing password to the browser's password manager. Suggestions depend on the browser and saved credentials; a password saved for the site may not be the password for this particular archive. Check the selection before downloading because an incorrect file password consumes an attempt.

Deletion verifies the cryptographic key before checking the deletable flag or deleting Redis/file data. Invalid keys return not found and leave both counters and content intact. Non-deletable records remain protected even with a valid key.

File deletion reports an error if the archive cannot be removed or associated password metadata cannot be deleted. The file's Redis metadata may already have been removed at that point; the periodic archive reconciler retries physical cleanup when Redis and the filesystem are available. Do not treat an error response as proof that all related resources were removed.

New password and file hashes are created with expiry in one Redis script. Before writing, the script checks that the key is absent and that `EXPIRE` and `DEL` are allowed on it; otherwise creation fails without a new hash. The Redis account must allow the existing read and write commands as well as `EVAL`, `EVALSHA`, `EXISTS`, `HMSET`, `EXPIRE`, and `DEL` for Okuru's keys. Review ACLs before deployment. A fatal Redis failure cannot be ruled out by source review alone.

Opening a browser deletion URL displays a confirmation. The native HTML form POSTs to the same URL with its CSRF token. API clients can use the DELETE route with CSRF protection.

An exhausted but unexpired archive can still be confirmed for deletion without reopening a download. The confirmation and mutation each authenticate the supplied key; the POST does not rely on a previous GET.

Authorization tests cover cross-resource HTTP requests with the real CSRF middleware, valid and invalid bearer keys, non-deletable resources, counters, confirmation POSTs and file integrity.

Okuru stores a ZIP inside an authenticated age envelope. A user-supplied password selects `age-user-password-v2` (scrypt). Without a password Okuru generates a fresh X25519 identity and records `age-x25519-v1`. A missing, unknown or inconsistent format is rejected. Okuru decrypts the archive during download and delivers a standard ZIP. The server sees the contents during processing.

Password-protected archives use scrypt work factor 18. One derivation needs approximately 256 MiB of working memory. Cooperating processes sharing the protected storage root admit one derivation at a time. Garbage collection and other processes can increase memory use. Multipart file parts are encrypted in a private staging directory. Plaintext may still appear in memory, swap, dumps or intermediary infrastructure. Deletion is not secure erasure. See [upload safety](upload-safety.md) for the staging guarantees and limits.

Encrypted downloads support bounded continuation through authenticated sessions and HTTP Range as described in `download-resume.md`. Authentication is checked while streaming; if a later chunk is corrupt or truncated, previously transmitted bytes cannot be retracted and the server aborts the HTTP response. Actual client and proxy behavior must be verified in the target deployment.
