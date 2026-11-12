# Utility tests

This suite exercises the `utils` package, including package-private storage and encryption helpers. It covers:

- Archive encryption, authentication, format compatibility and upload-name validation.
- Redis connections, token namespaces, atomic access attempts and download sessions.
- Encrypted multipart staging, cleanup, storage quotas and multi-process recovery.
- Windows filename rules, storage path guards, locks and access control lists.
- TLSA helper handling of credentials and untrusted responses.

Several Redis tests require a disposable service configured by `OKURU_TEST_REDIS_ADDR`, and TLSA tests require `bash` and `jq`. Some tests use temporary directories or child processes; the Windows tests require Windows and a suitable filesystem to validate actual behavior. They cannot be considered validated solely because they compile on another operating system.

Preserve platform-specific filenames and build tags when adding or moving tests. See the [test suite guide](../../README.md) and [Windows verification](../../../docs/windows-verification.md) for prerequisites.
