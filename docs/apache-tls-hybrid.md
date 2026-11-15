# Optional hybrid TLS key exchange for Apache

This is a reviewable deployment option, not an active configuration. Echo's version does not control the public TLS handshake: Apache negotiates that connection if it terminates public TLS. Okuru's Go server has a separate TLS 1.3 configuration. A hybrid exchange on one connection does not prove the other connection uses it. Confirm the real topology, including any CDN, TLS terminator and the Apache-to-Okuru proxy URL, before changing anything.

`X25519MLKEM768` combines classical X25519 and ML-KEM-768 for TLS key exchange. It is not a TLS cipher suite, does not make the certificate signature post-quantum, and does not replace certificate validation. Existing clients without hybrid support still need a classical key exchange.

## Check the running stack first

On the server, record the active configuration and version without printing private keys or environment files:

```sh
sudo apache2ctl -v
sudo apache2ctl -M
sudo apache2ctl -S
sudo apache2ctl -t -D DUMP_INCLUDES
openssl version -a
openssl list -providers
openssl list -tls1_3 -tls-groups
sudo grep -RniE 'SSLOpenSSLConfCmd|SSLProtocol|SSLCipherSuite|SSLProxy|ProxyPass|Protocols' /etc/apache2
```

The `openssl` command may use a different library, configuration or providers from the running Apache `mod_ssl`. Check the actual loaded library and service environment by the methods appropriate to the installation, for example the `mod_ssl` package dependencies and `/proc/<apache-pid>/maps` on Linux. A distribution may backport support; test the group with the Apache process's own configuration. Do not infer support from a separately installed OpenSSL executable.

The snippet targets Apache 2.4.8 or later with `mod_ssl`, and OpenSSL 3.5 or later with the `X25519MLKEM768` group provided and enabled. Its `DEFAULT` group-list syntax also requires OpenSSL 3.5 or later. A missing group or unsupported syntax can make Apache configuration invalid. FIPS mode, providers, system crypto policy, distribution patches and an existing `Groups`/`Curves` directive can change the effective result.

OpenSSL 3.5 already includes the hybrid group in its default group list. If the existing Apache configuration inherits that default and tests confirm the desired negotiation, no new directive is necessary. If an explicit configuration is needed, compare its existing groups first: the supplied fragment restores **OpenSSL's built-in** default list, not a custom list previously defined by the administrator. Check effects on TLS 1.2, certificate signature compatibility and all virtual hosts. The list expresses allowed groups; it does not guarantee that every client offering a hybrid group will negotiate one. TLS 1.3 server selection also depends on the offered key shares.

The configuration supplied for this migration already lists `X25519MLKEM768:X25519:P-384`. If that is the effective configuration of the intended virtual host, it already enables the hybrid group and provides two classical fallbacks; do not add the optional fragment on top, because `DEFAULT` would replace that explicit selection. This list does not include P-256, so clients offering only P-256 cannot negotiate a shared key-exchange group. Whether to expand the list is a compatibility decision, not an automatic migration change. The configuration supplied in conversation has not been verified on the server.

## Staging and activation

After backing up and reviewing the current virtual-host configuration, consider including `deploy/apache/tls-hybrid-groups.conf` inside the intended TLS virtual host in a staging environment. Resolve any competing `SSLOpenSSLConfCmd Groups` or `Curves` configuration instead of adding ambiguous duplicates. Keep the existing protocol policy, certificate, security headers, proxy settings and authentication. Do not include the snippet globally merely to affect one site.

```apache
Include /absolute/path/to/tls-hybrid-groups.conf
```

Test with the same Apache binary, linked OpenSSL, providers and policy as the target:

```sh
sudo apache2ctl configtest
```

An accepted syntax is not proof of negotiation. Test the staged service as described below, including classical fallback and the application's existing browser/API/upload/download checks. Inspect the actual error logs, without exposing URLs containing secrets. Only after a successful review and config test should the operator reload the staged service. Preserve the previous file and its includes so the change can be rolled back: restore them, run `apache2ctl configtest`, then reload. Avoid restarting a production service to test a speculative configuration.

## Verify the negotiated group

Use a client OpenSSL build that supports the requested group. Replace `HOST` with the certificate's DNS name and `ADDRESS` with the target host and port; where needed, add an appropriate `-CAfile`. Each command starts a fresh connection and validates the certificate and hostname:

```sh
openssl s_client -connect ADDRESS:443 -servername HOST -verify_hostname HOST \
  -verify_return_error -tls1_3 -groups X25519MLKEM768 -brief </dev/null
openssl s_client -connect ADDRESS:443 -servername HOST -verify_hostname HOST \
  -verify_return_error -tls1_3 -groups X25519 -brief </dev/null
```

The first command tests hybrid support; the second tests classical fallback. Inspect the negotiated group and exit status, not just the cipher suite. Test ordinary client offers separately, both HTTP/2 and HTTP/1.1 if supported by the existing deployment, and each relevant IPv4/IPv6 address or load-balancer edge. If a CDN terminates TLS, the public test measures the CDN handshake, not the origin. A failed hybrid-only handshake does not by itself establish whether Apache, a provider, a proxy or a network device caused the failure.

For an HTTPS connection from Apache to Go, independently verify the backend certificate chain, hostname and expiry, and the actual group negotiated on that hop. Apache documents `SSLProxyVerify none` as its default; inspect the effective configuration rather than assuming verification is enabled. Do not disable certificate verification to make the test pass. The public-server `SSLOpenSSLConfCmd` snippet above is not a claim about Apache's outbound proxy TLS configuration. If the proxy uses plaintext HTTP, there is no TLS key exchange on that hop.

Go 1.27.4 normally offers hybrid groups by default when `CurvePreferences` is empty, subject to `GODEBUG` and runtime/FIPS settings. The repository's Go server currently sets TLS 1.3 and leaves `CurvePreferences` empty. Confirm the built binary and effective service environment before relying on this, and test the real connection rather than inferring its negotiated group from source code.

References: [Apache mod_ssl](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslopensslconfcmd), [OpenSSL group selection](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/), [OpenSSL SSL_CONF commands](https://docs.openssl.org/3.5/man3/SSL_CONF_cmd/), and [Go crypto/tls](https://pkg.go.dev/crypto/tls).
