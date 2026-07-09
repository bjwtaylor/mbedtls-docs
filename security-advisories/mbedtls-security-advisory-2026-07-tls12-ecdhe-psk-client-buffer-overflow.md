# Remote buffer overflow in TLS 1.2 ECDHE-PSK client handshake (CVE-2026-50580)

**Title** | Remote buffer overflow in TLS 1.2 ECDHE-PSK client handshake
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50580
**Date** | 7th of July, 2026
**Affects** | Mbed TLS 1.3.10 through 3.6.6; Mbed TLS 4.0.0 through 4.1.0
**Not affected** | Mbed TLS 1.3.9 and earlier; Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later versions; TF-PSA-Crypto
**Impact** | A malicious TLS 1.2 server can cause a client configured with an oversized PSK identity to write past the end of the TLS output buffer when an ECDHE-PSK ciphersuite is negotiated.
**Severity** | HIGH
**Credits** | Karnakar Reddy (@karnakarreddi)

## Vulnerability

In TLS 1.2 clients, `ssl_write_client_key_exchange()` constructs the
ClientKeyExchange message for ECDHE-PSK ciphersuites by writing the PSK
identity followed by the client's ephemeral EC public key. Before the fix, the
ECDHE-PSK path checked that the output message buffer had enough room for the
handshake header, the two-byte PSK identity length, and the PSK identity, but
did not reserve room for the following one-byte EC point length field and the
EC public key.

If the client was configured with a sufficiently long PSK identity, this check
could pass while leaving too little room for the EC public key. The subsequent
public key export then computed the remaining output space from a pointer that
could already be beyond the intended TLS output-content boundary. This could
underflow the available-length calculation and let the public key export write
past the end of the TLS output buffer in affected configurations.

Applications are vulnerable when they use a TLS 1.2 client configured with an
oversized static PSK identity, allow negotiation of ECDHE-PSK ciphersuites, and
run with an output-buffer layout that does not leave enough spare space after
`MBEDTLS_SSL_OUT_CONTENT_LEN` to absorb the overflow. The issue is exposed in
particular when CBC ciphersuites are disabled, reducing the extra output-buffer
padding that otherwise masks the overwrite in common configurations.

## Impact

A malicious TLS 1.2 server or a TCP man-in-the-middle that negotiates an
ECDHE-PSK ciphersuite with an affected client can trigger memory corruption
while the client constructs its ClientKeyExchange message. Confirmed outcomes
include a client-side process crash and denial of service. Depending on
allocator behavior, build configuration, and application memory layout, code
execution and heap corruption may be possible.

For the attack to be possible, the client application must be configured with a
very long PSK identity and must offer ECDHE-PSK ciphersuites. Applications that
use short PSK identities are not vulnerable to this issue: the PSK identity must
be long enough that the ECDHE-PSK ClientKeyExchange message can fit the
handshake header and PSK identity, but not the following EC public key.

## Affected versions

Mbed TLS versions 1.3.10 through 3.6.6 and 4.0.0 through 4.1.0 are affected
when `MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED` is enabled and the application can
use an oversized PSK identity.

Mbed TLS 1.3.9 and earlier are not affected because they do not have
ECDHE-PSK support. Mbed TLS 3.6.7 and later 3.6.x versions, Mbed TLS 4.1.1 and
later 4.1.x versions, and Mbed TLS 4.2.0 and later versions include the fix.

TF-PSA-Crypto is not affected.

## Work-around

Applications can avoid the issue by using short PSK identities. For
ECDHE-PSK, the ClientKeyExchange message needs 7 bytes of header and length
fields, the PSK identity, and the encoded client EC public key. The encoded
public key size depends on the negotiated curve; for the largest currently
supported built-in curves, reserving 133 bytes for it is sufficient. Therefore,
applications using those curves are not affected if the PSK identity length is
at most `MBEDTLS_SSL_OUT_CONTENT_LEN - 140` bytes. For example, this allows PSK
identities up to 116 bytes with `MBEDTLS_SSL_OUT_CONTENT_LEN` set to 256, or up
to 884 bytes with `MBEDTLS_SSL_OUT_CONTENT_LEN` set to 1024. A 64-byte PSK
identity has enough room even with a 256-byte output content buffer.

Applications are also not vulnerable if they do not use TLS clients, do not
enable TLS 1.2, or do not enable ECDHE-PSK ciphersuites. If applications cannot
rely on PSK identity lengths being short enough or disable TLS 1.2 ECDHE-PSK
support by disabling `MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED`.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version,
Mbed TLS 4.1.1 or a later 4.1.x version, or Mbed TLS 4.2.0 or a later version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | f9835c081f1ebed8c2ea3b23574da71c1bb66e44 | N/A | N/A | f63ca6e0af1d37ae048e00e692f21d302d0acd25 | baf449db7e31f031ed5def0fecf417122f72d3ee |
| With tests and documentation | f9835c081f1ebed8c2ea3b23574da71c1bb66e44^..b961ac2cf2472829066a97f10af544af267cfca2 | N/A | N/A | f63ca6e0af1d37ae048e00e692f21d302d0acd25^..a98b95074ad1d2a73e91278a380a424f3f4df4c6 | baf449db7e31f031ed5def0fecf417122f72d3ee^..911b9b67dbf335f79253c2b66acc9767e34b3105 |
