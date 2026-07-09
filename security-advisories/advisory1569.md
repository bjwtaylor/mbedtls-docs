# Signature algorithm restrictions not enforced on certificate chain (CVE-2026-54441)

**Title** | Signature algorithm restrictions not enforced on certificate chain
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-54441
**Date** | 30 June 2026
**Affects** | Mbed TLS up to 3.6.6 and earlier; Mbed TLS 4.0.0 and 4.1.0
**Not affected** | Mbed TLS 3.6.7 and later, Mbed TLS 4.1.1 and later, Mbed TLS 4.2.0 and later
**Impact** | An application may accept certificate chains signed with algorithms that were not intended to be allowed
**Severity** | LOW
**Credits** | Xiangdong Li, Beijing University of Posts and Telecommunications (BUPT)

## Vulnerability

Mbed TLS provides two separate API functions that affect which signature algorithms are accepted during a TLS handshake:

- `mbedtls_ssl_conf_sig_algs()`: configures the list of signature algorithms advertised in the TLS `signature_algorithms` extension, which is enforced for handshake signatures.
- `mbedtls_ssl_conf_cert_profile()`: controls which signature algorithms are accepted when verifying the certificate chain.

In the TLS 1.3 protocol, the `signature_algorithms` extension covers both handshake signatures and certificate chain signatures unless a separate `signature_algorithms_cert` extension is also sent. Mbed TLS does not send `signature_algorithms_cert`, so the same list is advertised for both purposes. This makes it reasonable to expect that `mbedtls_ssl_conf_sig_algs()` would also restrict which signature algorithms are accepted in the certificate chain.

However, Mbed TLS enforces these two settings independently: `mbedtls_ssl_conf_sig_algs()` only affects handshake signatures, while certificate chain verification is governed solely by `mbedtls_ssl_conf_cert_profile()`. The documentation for `mbedtls_ssl_conf_sig_algs()` did not make this separation explicit, which could lead developers to believe that configuring `sig_algs` alone is sufficient to enforce signature algorithm restrictions across the entire handshake, including certificate verification.

An application is vulnerable if it calls `mbedtls_ssl_conf_sig_algs()` to configure a restricted set of algorithms and assumes that the certificate chain will also be verified against that restriction, without also calling `mbedtls_ssl_conf_cert_profile()` with a suitably restrictive profile.

## Impact

A peer may present a certificate chain signed with a signature algorithm that the application intended to reject. If the application relies solely on `mbedtls_ssl_conf_sig_algs()` and does not configure a certificate profile via `mbedtls_ssl_conf_cert_profile()`, the certificate chain signature will be accepted regardless of the configured `sig_algs`. This may allow a peer to use certificates with signature algorithms the developer intended to forbid, potentially weakening the security posture of the application.

## Affected versions

Mbed TLS 3.6.6 and earlier; Mbed TLS 4.0.0 and 4.1.0.

## Resolution

Applications can protect themselves by explicitly calling `mbedtls_ssl_conf_cert_profile()` with an X.509 certificate profile that restricts the accepted signature algorithms to match the intended policy. For example, use one of the built-in profiles such as `mbedtls_x509_crt_profile_suiteb` or define a custom `mbedtls_x509_crt_profile` structure.

## Fix commits

Updated documentation can be found at following commits:

| Branch | Mbed TLS 3.6.x | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- |
| Updated documentation | aecc26ac7c523e741dd62d94890278326fe7c230..b9c8c9c4275bf8e5e88aa9e1e8f6d518fa78367b | b2e36d7d7aa9968087eac0a40457783c61c90720..bd57fb5e8afe003ed24a2ae9e8ca487ecdc4c3f4 | 4a1d150cdf441d0b1d984ea825a21d5770a9f94a..147ad72669797947bef12a0bdbe5dec0ed805c58 |

