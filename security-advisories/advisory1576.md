# Use-after-free in mbedtls_pkcs7_free() when reusing a PKCS7 context (CVE-2026-50579)

**Title** | Use-after-free in mbedtls_pkcs7_free() when reusing a PKCS7 context
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50579
**Date** | TODO(publication date)
**Affects** | Mbed TLS 3.3.0 through 3.6.6; Mbed TLS 4.0.0 through 4.1.0
**Not affected** | Mbed TLS before 3.3.0; Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later versions
**Impact** | Memory corruption and denial of service
**Severity** | HIGH
**Credits** | NVIDIA Project Vanessa

## Vulnerability

`mbedtls_pkcs7_free()` frees the signer list in an `mbedtls_pkcs7` context, but in affected versions it only clears `pkcs7->raw.p` before returning. Other fields in the context, including `signed_data.signers.next`, can therefore retain stale pointers to freed memory.

An application is vulnerable if it parses PKCS7 data into an `mbedtls_pkcs7` context, calls `mbedtls_pkcs7_free()` on that context, and later reuses the same context for another PKCS7 parse without first reinitializing it. In such a parse -> free -> parse -> free sequence, specially crafted PKCS7 input can leave stale signer-list pointers in the context and cause a later free operation to walk freed memory.

Applications are not affected if they do not build or enable `MBEDTLS_PKCS7_C`, if they do not parse PKCS7 data, or if they do not reuse an `mbedtls_pkcs7` context after calling `mbedtls_pkcs7_free()` without reinitializing it.

## Impact

A malicious PKCS7 input can trigger a use-after-free or double-free in applications that reuse an `mbedtls_pkcs7` context after freeing it. This can lead to memory corruption and denial of service. Depending on the platform, allocator behavior, and surrounding application memory layout, further impact may be possible.

## Affected versions

Mbed TLS 3.3.0 through 3.6.6 are affected.
Mbed TLS 4.0.0 through 4.1.0 are affected.

Mbed TLS versions before 3.3.0 are not affected because they do not include the affected PKCS7 parser code.

TF-PSA-Crypto is not affected.

## Work-around

Applications using an affected version should not reuse an `mbedtls_pkcs7` context after calling `mbedtls_pkcs7_free()` unless the context is reinitialized with `mbedtls_pkcs7_init()` before the next parse operation.

Applications can also avoid the issue by using a fresh `mbedtls_pkcs7` context for each PKCS7 parse/free cycle.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version,
or to Mbed TLS 4.1.1 or a later 4.1.x version,
or to Mbed TLS 4.2.0 or a later version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The TF-PSA-Crypto and Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | 699d4030c2eba488033d2291d52966533c819db0 | N/A | N/A | b1a4b07509cbadbaa963ae896d4d44ddba550f74 | 67e696b430716f95ed714f2c1404681697251438 |
| With tests and documentation | 699d4030c2eba488033d2291d52966533c819db0^..12717ec8f4c3c4721365c6dcb588e77f3ef6e223 | N/A | N/A | b1a4b07509cbadbaa963ae896d4d44ddba550f74^..c20cd06cb41453ed29609c3cd9aacf24e54a7083 | 67e696b430716f95ed714f2c1404681697251438^..377aa4eff16cd0aa5e7440a41de59847e3a789a0 |
