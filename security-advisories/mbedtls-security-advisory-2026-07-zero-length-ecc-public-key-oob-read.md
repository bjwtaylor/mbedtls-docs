# Out-of-bounds read when parsing a zero-length ECC public key (CVE-2026-50583)

**Title** | Out-of-bounds read when parsing a zero-length ECC public key
--------- | ------------------------------------------------------------
**CVE** | CVE-2026-50583
**Date** | 30 June 2026
**Affects** | All versions of Mbed TLS from 3.5.0 to 3.6.6 with driver-only ECC; all versions of Mbed TLS from 4.0.0 to 4.1.0; all versions of TF-PSA-Crypto up to 1.1.0
**Not affected** | Mbed TLS up to 3.4.1; Mbed TLS 3.5.0 through 3.6.6 with built-in ECC; Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later 4.x versions; TF-PSA-Crypto 1.2.0 and later 1.x versions
**Impact** | Out-of-bounds read while parsing malformed ECC key material, potentially causing a crash
**Severity** | LOW

## Vulnerability

When parsing malformed externally supplied ECC key material, Mbed TLS or
TF-PSA-Crypto can read one byte past the supplied public-key buffer. The
malformed input can be an ASN.1 SubjectPublicKeyInfo whose ECC public-key
BIT STRING contains no ECPoint payload, or the optional `publicKey` field of a
SEC1 ECPrivateKey.

In Mbed TLS, this issue can be reached through APIs that parse ECC public keys,
EC private keys, certificates or CSRs, including
`mbedtls_pk_parse_public_key()`, `mbedtls_pk_parse_key()`,
`mbedtls_x509_crt_parse()` and `mbedtls_x509_csr_parse()`.

Internally, the missing length check is in `mbedtls_pk_ecc_set_pubkey()`, which
inspects the first byte of the encoded public key before validating that the
supplied public-key buffer is non-empty.

In Mbed TLS 3.x, this code path is only used when `MBEDTLS_PK_USE_PSA_EC_DATA`
is defined. Builds using the legacy ECP-backed representation are not affected.
Mbed TLS 4.x is affected through its TF-PSA-Crypto submodule.

## Impact

Out-of-bounds read while parsing malformed ECC key material, potentially causing
a crash.

## Affected versions

All versions of TF-PSA-Crypto up to 1.1.0 are affected.

All versions of Mbed TLS from 3.5.0 to 3.6.6 are affected in configurations where
`MBEDTLS_USE_PSA_CRYPTO` and the PK module are enabled, PSA supports ECC through
a driver, and built-in ECC support is disabled.

All versions of Mbed TLS from 4.0.0 to 4.1.0 are affected.

## Work-around

Applications using vulnerable versions should avoid parsing ECC public keys,
certificates, CSRs or EC private keys unless the input has first been validated
to reject zero-length ECC public-key encodings.

## Resolution

Affected users should upgrade to TF-PSA-Crypto 1.1.1 or a later 1.1.x version,
or to TF-PSA-Crypto 1.2.0 or a later 1.x version.

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version,
or to Mbed TLS 4.1.1 or a later 4.1.x version,
or to Mbed TLS 4.2.0 or a later 4.x version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The TF-PSA-Crypto and Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | 0e2d7037db4048dbf1c194508c07384a818261d5 | c99519080302cbcf19ad61d57c1d6fc614608336 | e7183dbf9789834f89a5ed41f2156dcf34f130c3 | N/A | N/A |
| With tests and documentation | aecc26ac7c523e741dd62d94890278326fe7c230..3208173d3d6728b6d1eb25a1a448067c781cbb69 | de89cfc02ecb5a4ae67da155ebace3eff83555b2..32a2f6bb62dd3837951ccd546cb62638d56cbf61 | feb70754b0a8d79f46d2c5f3eb8348c2212918c8..718f15d851316cbed7242b3a07b31c1712c51ef1 | N/A | N/A |
