# Timing side-channel in RSA PKCS#1 v1.5 decryption (CVE-2026-50587)

**Title** | Timing side-channel in RSA PKCS#1 v1.5 decryption
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50587
**Date** | 7th of July, 2026
**Affects** | All versions of Mbed TLS from 2.17.0 to 3.6.6; all versions of Mbed TLS from 4.0.0 to 4.1.0; all versions of TF-PSA-Crypto up to 1.1.0
**Not affected** | Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later 4.x versions; TF-PSA-Crypto 1.1.1 and later 1.1.x versions; TF-PSA-Crypto 1.2.0 and later 1.x versions
**Impact** | Plaintext recovery via decryption side channel
**Severity** | MEDIUM
**Credits** | zhengg

## Vulnerability

The function `psa_asymmetric_decrypt()` used with `PSA_ALG_RSA_PKCS1V15_CRYPT`
has a timing side channel in its error handling that allows an attacker to
distinguish between success, invalid padding, and valid padding that produces
a plaintext larger than the provided buffer.

Additionally, in Mbed TLS 3.6 with `MBEDTLS_USE_PSA_CRYPTO` enabled,
`mbedtls_pk_decrypt()` has a similar side channel when used with RSA PKCS#1
v1.5. (TF-PSA-Crypto retains some `mbedtls_pk_xxx()` APIs, but not
`mbedtls_pk_decrypt()`.)

## Impact

An attacker who can submit crafted RSA PKCS#1 v1.5 ciphertexts for repeated
decryption and distinguish the resulting timing or execution-path differences
can gradually recover plaintexts by exploiting the side channel as a
Bleichenbacher oracle.

Depending on protocol usage, this may allow recovery of transported
secrets (e.g. the pre-master secret in TLS 1.2 pure-RSA key exchange) and
compromise of confidentiality.

## Affected versions

All versions of TF-PSA-Crypto up to 1.1.0 are affected.

All versions of Mbed TLS from 2.17.0 to 3.6.6 are affected.
All versions of Mbed TLS from 4.0.0 to 4.1.0 are affected.

## Work-around

There is no practical work-around for `psa_asymmetric_decrypt()`.

In Mbed TLS 3.6, `mbedtls_pk_decrypt()` is not affected if
`MBEDTLS_USE_PSA_CRYPTO` is disabled, which it is in the default configuration.
(The low-level APIs from `rsa.h` in Mbed TLS 3.6 are not affected, because the
side channel is in error translation and propagation.)

## Resolution

Affected users should upgrade to TF-PSA-Crypto 1.1.1 or a later 1.1.x version,
or to TF-PSA-Crypto 1.2.0 or a later 1.x version.

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version,
or to Mbed TLS 4.1.1 or a later 4.1.x version,
or to Mbed TLS 4.2.0 or a later 4.x version.

## Warning

Even after this side channel in the library is fixed, RSA PKCS#1 v1.5 decryption
remains a dangerous operation, and applications using it need to take at least
the following precautions, where observable behavior may include error
codes, alerts, connection behavior, logs visible to an attacker, later protocol
messages, or timing.

1. Do not allow an attacker to distinguish, through observable behavior, between
   successful decryption, invalid padding, and valid padding with a buffer too
   small for the resulting plaintext.
2. If the protocol expects a fixed-length secret, treat invalid padding or
   unexpected-length plaintexts as a fresh random secret of the expected length,
   without letting observable behavior reveal whether you're using the
   plaintext or the random bytes.
3. Do not let any observable behavior reveal information about individual bytes
   of the decrypted plaintext, such as whether a byte equals an expected value.
4. Do not let any observable behavior reveal the length of the resulting
   plaintext.

RSA PKCS#1 v1.5 decryption is widely considered dangerous, and whenever possible
should be avoided in favour of better alternatives, such as OAEP.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The TF-PSA-Crypto and Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | 4c70413087eb..682d8f3e894e + 8f4a4eac9878 + fe47e9ed89f5 + c76cfd536e488b1397d5077e667e84339e471fa1 | ab2b4230d01b..d9e5bd9ada7babe2c46cc10067aff05ffb2cc466 | b31204d470c9..cc6ade732a46fb9a268c6e51e807ee3ba48fd452 | n/a (submodule) | n/a (submodule) |
| With tests and documentation | 4c70413087eb..591982e0477b6a70dba525b72073054cfdd5996b | ab2b4230d01b..7ecf00d6c444ebe79db1e55870b97c30526c03c0 | b31204d470c9..f625206b88bbcba76551a007bc38e3ff8858c686 | n/a (submodule) | n/a (submodule) |
