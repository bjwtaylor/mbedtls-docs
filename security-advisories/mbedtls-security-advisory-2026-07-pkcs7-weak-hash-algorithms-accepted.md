# PKCS7 signed data verification accepts weak hash algorithms

**Title** | PKCS7 signed data verification accepts weak hash algorithms
--------- | ----------------------------------------------------------
**CVE** | N/A
**Date** | 7th of July, 2026
**Affects** | Mbed TLS from 3.3.0 up to 3.6.6; Mbed TLS 4.0.0 to 4.1.0
**Not affected** | Mbed TLS 3.6.7 and later 3.6.x versions, Mbed TLS 4.1.1 and later 4.1.x versions, Mbed TLS 4.2 and later 4.x versions
**Impact** | An attacker capable of engineering hash collisions can forge a second message that passes PKCS7 signature verification against a previously validated signature
**Severity** | LOW

## Vulnerability

`mbedtls_pkcs7_signed_data_verify()` and `mbedtls_pkcs7_signed_hash_verify()` accepted any hash
or signature algorithm that was enabled in the library, including algorithms for which collisions
can be engineered (MD5 or SHA-1). The choice of algorithm is taken from the PKCS7 context
itself (i.e. it is attacker-controlled) and was not validated against any security profile.

Consider the following protocol:

1. Alice sends Bob a message together with a PKCS7 signature.
2. Bob verifies the message against the PKCS7 signature and, on success, records the signature
   as a validated one.
3. Later, Alice sends Bob a new message together with the same PKCS7 signature.
4. Bob verifies the new message against the recorded PKCS7 signature and accepts it.
5. Bob takes some action based on the content of the new, unvalidated message.

If the hash algorithm used in the PKCS7 structure is MD5 or SHA-1, an attacker can craft
two different messages that produce the same hash, and thus share a valid PKCS7 signature. This
makes step 4 accept a message that was never signed by Alice.

## Impact

An attacker able to compute a hash collision can produce a second message that passes PKCS7
signature verification with an existing, legitimately generated signature. Applications that
use the signature of a PKCS7 object as an indication that the data is valid may then act on
content that has not been authenticated by the signer.

## Affected versions

Mbed TLS from 3.3.0 up to 3.6.6; Mbed TLS 4.0.0 to 4.1.0.

## Work-around

Disable `MBEDTLS_PKCS7_C` or use ASN1 APIs to parse the PKCS#7 content and verify that
DigestAlgorithmIdentifiers does not contain any weak hash algorith.

An application built without `MBEDTLS_PKCS7_C` is not vulnerable.

Applications that only accepts PKCS7 data that has been signed by entitites that they
trust not to use weak cryptography are not vulnerable.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version, to Mbed TLS 4.1.1 or a
later 4.1.x version, or to Mbed TLS 4.2.0 or a later 4.x version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | -------------- | --------------------- |
| With tests and documentation | f6f6492228b3914fe42a95724d24cdca9abdb790..16415a66b4f1669a459441eaee5421b28d0c0d7c | 2660eea3f04776a9f57bfe92a5ae534bda4f659d..5b67d61d0281a4456986d18dbe49a0fa3d06431e | 2beeff6a8e64ce9dedcb6fa986ea9e6d340abe09..f155d9fefd3d8cc59c7294ca1bcbed7715b0d9ae |
