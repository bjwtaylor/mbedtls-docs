# Extended master secret calculation failure ignored (CVE-2026-50581)

**Title** | Extended master secret calculation failure ignored
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50581
**Date** | TODO(33 Grune 20xx)
**Affects** | all versions of Mbed TLS up to 3.6.6; Mbed TLS 4.0.0 to 4.1.0
**Not affected** | Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later versions
**Impact** | security degratation in protocols using the TLS master secret; sanitizer crash
**Severity** | LOW
**Credits** | Matthew Gretton-Dann

## Vulnerability

### Extended master secret

The peers of a TLS connection establish a shared secret, called the master secret, which is used to validate the handshake (through the Finished messages), to calculate session keys, and which can be used to derive additional cryptographic material for higher-level protocols.

In TLS versions up to 1.2 (including DTLS), the Extended Master Secret (EMS) extension, defined by [RFC 7627 §4](https://datatracker.ietf.org/doc/html/rfc7627#section-4), changes the way the master secret is calculated to make it more robust some attacks. (In TLS 1.3, the basic protocol already has the desired properties.) Specifically, in the basic protocol, a man-in-the-middle may be able to force its connection with a victim client and its connection with a victim server to have the same master secret, which breaks assumptions of higher-level protocols such as EAP. See the paper [“Triple Handshakes and Cookie Cutters: Breaking and Fixing Authentication over TLS” by Bhargavan et al. (2014)](https://inria.hal.science/hal-01102259/file/triple-handshakes-and-cookie-cutters-oakland14.pdf) for more information. Mbed TLS uses the EMS extension if possible.

The master secret is the output of a pseudorandom function. One of its inputs is a session value. In the basic protocol, the session value is the concatenation of the ClientHello random value and the ServerHello random value. When the Extended Master Secret extension is enabled, the session value is a hash of the transcript of the handshake so far.

Due to an implementation flaw in the affected versions of the library, if the calculation of the transcript hash fails, the handshake continues with an incorrect value, and the code reads from a stack buffer out of bounds. The gist of the affected code in `ssl_compute_master()` in `ssl_tls.c` is as follows (many irrelevant lines are omitted):

```
unsigned char session_hash[48];
unsigned char const *seed = handshake->randbytes;
size_t seed_len = 64;
if (handshake->extended_ms == MBEDTLS_SSL_EXTENDED_MS_ENABLED) {
    seed = session_hash;
    ret = handshake->calc_verify(ssl, session_hash, &seed_len);
    // missing: early return if ret != 0
}
// ...
if (mbedtls_ssl_ciphersuite_uses_psk(handshake->ciphersuite_info) == 1) {
    status = setup_psa_key_derivation(&derivation, psk, alg,
                                      ssl->conf->psk, ssl->conf->psk_len,
                                      seed, seed_len,
                                      (unsigned char const *) lbl,
                                      (size_t) strlen(lbl),
                                      other_secret, other_secret_len,
                                      master_secret_len);
    status = psa_key_derivation_output_bytes(&derivation,
                                             master,
                                             master_secret_len);
} else {
    ret = handshake->tls_prf(handshake->premaster, handshake->pmslen,
                             lbl, seed, seed_len,
                             master,
                             master_secret_len);
}
```

Depending on the exact way in which `handshake->calc_verify()` fails, the `seed` buffer may end up having predictable content.

* If `seed_len` is not updated, then `session_hash` remains uninitialized. Thus the `seed` input to the calculation of the master secret (`master`) is indeterminate, and overreads the stack buffer for 16 bytes.
* If `seed_len` is updated to the correct value, but `session_hash` remains uninitialized, then the `seed` input to the calculation of the master secret (`master`) is indeterminate.
* If `seed_len` is updated to 0, then the `seed` input to the calculation of the master secret (`master`) is the empty string.

If `seed_len` is not updated and the environment detects stack buffer overflows precisely, for example with AddressSanitizer, the application aborts. Note that there is no risk of overflowing the stack itself, because auxiliary functions called by `ssl_compute_master()` use more than 16 bytes of stack.

Otherwise the calculated master secret is wrong. This causes the Finished message to have the wrong value, and hence a correctly operating peer will abort the handshake.

### Consequences if both peers are affected

If both peers are running Mbed TLS with the same flaw, it is in principle possible that both sides will have the same content on the stack, and thus they will end up with the same incorrect master secret. Because the master secret no longer depends on the handshake transcript, it allows impersonation attacks on protocols such as EAP-TLS that rely on the uniqueness of the TLS master secret.

The master secret depends on other inputs which are not affected, including the premaster secret. Thus this flaw does not allow the attacker to discover the master secret. Furthermore, the Finished calculation still correctly uses a handshake transcript including both the ClientHello random and the ServerHello random. Hence the flaw does not allow a direct man-in-the-middle attack, or a direct replay attack. Also, the basic triple handshake attack against TLS itself, as described in the 2014 Bhargavan et al. paper, is no longer possible since Mbed TLS does not allow a server certificate change on renegotiation.

Since the uninitialized stack buffer is only used as the input of a pseudorandom function, there is no risk of leaking the stack content.

### Failure modes of `calc_verify`

The following failure modes are possible in the `calc_verify` implementation:

* An intermediate function used before the hash calculation requires heap memory, and the memory allocation fails.
* The hash calculation uses a third-party driver which reports an error. Plausible error causes are a failure of the underlying hardware, or a failure of a heap allocation.

Whether a heap allocation is required, and whether failures cause `seed_len` to be updated, depends on the library version, on the configuration and on the (D)TLS protocol version.

* Up to Mbed TLS 3.3.x, when `MBEDTLS_USE_PSA_CRYPTO` is not enabled, there is no heap allocation. `seed_len` is always updated.
* In Mbed TLS 3.4.x to 3.6.x, when `MBEDTLS_USE_PSA_CRYPTO` is not enabled, there is a heap allocation. `seed_len` is not updated if any failure occurs.
* From Mbed TLS 2.23.0 to 3.3.x, when `MBEDTLS_USE_PSA_CRYPTO` is enabled, there is a heap allocation in (D)TLS 1.2 (using SHA-256 or SHA-384), but not in earlier protocol versions (using MD5 and SHA-1 — not available from Mbed TLS 3.0.0 onwards). `seed_len` is not updated if any failure occurs.
* In Mbed TLS 3.4.x, when `MBEDTLS_USE_PSA_CRYPTO` is enabled, there is no heap allocation. `seed_len` is not updated if any failure occurs.
* In Mbed TLS 3.5.x, when `MBEDTLS_USE_PSA_CRYPTO` is enabled, there is no heap allocation. `seed_len` is always updated.
* In Mbed TLS 3.6.x, when `MBEDTLS_USE_PSA_CRYPTO` is enabled, there is a heap allocation unless `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` is enabled. `seed_len` is not updated if this allocation fails, but it is updated if the hash calculation itself fails.
* In Mbed TLS 4.0.0 to 4.1.0, there is a heap allocation unless `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` is enabled. `seed_len` is not updated if this allocation fails, but it is updated if the hash calculation itself fails.

## Impact

Affected versions of Mbed TLS may be affected by the attack on higher-level protocols such as EAP which the TLS extended master secret was designed to prevent, if both peers are running an affected version and the attacker manages to cause a failure on both sides. In addition, the bug may cause a buffer overread on the stack (but not a stack overread).

The table below describes the impact of the flaw based on the library version, the compile-time configuration and the protocol version. In this table:

* “Hash driver failure” refers to the alternative implementation (up to Mbed TLS 3.x) or the PSA accelerator driver (for (D)TLS 1.2 when `MBEDTLS_USE_PSA_CRYPTO` is enabled, or for (D)TLS 1.2 in Mbed TLS 4.x) for the applicable hash algorithm.
* “uniq” indicates that an attack on the master secret uniqueness in higher-level protocols may be possible if both the client and the server are affected.
* “ASan” indicates that an affected application may crash if the platform detects a 16-byte buffer overread on the stack.
* “N/A” indicates that the failure is not possible in this configuration.

| Library version | Configuration | (D)TLS version | Hash driver failure | Heap allocation failure |
| --------------- | ------------- | -------------- | ------------------- | ----------------------- |
| up to 3.3.x | default | $\le 1.2$ | uniq | N/A |
| 3.4.0 to 3.6.x | default | $\le 1.2$ | uniq | uniq, ASan |
| 2.23.0 to 2.28.x | `MBEDTLS_USE_PSA_CRYPTO` enabled | $\le 1.1$ | uniq | N/A |
| 2.23.0 to 3.3.x | `MBEDTLS_USE_PSA_CRYPTO` enabled | $1.2$ | uniq, ASan | uniq, ASan |
| 3.4.x | `MBEDTLS_USE_PSA_CRYPTO` enabled | $1.2$ | uniq, ASan | N/A |
| 3.5.x | `MBEDTLS_USE_PSA_CRYPTO` enabled | $1.2$ | uniq | N/A |
| 3.6.0 to 3.6.6 | `MBEDTLS_USE_PSA_CRYPTO` enabled, `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` not enabled | $1.2$ | uniq | uniq, ASan |
| 3.6.0 to 3.6.6 | `MBEDTLS_USE_PSA_CRYPTO` enabled, `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` enabled | $1.2$ | uniq | N/A |
| 4.0.0 to 4.1.0 | `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` not enabled | $1.2$ | uniq | uniq, ASan |
| 4.0.0 to 4.1.0 | `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` enabled | $1.2$ | uniq | N/A |

## Affected versions

All versions of Mbed TLS up to 3.6.6, and Mbed TLS 4.0.0 and 4.1.0, may be affected by an impersonation attack on higher-level protocols if both the TLS client and the TLS server are running a vulnerable version. See [RFC 7627](https://datatracker.ietf.org/doc/html/rfc7627#section-6.1) for more information about the attack.

In addition, Mbed TLS 3.4.0 to 3.6.6, and Mbed TLS 4.0.0 and 4.1.0, are affected by a stack buffer overread in some configurations, as described in the “[Impact](#impact)” section above.

## Work-around

Applications can avoid the stack buffer overflow by disabling the extended master secret extension. This can be done at compile time by disabling `MBEDTLS_SSL_EXTENDED_MASTER_SECRET`, or at runtime by calling `mbedtls_ssl_conf_extended_master_secret(&ssl_conf, MBEDTLS_SSL_EXTENDED_MS_DISABLED)`. Note however that this makes the application susceptible to attacks based on the lack of uniqueness of the master secret.

To maintain the master secret uniqueness, it is enough for one end of the TLS connection to run a non-vulnerable version of Mbed TLS or a different TLS implementation.

Versions and configurations that do not allocate memory and use the built-in hash implementation are not affected. See the “[Impact](#impact)” section above for details.

TLS 1.3 is not affected.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version, to Mbed TLS 4.1.1 or a later 4.1.x version, or to Mbed TLS 4.2.0 or above.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | Mbed TLS 4.1.x | Mbed TLS 4.x |
| ------ | -------------- | ----------------- | ------------ |
| Basic fix | f595df4569c1a1650ad9d077e2f2e819e9f1dddb | 4e26c248ec9541b95d3e3e0178960f53d8bb40b8 | 9063aca165efaa68c08f95159c4e84e0f17464a9 |
| With tests and documentation | 338572c1d805a31b875a448536bcb50d72f9bc40..27065ceb643a4266888ba1f200e4f20845e801cf | 657760964e57fd9d88aead3f9bf69b97442a9294..7cbd8582ee9942ffce5dc907dc36addcdc2185eb | 98e4a7b02afd5f421cb3c9659c1678f282b2650a..c438b0b9a92d81fd7ec8aa9148d0272299815155 |
