# Possible buffer overflow in `mbedtls_ecdh_calc_secret()` (CVE-2026-35336)

**Title** | Possible buffer overflow in `mbedtls_ecdh_calc_secret()`
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-35336 
**Date** | 7th of July, 2026
**Affects** | All versions of Mbed TLS up to 3.6.6
**Not affected** | Mbed TLS 3.6.7 and later, Mbed TLS 4.0 and later, all versions of TF-PSA-Crypto
**Impact** | Depending on the location of the buffer, up to remote code execution
**Severity** | MEDIUM
**Credits** | Reported by Eva Crystal (0xiviel), founder of XSource Security

## Vulnerability

When `mbedtls_ecdh_calc_secret()` is called with an output buffer that is too small to hold the output, sometimes the function will not return an error as it should, but instead write past the end of the buffer.

The behaviour depends on the value of the computed shared secret, which is unpredictable to the attacker, so the behaviour can be considered random. For example, when using the curve NIST P-521 (secp521r1), which requires a 66-byte output buffer:
- if the provided buffer is 65 bytes, the function will overwrite it by 1 byte with probability around 1/2 (and otherwise correctly return an error);
- if the provided buffer is 64 bytes, it will be overwritten by 2 bytes with probability around 1/512 (otherwise an error is returned);
- if it is 48 bytes (sized for a 384-bit curve), it will be overwritten by 18 bytes with probability 2^-137 (so, in practice never and an error is always returned).

This is due to the size check omitting the most significant bytes of the shared secret if those happen to be zero, while all the bytes are going to be written out regardless.

Note that unlike some buffer overflows that cause the function to write more than expected, the function always writes the expected amount. It will only overflow the buffer if it was too small in the first place. Said otherwise, applications that are functionally correct are also immune from this overflow.

## Impact

The impact depends on the location of the buffer being overwritten and the memory layout of the application. The attacker does not control the bytes being written past the end of the buffer, but depending on the environment, may be able to try repeatedly. In the worst case, the consequences may range up to arbitrary code execution.

## Affected versions

All versions of Mbed TLS up to Mbed TLS 3.6.6 are affected.

Mbed TLS 4.0 and higher is not affected (does not call this API).

TF-PSA-Crypto is not affected (does not contain this API).

## Work-around

Applications should ensure that the buffer passed to `mbedtls_ecdh_calc_secret()` is large enough: at least `(bits + 7) / 8` bytes, where `bits` is the bit size of the curve being used. The macro `MBEDTLS_ECP_MAX_BYTES` provides a size that's safe for all curves enabled in this build.

Applications that do not call `mbedtls_ecdh_calc_secret()` are not affected. Applications that only call `mbedtls_ecdh_calc_secret()` with a large enough buffer are not affected.

The API `psa_raw_key_agreement()` was not affected as it has a correct size check.

Use of ECDH in TLS was not affected as the output buffer is always large enough.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or later, or use the above work-around.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.x | Mbed TLS 4.x |
| ------ | -------------- | ----------------- | ------------ |
| Basic fix | 1d71bcc31cb8080b14b0dcbc6bc859c11d622c0f | n/a | n/a |
| With tests and documentation | 77b1a22bc31d..00d767aef58b | n/a | n/a |
