# Out-of-bounds read in TLS 1.2 EC J-PAKE ServerKeyExchange parsing (CVE-2026-50588)

**Title** | Out-of-bounds read in TLS 1.2 EC J-PAKE ServerKeyExchange parsing
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50588
**Date** | 7th of July, 2026
**Affects** | Mbed TLS 3.3.0 through 3.6.6; Mbed TLS 4.0.0 through 4.1.0
**Not affected** | Mbed TLS before 3.3.0; Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later 4.x versions
**Impact** | A malicious TLS 1.2 server can cause a client to read outside the validated ServerKeyExchange message while parsing an EC J-PAKE key exchange
**Severity** | LOW
**Credits** | Biniam Demissie

## Vulnerability

In TLS 1.2 clients, when parsing a ServerKeyExchange message for the EC J-PAKE
ciphersuite, Mbed TLS read the first three bytes of the EC J-PAKE key exchange
parameters before checking that three bytes were present in the message body.
These bytes encode the curve type and the TLS named curve identifier.

If a malicious TLS 1.2 server selected the
`MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8` ciphersuite and sent a truncated
ServerKeyExchange message, the client could read beyond the validated end of
the current handshake message. If the bytes read beyond the message happened to
match the expected curve encoding, subsequent EC J-PAKE parsing could consume a
larger amount of data outside the message boundary.

This vulnerability only affects builds with
`MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED` enabled. EC J-PAKE support is disabled
in the default Mbed TLS configuration.

## Impact

A malicious TLS 1.2 server can trigger an out-of-bounds read in an affected
client during the handshake. In most configurations, the read remains within
the TLS input buffer and reads stale data from outside the current handshake
message. In configurations where the TLS input buffer is too small for an
EC J-PAKE handshake, the read can go past the end of the heap buffer.

The overread data is not copied back to the peer. The practical information
leakage is limited to whether the overread data is accepted by later parsing,
so the severity is LOW.

## Affected versions

Mbed TLS versions 3.3.0 through 3.6.6 and 4.0.0 through 4.1.0 are affected when
`MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED` is enabled.

Mbed TLS versions before 3.3.0 do not have the affected EC J-PAKE
ServerKeyExchange parsing code. Mbed TLS 3.6.7 and later 3.6.x versions,
Mbed TLS 4.1.1 and later 4.1.x versions, and Mbed TLS 4.2.0 and later 4.x
versions, are not affected.

## Work-around

Disable TLS 1.2 EC J-PAKE support by disabling
`MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED`, or ensure that clients do not offer the
`MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8` ciphersuite.

Applications that are built without `MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED`, do
not use TLS clients, only use TLS 1.3, or never allow negotiation of the
EC J-PAKE ciphersuite are not vulnerable.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version,
Mbed TLS 4.1.1 or a later 4.1.x version, or Mbed TLS 4.2.0 or a later version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | e3be807e5c5ce216b8b832b1e746e4ef5c0765bf | N/A | N/A | 1ac3989db6cd0416f562764e3bfacca62ce4875c | 08e3e3f81e6c5703c3afcbfcb47c600a2b10afcb |
| With tests and documentation | e3be807e5c5ce216b8b832b1e746e4ef5c0765bf^..e1351f7881991951049fdcca230edd85dcde6f90 | N/A | N/A | 1ac3989db6cd0416f562764e3bfacca62ce4875c^..1a5e328377af66a1795ebf9440e79592bffa2a71 | 08e3e3f81e6c5703c3afcbfcb47c600a2b10afcb^..1aa125454601ef3492c285d2122518ac3fa3b6c2 |
