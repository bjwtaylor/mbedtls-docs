# Everest: lack of contributory behaviour due to improper input validation (CVE-2026-54434)

**Title** | Everest: lack of contributory behaviour due to improper input validation
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-54434
**Date** | TODO(33 Grune 20xx)
**Affects** | TF-PSA-Crypto 1.1.0, Mbed TLS 4.1.0
**Not affected** | TF-PSA-Crypto 1.0.0, Mbed TLS 4.0.0 and earlier
**Impact** | ECDH does not guarantee contributory behaviour, which some protocols may require
**Severity** | MEDIUM
**Credits** | foobarto

## Vulnerability

In builds with `MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED`, when doing key agreement
with `PSA_ALG_ECDH` on Curve25519 (X25519) using the built-in driver, the
implementation does not reject an all-zero shared secret. As a result, the peer
can force the resulting shared secret to a fixed value. This is known as lack of
contributory behaviour.

Curve25519 as specified by RFC 7748 does not mandate this check. Some protocols do mandate it, notably TLS.

## Impact

The direct impact is that the peer can force the ECDH shared secret to a fixed
value (all-zero). The larger impact depends on the overall protocol in which ECDH
is used.

The problem is not known to be exploitable in TLS 1.3 (or TLS 1.2 when the
extended master secret extension is used). In that case, the derived secrets
depends on the full handshake transcript, preventing an attacker from
achieving key synchronization between different connections (unknown key share).

The problem may be exploitable in TLS 1.2 when the extended master secret
extension is not used, as it removes the ECDH contribution to the master secret,
which may be the first step in attacks such as those described in Section VI of the
[Triple Handshake
paper](https://inria.hal.science/hal-01102259/file/triple-handshakes-and-cookie-cutters-oakland14.pdf),
and could lead to other similar attacks. (Note that the
Triple Handshake attack itself (VI-A) should not be possible as Mbed TLS does
not allow the peer to change its certificate during renegotiation.)

## Affected versions

The only affected versions are TF-PSA-Crypto 1.1.0 and Mbed TLS 4.1.0.

## Work-around

Applications that do not enable `MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED` are not
vulnerable (this option is disabled in the default configuration).

Applications that do not use ECDH with Curve25519 (X25519) in a protocol that
requires contributory behaviour are not vulnerable.

If practical, applications that enable Everest and use X25519 in a protocol that
requires contributory behaviour should manually check whether the shared secret
is all-zero and abort if that's the case.

## Resolution

Affected users should upgrade to TF-PSA-Crypto 1.1.1 or later (resp. Mbed TLS
4.1.1 or later).

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | n/a | 1ffb2d8b7a5afcb8452bffd9ede9b9e0b0c4b281 and 90bb6c6581e8cd5b37d7478bc15439e08eea9889 | 01a7c529e1b60f26d4085997b1b1ee9eea3fdec8 and 7d1f5a972c8d8b8687dd4fd47fb69450e04dfd55 | n/a (submodule) | n/a (submodule) |
| With tests and documentation | n/a | de89cfc02ecb..90bb6c6581e8cd5b37d7478bc15439e08eea9889 | 4b8d491f8b2e..7d1f5a972c8d8b8687dd4fd47fb69450e04dfd55 | n/a (submodule) | n/a (submodule) |
