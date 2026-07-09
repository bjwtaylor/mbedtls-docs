# Side channel leak in ECC optimized modp (CVE-2026-54435)

**Title** | Side channel leak in ECC optimized modp
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-54435
**Date** | 7th of July, 2026
**Affects** | All versions of Mbed TLS up to 3.6.6; all versions of Mbed TLS from 4.0.0 to 4.1.0; all versions of TF-PSA-Crypto up to 1.1.0
**Not affected** | Mbed TLS 3.6.7 and later 3.6.x versions; Mbed TLS 4.1.1 and later 4.1.x versions; Mbed TLS 4.2.0 and later 4.x versions; TF-PSA-Crypto 1.1.1 and later 1.1.x versions; TF-PSA-Crypto 1.2.0 and later 1.x versions
**Impact** | A privileged local adversary can recover long-term ECC keys
**Severity** | MEDIUM
**Credits** | Alejandro Cabrera Aldaya from Tampere University

## Vulnerability

The TF-PSA-Crypto / Mbed TLS implementation of elliptic curves uses specialised
routines for fast reduction modulo the curve's prime. These routines were not
constant-time. An attacker able to obtain precise enough execution traces can
recover the secret key used in some operations. Affected operations include
deterministic ECDSA signature generation, derivation of the public key when
loading a private key, and deterministic key generation (key derivation). These
operations perform scalar multiplication with the same secret scalar on repeated
invocations.

In order to get precise enough traces, the adversary needs to be local and
privileged: typically an untrusted OS attacking a secure enclave. (Physical side
channels could also be used, but TF-PSA-Crypto [does not aim to
protect](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/SECURITY.md#physical-attacks) against
such attacks.)

## Impact

The adversary can fully recover long-term ECC keys.

## Affected versions

All versions of TF-PSA-Crypto up to 1.1.0 are affected.

All versions of Mbed TLS up to 3.6.6 are affected.
All versions of Mbed TLS from 4.0.0 to 4.1.0 are affected.

## Work-around

There is no practical work-around that applies to all affected curves.

For NIST curves (secpXXXXr1), disabling `MBEDTLS_ECP_NIST_OPTIM` avoids the
affected optimized modular reduction routines. However, this option is enabled
in the default configuration, and disabling it incurs a significant performance
degradation that may not be acceptable.

Brainpool curves are not affected because they do not use fast modular reduction
routines.

Koblitz curves (secpXXXk1) and Montgomery curves (Curve25519 and Curve448) are
affected in all configurations.

## Resolution

Affected users should upgrade to TF-PSA-Crypto 1.1.1 or a later 1.1.x version,
or to TF-PSA-Crypto 1.2.0 or a later 1.x version.

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version, or to
Mbed TLS 4.1.1 or a later 4.1.x version, or to Mbed TLS 4.2.0 or a later 4.x
version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The TF-PSA-Crypto and Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | aecc26ac7c52..6b4b14ae719c4f46ea70600d63b0d50dc727ff3a | 9c0f0cf88a19..072d46a1660b2d21cb8eb17d437efdb6bbfa48bd | feb70754b0a8..0db467d4b32e1cfc94558b96cc5cc92b3ec09598 | n/a (submodule) | n/a (submodule) |
| With tests and documentation | aecc26ac7c52..10f9bd4adda74d71827fd78006136f956d08d554 | 9c0f0cf88a19..23333b8bdd09cd87826fae76972da70f27125aeb | feb70754b0a8..c440358725cb3e70b30cbd984ce7a8c7075c7e2f | n/a (submodule) | n/a (submodule) |
| Additional improvements in the new functions | 5f62b3fa5607..05ce3e90eb863b751c4464633a94239fd1938608 | 592e8d0e0a85..6bf103767c578c39098a3bc76133224fb0d015af | e70cfdcc6be7..af3fe396866dc7cc1f4505191eadc7cbad36d3a4 | n/a (submodule) | n/a (submodule) |

