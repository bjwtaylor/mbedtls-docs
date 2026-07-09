# ChaCha20 counter overflow can reuse keystream (CVE-2026-50584)

**Title** | ChaCha20 counter overflow can reuse keystream
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50584
**Date** | 7th of July, 2026
**Affects** | Mbed TLS 2.12.0 through 3.6.6; Mbed TLS 4.0.0-beta through 4.1.0; TF-PSA-Crypto 1.0.0-beta through 1.1.0
**Not affected** | Mbed TLS before 2.12.0; Mbed TLS 3.6.7 and later 3.6.x; Mbed TLS 4.1.1 and later 4.1.x; Mbed TLS 4.2.0 and later; TF-PSA-Crypto 1.1.1 and later 1.1.x; TF-PSA-Crypto 1.2.0 and later
**Impact** | Reuse of ChaCha20 keystream can compromise confidentiality, and excessive ChaCha20-Poly1305 input can expose the Poly1305 one-time key and allow message forgery.
**Severity** | MEDIUM
**Credits** | jiliang

## Vulnerability

The ChaCha20 implementation in Mbed TLS and TF-PSA-Crypto did not reject
operations that made the 32-bit ChaCha20 block counter wrap around. The counter
could silently advance from `0xffffffff` to `0x00000000`, causing the same
keystream blocks to be generated again for a single key and nonce.

ChaCha20 has a 64-byte block size and a 32-bit block counter, so at most
`2^32` blocks, or 256 GB, may be processed for one key and nonce. Affected
versions did not consistently enforce this limit in the low-level ChaCha20 API,
the ChaCha20-Poly1305 API, or the PSA AEAD API.

Applications are vulnerable if they can process more than 256 GB of ChaCha20
data with the same key and nonce, or if they use the low-level
`mbedtls_chacha20_crypt()` API with a starting counter and input length that
crosses the end of the 32-bit counter range. For example, an operation starting
at counter `0xffffffff` with more than one ChaCha20 block of input could wrap
and reuse keystream from the beginning of the counter space.

For ChaCha20-Poly1305, counter 0 is reserved for deriving the one-time
Poly1305 key, and encryption normally starts at counter 1. If an overlong
message makes the ChaCha20 counter wrap to 0, the implementation can expose the
same block-0 keystream material that is used as the Poly1305 key. If an
attacker can know or control the corresponding plaintext, they can recover the
one-time Poly1305 key for that nonce and forge authenticators for messages under
the same key and nonce. This is a loss of authenticity for ChaCha20-Poly1305.

## Impact

If an application encrypts enough data for the ChaCha20 counter to wrap while
reusing the same key and nonce, ciphertext confidentiality can be compromised
because keystream bytes are reused. In ChaCha20-Poly1305, processing an
overlong message can also expose the Poly1305 one-time key for the nonce,
allowing message forgery.

The practical exposure is limited to applications that process very large
messages or streams, or that directly request ChaCha20 output close to the end
of the counter range. Applications that never process such large amounts of data
under a single key and nonce are not affected in practice.

## Affected versions

Mbed TLS 2.12.0 through 3.6.6, and Mbed TLS 4.0.0-beta through 4.1.0, are
affected. Mbed TLS 3.6.7, Mbed TLS 4.1.1, and Mbed TLS 4.2.0 contain
the fix. Earlier Mbed TLS
releases, including Mbed TLS 2.11.0, are not affected because they did not
include ChaCha20 or ChaCha20-Poly1305 support.

TF-PSA-Crypto 1.0.0-beta through 1.1.0 is affected. TF-PSA-Crypto 1.1.1
and TF-PSA-Crypto 1.2.0 contain the fix.

Mbed TLS TLS protocol code is not affected as it does not expose a way to exceed
the ChaCha20-Poly1305 record limits under a single key and nonce.

## Work-around

Applications using an affected library version should ensure that no ChaCha20
operation processes more than 256 GB with the same key and nonce. Applications
should also ensure that direct uses of `mbedtls_chacha20_crypt()` do not combine
a starting counter and input length that cross the 32-bit block counter limit.

For ChaCha20-Poly1305, applications should impose a stricter per-message limit
of 256 GB - 64 bytes and must not encrypt or decrypt input that would cause the
underlying ChaCha20 counter to wrap. If a stream can approach this limit, rekey
before the limit is reached.

Applications are not vulnerable in practice if they never process enough data
with one ChaCha20 key and nonce for the 32-bit block counter to wrap.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x
version, TF-PSA-Crypto 1.1.1 or a later 1.1.x version, or
TF-PSA-Crypto 1.2.0 or a later version.

The fix makes ChaCha20 and ChaCha20-Poly1305 operations fail when
processing the requested input would wrap the 32-bit block counter.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you
are maintaining a branch with backported bug fixes, here are the most relevant
commits. Please note that these commits may not apply cleanly to older versions
of the library, and may not provide a complete fix even if they do apply. The
Mbed TLS development team does not provide support outside of maintained
branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | 609b1c51b1a6fdb23210075607529a0505e0c4f9 56b050d7386440555bf2077ea0f0334b0bae1ee9 7bf0215f8d2a5b4ca5b56c4692ef09176a342e91 4ee90fe0e626c5d7ed06f803ff3a4470172659ac |7f54f62dd153ca3517956ffe0f21ff8e40d4f5c2 43899e4ae6f664ac568eedf2737d2aaf0e2782dd 92c6e9e027714c76fe4964923e81108405681509 ba70d7119b2f93b095f445904c9e6b63ca939b33 539b6749e8bd9107a4be176df53e1bcebbb21e45 b7166633d54719586ef49ef332c09f195159114d | 0a0770afe00ff18ebaa2b9d6a59e55af85f3c77e f27067bf2826e33c34422f60d5ed20192ac12bfc 001716ed1ebef1f0f7f59a9c1fbc65c3b3ee70ab f5197f0e194f3903bb0fc134d30036efec2593b9 af6e027450892b0ff36a14a3b50be93ce0f1cfd0 8de9f6aa776d5e92d77b10dfca6666f83f542ab2 | N/A | N/A |
| With tests and documentation |e05f16967735b1a7f184406269e1b7959949b17d^..e8908dfa54422bed618ed6dc3fb9a8a77d516245  |21b9b1ec550b71216592b317f64a11453b2ef66b^..b3ae691c3c58668244bd7c6f31de82a71359fbf0 |897ec8da009c88f5dcf10c947b03f085cc199210^..89620b3cd4649dc3af967af8cf901dcaa1986ec0 | N/A | N/A |
