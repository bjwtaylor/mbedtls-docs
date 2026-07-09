# Heap corruption with early renegotiation after corrupted record in DTLS (CVE-2026-50713)

**Title** | Heap corruption with early renegotiation after corrupted record in DTLS
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50713
**Date** | TODO(33 Grune 20xx)
**Affects** | Mbed TLS 3.6.3 to 3.6.6
**Not affected** | Mbed TLS 3.6.2 and earlier; Mbed TLS 4.0.0 and later
**Impact** | Remote code execution through heap corruption
**Severity** | HIGH
**Credits** | Haruki Oyama

## Vulnerability

Mbed TLS 3.6.3 added support for receiving fragmented handshake messages in TLS 1.2 and 1.3, for interoperability. This new feature required an extra field in the TLS context (`mbedtls_ssl_context`), called `in_hsfraglen` in Mbed TLS 4.0.0, containing the amount of data that is already received in an incomplete handshake message. In the 3.6 long-term support (LTS) branch, in order to preserve ABI compatibility, the existing field `badmac_seen` was renamed to `badmac_seen_or_in_hsfraglen`. In DTLS, this field tracks the number of records received with a bad MAC (or authentication tag, in AEAD cipher suites). In TLS, this field was previously unused, and is now used for handshake message parsing.

Due to an implementation mistake, the code sometimes reads the dual-purpose field without checking the active protocol. Specifically, at the beginning of `mbedtls_ssl_prepare_handshake_record()`, the field `ssl->in_hslen` is not updated when `ssl->badmac_seen_or_in_hsfraglen != 0`. Thus, after receiving a message with a bad MAC, the handshake message length is not updated, which causes problems in subsequent processing.

During the initial DTLS handshake, only the last message (Finished) is authenticated with a MAC or tag, and if the MAC is invalid, the handshake is rejected immediately. (Note that only DTLS 1.2 is supported, not DTLS 1.3.) Therefore `ssl->badmac_seen_or_in_hsfraglen` remains 0.

After exchanging application data, `ssl->badmac_seen_or_in_hsfraglen` may be nonzero if a bad-MAC limit has been set with `mbedtls_ssl_conf_dtls_badmac_limit()`. If the library sees a handshake message, it can only legitimately be a renegotiation attempt. If renegotiation is disabled (at compile time or run time), the attempt is correctly rejected.

However, if renegotiation is enabled, the library decrypts and parses the handshake message.
Due to the incorrect value of `ssl->in_hslen`, the normal message processing fails.

Furthermore, if the handshake message's sequence number indicates a prior missing record, then this message needs to be queued. This happens in the function `ssl_buffer_message()`, which allocates a heap buffer to store the message. The buffer size is `ssl->in_hslen`, which is still 0. On most platforms, `malloc(0)` reserves a unique heap location whose size is only a few bytes. The library then writes at least a reconstructed 12-byte header, followed by the message content, whose length is determined from the message content. This overflows a heap buffer, thus corrupts the heap.

## Impact

A man-in-the-middle in a DTLS connection where one endpoint has enabled renegotiation and has set a limit to the number of corrupted records can cause heap corruption by rearranging traffic or injecting specially crafted packets. Depending on the application and on the memory layout, this may allow remote code execution.

## Affected versions

Only versions of Mbed TLS from 3.6.3 to 3.6.6 are affected.

## Work-around

Applications are affected only if they declare a limit to the number of records with a bad MAC/tag with `mbedtls_ssl_conf_dtls_badmac_limit()`. By default, the bad MAC count is unlimited, which avoids the bug.

Applications are affected only if renegotiation is enabled. It is disabled by default.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version,
or to Mbed TLS 4.x (which has incompatible changes).

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The TF-PSA-Crypto and Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | -------------- | --------------------- |
| Basic fix | 24c2875cb0eb655fffe7b6a7a956f34bacb7b0a4 | N/A | N/A |
| With tests and documentation |  915442dbedffa7c856b92a021e9ac40176514f20..794e1a89db1fdf101ce39134647d08b0bd936e3f | N/A | N/A |
