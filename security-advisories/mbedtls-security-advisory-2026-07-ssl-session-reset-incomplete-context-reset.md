# Incomplete context reset in mbedtls_ssl_session_reset() (CVE-2026-50585)

**Title** | Incomplete context reset in mbedtls_ssl_session_reset()
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50585
**Date** | 7th of July, 2026
**Affects** | <ul><li>`badmac_seen`: Mbed TLS releases up to 3.6.2, Mbed TLS 4.0.0 and 4.1.0.</li><li>`dtls_srtp_info`: Mbed TLS from 2.25.0 up to 3.6.6, Mbed TLS 4.0.0 and 4.1.0</li></ul>
**Not affected** | <ul><li>`badmac_seen`: Mbed TLS 3.6.3 and later 3.6.x releases, Mbed TLS 4.1.1 and later 4.1.x releases, Mbed TLS 4.2.0 and later 4.2.x releases.</li><li>`dtls_srtp_info`: Mbed TLS 3.6.7 and later 3.6.x releases, Mbed TLS 4.1.1 and later 4.1.x releases, Mbed TLS 4.2.0 and later 4.x releases</li></ul>
**Impact** | Applications reusing an SSL context may experience premature DTLS connection failure or incorrect DTLS-SRTP parameter inheritance
**Severity** | MEDIUM
**Credits** | jjfz123 / https://github.com/jjfz123 / https://www.linkedin.com/in/jjfdzcastro1/

## Vulnerability

`mbedtls_ssl_session_reset()` is intended to reset an `mbedtls_ssl_context` for reuse across multiple connections. However, two fields of `mbedtls_ssl_context` were not zeroed by this function:

- `badmac_seen`: a DTLS-specific counter tracking the number of records received with a failing MAC. If `badmac_limit` is configured via `mbedtls_ssl_conf_bad_mac_limit()`, the counter from the previous connection carries over to the next one.
- `dtls_srtp_info`: holds the SRTP protection profile and MKI value negotiated during a DTLS-SRTP handshake. The structure is not cleared on session reset, so once the server received the SRTP extension it will always send it to the following sessions. It will share also `srtp_mki` from the last SRTP session.

An application is vulnerable if it calls `mbedtls_ssl_session_reset()` to reuse an `mbedtls_ssl_context` for a subsequent connection.

## Impact

**`badmac_seen` DoS:** once a server has reached `badmac_limit`, it will no longer tolerate any bad MAC even in new connections.

**`dtls_srtp_info` DoS:** once a client has used SRTP, the server will indeed always send the SRTP extension.

**`dtls_srtp_info` information leak:** the server sends the `srtp_mki` value from the previous client that sent it. This value is a key identifier. This is a minor loss of privacy, not leakage of confidential material.

## Affected versions

`badmac_seen`: Mbed TLS releases up to 3.6.2, Mbed TLS 4.0.0 and 4.1.0.

`dtls_srtp_info`: Mbed TLS from 2.25.0 up to 3.6.6, Mbed TLS 4.0.0 and 4.1.0

## Work-around

Applications can avoid this vulnerability by not reusing SSL contexts across connections. Instead of calling `mbedtls_ssl_session_reset()`, call `mbedtls_ssl_free()` followed by `mbedtls_ssl_init()`, `mbedtls_ssl_setup()` and all the optional configuration functions (ex: `mbedtls_ssl_set_bio()`) to obtain a fresh context for each connection.

Applications that do not call `mbedtls_ssl_conf_bad_mac_limit()` with a non-zero value are not affected by the `badmac_seen` issue.

Applications that have `MBEDTLS_SSL_DTLS_SRTP` disabled (which it is by default) or that do not call `mbedtls_ssl_conf_dtls_srtp_protection_profiles()` are not affected by the `dtls_srtp_info` issue.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or later Mbed TLS 3.6.x versions, Mbed TLS 4.1.1 and later Mbed TLS 4.1.x versions, Mbed TLS 4.2.0 or later Mbed TLS 4.x versions.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | -------------- | --------------------- |
| Basic fix | 2c33afacd5f65a609534839bdeb6c11f5204328b | 4b086ed04e12a0d621cee6dfbc30ee6f2e74d0bf | a2338a21fa8c6c1c80284f80c032208168cdb183 |
| With tests and documentation | 2c33afacd5f65a609534839bdeb6c11f5204328b^..e093798e77337929d81c7e37712bf00b7fc59daf | be883e19f50d9cb66d881598bb02102eabf3a957^..3b84f44c7fb2e987ad3a878e5d8abfaf549408be | 3e191be15a7b5a51b1a9d76b48dc88f77929851c^..4f92a63e4a2e07a62ae0da604d0269e25450345f |
