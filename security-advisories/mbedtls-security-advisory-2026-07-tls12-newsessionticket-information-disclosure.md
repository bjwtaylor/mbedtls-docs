# Information disclosure in TLS 1.2 NewSessionTicket (CVE-2026-50586)

**Title** | Information disclosure in TLS 1.2 NewSessionTicket
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50586
**Date** | 7th of July, 2026
**Affects** | Mbed TLS 2.0.0 through 2.28.10; Mbed TLS 3.0.0 through 3.6.6; Mbed TLS 4.0.0 through 4.1.0
**Not affected** | Mbed TLS 1.3.22 and earlier; Mbed TLS 3.6.7 and later 3.6 versions; Mbed TLS 4.1.1 and later 4.1 versions; Mbed TLS 4.2.0 and later 4.x versions
**Impact** | A TLS 1.2 server can disclose 4 bytes of stack memory to a peer in a NewSessionTicket message when ticket generation fails.
**Severity** | LOW
**Credits** | James Love

## Vulnerability

Mbed TLS TLS 1.2 servers can send a NewSessionTicket message after the server session-ticket write callback fails. In `ssl_write_new_session_ticket()` in `library/ssl_tls12_server.c`, the callback configured through `mbedtls_ssl_conf_session_tickets_cb()` is responsible for writing the session ticket and returning both the ticket length and the ticket lifetime hint.

Before the fix, the local `lifetime` variable was not initialized before calling the callback. If the callback returned an error without writing `lifetime`, the function still serialized `lifetime` into the `ticket_lifetime_hint` field of the NewSessionTicket handshake message. This caused 4 bytes of uninitialized server stack memory to be sent to the TLS 1.2 peer.

Applications are only affected when they run a TLS 1.2 server with session tickets enabled and the configured ticket-write callback can fail on a path that leaves the lifetime output parameter unset. The built-in behavior intentionally continues the handshake with an empty ticket when ticket generation fails, so the failure path must still produce a well-defined zero lifetime and zero-length ticket.

## Impact

A remote peer that can trigger or observe a ticket-write failure can receive 4 bytes of stack memory from the server process in the `ticket_lifetime_hint` field. The practical impact is limited because exploiting this for sensitive data would require useful data to remain on the stack in the leaked location and require the attacker to arrange a failing ticket-write path.

## Affected versions

Mbed TLS 2.0.0 through 2.28.10, Mbed TLS 3.0.0 through 3.6.6, and Mbed TLS 4.0.0 through 4.1.0 are affected when TLS 1.2 session tickets are enabled and ticket generation can fail as described above.

Mbed TLS 1.3.22 and earlier are not affected. Although those releases contain TLS 1.2 NewSessionTicket code, they do not contain the callback path with an uninitialized `lifetime` variable.

## Work-around

Applications can avoid the issue by disabling TLS 1.2 session tickets, disabling TLS 1.2 server support, or ensuring that their ticket-write callback always initializes both output parameters before returning, including on failure paths.

Applications are not vulnerable if they do not use TLS 1.2 server-side session tickets, if their ticket-write callback cannot fail, or if the callback always sets the ticket length and lifetime outputs to defined values before returning an error.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version, Mbed TLS 4.1.1 or a later 4.1.x version, Mbed TLS 4.2.0, or a later maintained release containing the fix. The fix initializes the ticket length and lifetime variables to zero before calling the ticket-write callback, so the failure path sends an empty ticket with a zero lifetime instead of serializing uninitialized stack data.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | 99ccd257e2d6c5fc53bc970e3e533a90c363f8e1 548ed19f707565db5fb4c2487edd7ae1bea50199 | N/A | N/A | 56e314728bd5c3fcb41a646972c2159403d733ac  dd5a8501c0e58acfff9ec551cb1b15b69a24591f | a5c2e02198433b4808c500bd8f5e77bd07d82bf1 38185e2308d201d7dfd05aa0032636440bdd1bfa |
| With tests and documentation | 02451dcc658d397381b16a574c2c68d441e92b33^..6bf3204e64f720a54b8d22a76dde9ec609154ce8 | N/A | N/A | 75cfc5c0b9cbd6b820fd45642d9c37aaf6beb7a5^..f2a1306c867f6c3be7d7e04af39772afbd46b57a | f5675fd06442dbf9d11dfdd78a5d99657de8b12f^..273c9b38b78da06244bd685dd7073e599f10eb9e |
