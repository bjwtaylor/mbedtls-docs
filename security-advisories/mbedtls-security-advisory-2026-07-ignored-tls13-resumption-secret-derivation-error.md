# Ignored TLS 1.3 resumption secret derivation error (CVE-2026-50640)

**Title** | Ignored TLS 1.3 resumption secret derivation error
--------- | ----------------------------------------------------------
**CVE** | CVE-2026-50640
**Date** | TODO(publication date)
**Affects** | Mbed TLS 3.3.0 through 3.6.6; Mbed TLS 4.0.0-beta through 4.1.0
**Not affected** | Mbed TLS before 3.3.0; Mbed TLS 3.6.7 and later 3.6.x; Mbed TLS 4.1.1 and later 4.1.x; Mbed TLS 4.2.0 and later.
**Impact** | A TLS 1.3 server could issue invalid tickets, leading to extra resource usage, or to rejecting connections in rare configurations.
**Severity** | LOW
**Credits** | jjfz123 (https://github.com/jjfz123, https://www.linkedin.com/in/jjfdzcastro1/)

## Vulnerability

An error-handling bug was found in the TLS 1.3 server handshake code. Mbed TLS
logged a failure from a cryptographic computation but did not return the error to
the caller. The handshake therefore continued after an operation that should have
been treated as fatal.

In TLS 1.3 servers, `ssl_tls13_process_client_finished()` computed the
resumption master secret after verifying the client's Finished message. If
`mbedtls_ssl_tls13_compute_resumption_master_secret()` failed, for example
because of memory allocation failure or another cryptographic operation failure,
the error was logged but not returned. The handshake could complete and the
server could subsequently generate `NewSessionTicket` messages from invalid
resumption-secret material.

This issue affects TLS code in Mbed TLS. It does not affect TF-PSA-Crypto.

## Impact

A server that encounters a resumption master secret computation failure can issue
invalid TLS 1.3 session tickets instead of failing the handshake. Clients that
later present such tickets will fail session resumption. In the common case where
the deployment also permits non-resumed handshakes, this causes fallback to a
full handshake and is primarily a limited denial-of-service amplifier: during
resource pressure, invalid tickets can increase the number of expensive full
handshakes and make recovery harder.

Deployments that rely exclusively on TLS 1.3 ticket-derived PSKs, without an
external PSK or another enabled handshake mode, may see clients fail to reconnect
after receiving invalid tickets. Such deployments are considered unusually
restrictive because TLS 1.3 tickets are short-lived and session resumption is an
optimization rather than a sole provisioning mechanism.

## Affected versions

Mbed TLS 3.3.0 through 3.6.6 are affected. Mbed TLS 3.6.7 contains the fix.

Mbed TLS 4.0.0-beta through 4.1.0 are affected. Mbed TLS 4.1.1 contains the
fix.

This issue affects builds that include TLS 1.3 server support and issue TLS 1.3
session tickets.

## Work-around

Servers can avoid issuing affected TLS 1.3 session tickets by disabling TLS 1.3
session ticket generation until an upgrade is available, for example by calling
`mbedtls_ssl_conf_new_session_tickets()` with `num_tickets` set to 0.
Applications should also avoid deployments where clients can only reconnect with
ticket-derived PSKs and have no provisioned external PSK or other fallback
handshake mode.

Applications are not affected if they do not build or enable TLS 1.3 server
support, or if they do not issue session tickets.

## Resolution

Affected users should upgrade to Mbed TLS 3.6.7 or a later 3.6.x version, or
to Mbed TLS 4.1.1 or a later 4.1.x version, or to Mbed TLS 4.2.0
or a later version.

## Fix commits

We recommend that users upgrade to a release including the fix. However, if you are maintaining a branch with backported bug fixes, here are the most relevant commits. Please note that these commits may not apply cleanly to older versions of the library, and may not provide a complete fix even if they do apply. The Mbed TLS development team does not provide support outside of maintained branches.

| Branch | Mbed TLS 3.6.x | TF-PSA-Crypto 1.1.x | TF-PSA-Crypto 1.x (x&gt;1) | Mbed TLS 4.1.x | Mbed TLS 4.x (x&gt;1) |
| ------ | -------------- | ------------------- | -------------------------- | -------------- | --------------------- |
| Basic fix | f595df4569c1a1650ad9d077e2f2e819e9f1dddb | N/A | N/A | 4e26c248ec9541b95d3e3e0178960f53d8bb40b8 | 9063aca165efaa68c08f95159c4e84e0f17464a9 |
| With tests and documentation | f595df4569c1a1650ad9d077e2f2e819e9f1dddb^..27065ceb643a4266888ba1f200e4f20845e801cf | N/A | N/A | 4e26c248ec9541b95d3e3e0178960f53d8bb40b8^..7cbd8582ee9942ffce5dc907dc36addcdc2185eb | 9063aca165efaa68c08f95159c4e84e0f17464a9^..c438b0b9a92d81fd7ec8aa9148d0272299815155 |
