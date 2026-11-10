# Zion protocol v1

Zion uses request version `1` over UDP/QUIC (ALPN `zion/1`) or TCP/TLS (ALPN `zion-tls/1`). Quinn supplies QUIC; Rustls supplies TLS 1.3 for both carriers, with Tokio Rustls handling TCP. Early data and 0-RTT are disabled. These are private protocols, without HTTP/3, MASQUE, or HTTPS camouflage.

## Authentication

Clients always verify the server certificate and name. Servers require a password proof, a trusted client certificate, or both, according to configuration. All authenticated clients have the same outbound permissions; there is no per-user policy or revocation interface.

The optional request field `auth` is a JSON array of 32 byte values. Certificate-only clients omit it. To calculate a password proof:

1. Serialize `(version, operation)` as a Serde JSON tuple.
2. Use those bytes as TLS exporter context with label `EXPORTER-zion-password-v1`, producing 32 bytes.
3. Sign the exported bytes with HMAC-SHA256, using the shared password as the key.

Ring verifies the proof before any destination connection or UDP association is opened. The password itself is not sent. Proofs are bound to the connection and operation. Authentication failure closes QUIC with application code `16` or drops the TCP/TLS connection. Certificate-only servers reject unexpected password proofs.

## Control exchange

Each connection carries one TCP session or UDP association. QUIC uses one bidirectional stream and no unidirectional streams; TCP/TLS uses its byte stream. Control frames contain a two-byte big-endian length followed by UTF-8 JSON. Length must be 1–4096 bytes; unknown top-level fields are rejected.

Requests without password proofs:

```json
{"version":1,"operation":{"Tcp":{"host":"example.com","port":443}}}
{"version":1,"operation":"Udp"}
```

Response:

```json
{"status":0,"bound":"127.0.0.1:12345"}
```

`status` uses SOCKS5 reply codes. TCP success is returned only after connecting to the destination. The local SOCKS client receives success after the tunnel response arrives.

## TCP

After the response, the same stream carries raw bytes. EOF closes only that sending direction, using TLS close-notify on TCP/TLS. QUIC normal completion waits up to five seconds for send acknowledgement; explicit stop codes are errors.

For QUIC, the client closes the connection after reading the response stream and forwarding it locally. The server waits for that close after draining its send stream. A transport ACK alone does not establish local application consumption.

## UDP

QUIC keeps its bidirectional stream open as a lifecycle channel and carries payloads in QUIC Datagrams. Each packet contains the SOCKS5 UDP envelope: reserved bytes, fragment byte, address type, destination, port, and payload. Only `FRAG=0` is accepted.

Each connection has one association and needs no session ID. The server accepts responses only from addresses to which it successfully sent a request. Oversized or malformed packets are dropped. There is no application retransmission, fragmentation, or reassembly.

TCP/TLS sends the same envelope preceded by a four-byte big-endian length, capped at 65,535 bytes including the envelope. Empty envelopes and oversized lengths close the association. Empty UDP payloads remain valid. Each client direction has a four-packet queue; writer congestion drops new packets. Partial frames survive cancellation of a pending receive. TCP retransmission can delay later packets in the same association.

A closed transport, closed control stream, or application idle timeout releases the association. Fatal transport errors end it; individual DNS or socket-send failures drop the affected packet.

## Defaults

| Resource | Limit |
| --- | --- |
| Local sessions | 256 |
| Server handshakes and sessions combined, across both carriers | 256 |
| UDP destinations per association | 256 |
| QUIC Datagram receive / send buffers | 256 KiB each |
| QUIC keepalive / transport idle timeout | 15 s / 45 s |
| Application UDP idle timeout | 60 s |

Connections are not pooled across sessions. Tunnel failure does not switch carriers or fall back to direct access.
