# Zion QUIC v1

Zion uses a private QUIC protocol with ALPN `zion/1` and request version `1`. Quinn supplies QUIC; Rustls supplies TLS 1.3. It is not HTTP/3 or MASQUE. Early data and 0-RTT are disabled.

## Authentication

Clients always verify the server certificate and name. Servers require a password proof, a trusted client certificate, or both, according to configuration. All authenticated clients have the same outbound permissions; there is no per-user policy or revocation interface.

The optional request field `auth` is a JSON array of 32 byte values. Certificate-only clients omit it. To calculate a password proof:

1. Serialize `(version, operation)` as a Serde JSON tuple.
2. Use those bytes as TLS exporter context with label `EXPORTER-zion-password-v1`, producing 32 bytes.
3. Sign the exported bytes with HMAC-SHA256, using the shared password as the key.

Ring verifies the proof before any destination connection or UDP association is opened. The password itself is not sent. Proofs are bound to the connection and operation. Authentication failure closes QUIC with application code `16`; certificate-only servers reject unexpected password proofs.

## Control stream

Each QUIC connection carries one TCP session or UDP association, using one bidirectional stream and no unidirectional streams. Control frames contain a two-byte big-endian length followed by UTF-8 JSON. Length must be 1–4096 bytes; unknown top-level fields are rejected.

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

After the response, the same stream carries raw bytes. EOF closes only that sending direction. Normal completion waits up to five seconds for send acknowledgement; explicit stop codes are errors.

The client closes QUIC after reading the response stream and forwarding it locally. The server waits for that close after draining its send stream. A transport ACK alone does not establish local application consumption.

## UDP

The bidirectional stream stays open as a lifecycle channel. Payloads use QUIC Datagrams containing the SOCKS5 UDP envelope: reserved bytes, fragment byte, address type, destination, port, and payload. Only `FRAG=0` is accepted.

Each connection has one association and needs no session ID. The server accepts responses only from addresses to which it successfully sent a request. Oversized or malformed packets are dropped. There is no application retransmission, fragmentation, or reassembly.

A closed control stream, closed QUIC connection, or application idle timeout releases the association. Fatal transport errors end it; individual DNS or socket-send failures drop the affected packet.

## Defaults

| Resource | Limit |
| --- | --- |
| Local sessions | 256 |
| Server handshakes and sessions combined | 256 |
| UDP destinations per association | 256 |
| QUIC Datagram receive / send buffers | 256 KiB each |
| QUIC keepalive / transport idle timeout | 15 s / 45 s |
| Application UDP idle timeout | 60 s |

Connections are not pooled across sessions. Tunnel failure does not fall back to direct access or a TCP transport.
