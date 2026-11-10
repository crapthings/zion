# IPv4 and IPv6

The local SOCKS listener, QUIC or TCP/TLS carrier, and destination each choose their address family independently. An IPv4 tunnel can carry IPv6 destinations, and vice versa. The server still needs a working route for each destination family.

## Listeners

The server defaults to `[::]:8443` with `IPV6_V6ONLY=false`, accepting both families on one UDP port. If IPv6 or dual-stack binding is unavailable, startup fails. For an IPv4-only host, set:

```yaml
listen: "0.0.0.0:8443"
```

Binding a specific IPv6 address does not also bind IPv4. Network firewall rules for each family remain separate.

The SOCKS listener binds one loopback address, defaulting to `127.0.0.1:1080`; `[::1]:1080` is also supported. The macOS app uses a random IPv4 loopback port and can still forward IPv6 destinations.

## Address selection

DNS candidates are deduplicated and interleaved by family, with up to eight addresses per family. QUIC handshakes, TCP/TLS handshakes, and destination TCP connections start alternatives at 250 ms intervals, or sooner when all current attempts fail.

Only the winning verified carrier connection receives the operation. Losing attempts are cancelled; authentication failure does not trigger a weaker mode. An explicit outbound interface applies to both families. IPv4-mapped IPv6 addresses are normalized to IPv4.

The client resolves the server name when building its configuration. Running clients do not refresh that candidate set or migrate established sessions. This is staggered connection racing, not a complete RFC 8305 implementation. Server-side destination resolution can use the separate [custom DNS policy](dns.md).

## UDP

Each outbound association uses separate IPv4 and IPv6 sockets where available. If a family is unavailable or a local send fails, another address can be tried. Only destinations actually sent to may return responses.

A successful local send gives no delivery confirmation. Silent packet loss does not trigger an alternate-address retry or duplicate transmission.

## Coverage

Loopback tests cover both carrier address families, mixed-family TCP/UDP destinations, address racing, cancellation, and unavailable-family fallback. These tests do not establish public IPv6 reachability on a deployment network.

System-wide route capture remains unfinished; see [backends](backends.md).
