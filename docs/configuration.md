# Configuration

Client and server files accept `.json`, `.yaml`, and `.yml`. No username or authentication-type field is needed.

```sh
zion client -c client.yaml
zion server -c server.yaml
```

## Transport

`transport: quic` (default) carries sessions over UDP. `transport: tls` uses TCP with TLS 1.3 and works without UDP connectivity to the server. Both can forward TCP and UDP destinations. The aliases `udp` and `tcp` select `quic` and `tls` respectively.

A server may use `transport: both` to listen on TCP and UDP at the same numeric port. Open both firewall protocols. Clients select one carrier; there is no automatic fallback. UDP over TCP retains packet boundaries but shares TCP retransmission delays.

The inline CLI also accepts `--transport quic|tls`, or `--transport both` for a server. File-based configuration uses the `transport` field instead.

## Authentication

For password authentication, use the same password on both sides:

```yaml
# client.yaml
server: passage.example.com:8443
password: replace-with-a-long-random-password
```

```yaml
# server.yaml
password: replace-with-a-long-random-password
cert: server.pem
key: server.key
```

The client always verifies the server certificate and name. It trusts built-in public roots by default; add `ca: ca.pem` for a private CA.

For client-certificate authentication:

```yaml
# client.yaml
server: passage.example.com:8443
ca: ca.pem
cert: client.pem
key: client.key
```

```yaml
# server.yaml
ca: ca.pem
cert: server.pem
key: server.key
```

On the client, `ca` trusts the server. On the server, `ca` requires trusted client certificates. A server with both `password` and `ca` requires both factors; the client must supply a password and certificate pair.

## Fields

| Field | Client | Server |
| --- | --- | --- |
| `transport` | `quic` or `tls`; defaults to `quic` | `quic`, `tls`, or `both`; defaults to `quic` |
| `server` | Required `host:port` or `[IPv6]:port` | — |
| `password` | Shared secret | Shared secret |
| `cert`, `key` | Optional client identity; supply together | Required TLS identity |
| `ca` | Server trust roots; defaults to public roots | Client trust roots; enables certificate authentication |
| `listen` | `127.0.0.1:1080`; loopback only | `[::]:8443`; dual stack |
| `server_name` | Certificate name; defaults to the server host or IP | — |
| `interface` | Bind carrier sockets to an outbound interface | — |
| `routing` | Ordered process rules and default policy; defaults to proxy | — |
| `dns` | — | Resolver IP list; defaults to system resolution |

To connect by IP while verifying a DNS name:

```yaml
server: 203.0.113.10:8443
server_name: passage.example.com
password: replace-with-a-long-random-password
```

`interface` selects a real device such as `en0` or `eth0`; it does not change system routes. An invalid or unavailable selection fails rather than choosing another interface.

Files are limited to 64 KiB and reject unknown fields. Passwords must be strings of 1–1024 bytes. Certificate paths are relative to the configuration file. `-c -` reads JSON from stdin, with paths relative to the working directory. File configuration cannot be mixed with command-line connection options.

Protect password files and private keys with mode `0600` on Unix.

## Private identities

```sh
zion credentials --server-name passage.example.com --output credentials
```

The output directory must not exist. The command creates a private CA and separate server/client identities. Give the server `server.pem` and `server.key`; give the client `ca.pem`. Certificate authentication also requires `ca.pem` on the server and `client.pem` / `client.key` on the client. Transfer files through a trusted channel.

The CA signing key is not saved. Issuance, renewal, and revocation after this initial generation are not implemented.

See [examples](../examples/), [DNS](dns.md), and [IPv4 and IPv6](#ipv4-and-ipv6).

## Process routing

Client configurations optionally select an ordered process-routing policy:

```yaml
routing:
  default_policy: proxy
  rules:
    - matcher: process_path
      value: /usr/bin/curl
      policy: direct
      enabled: true
    - matcher: process_name
      value: Example
      policy: reject
      enabled: true
```

Policies are `proxy`, `direct`, and `reject`. The first enabled exact, case-sensitive match wins; otherwise `default_policy` applies. Each rule requires `matcher`, `value`, `policy`, and `enabled`. Paths must be absolute. There may be at most 256 rules, each with a nonempty value of at most 4096 bytes; the complete configuration still has a 64 KiB limit.

Process attribution is best effort on macOS. Other platforms and unidentifiable connections use the default policy. UDP routing uses the owner of the SOCKS TCP association for all its datagrams. These rules only apply to the local SOCKS entry point, not the packet/TUN engine. Direct routing uses the client's local resolver and network rather than the tunnel's server-side DNS or outbound interface. No proxy failure implicitly selects direct access. Native process traffic and editing are documented in the [macOS client](macos-client.md#process-routing-and-traffic).

## IPv4 and IPv6

The SOCKS listener, tunnel carrier, and destination select address families independently. An IPv4 carrier can forward IPv6 destinations and vice versa, provided the server has a route. The server defaults to dual-stack `[::]:8443`; explicitly use `0.0.0.0:8443` on an IPv4-only host. Binding a specific IPv6 address does not also bind IPv4. The client listener must remain loopback; `[::1]:1080` is supported, while the app allocates an IPv4 loopback port.

Resolved addresses are deduplicated and interleaved, with up to eight per family. Verified carrier handshakes and outbound TCP connections race candidates at 250 ms intervals, advancing sooner when all active attempts fail. Losing attempts are cancelled; operations are sent only over the winning carrier. An explicit interface applies to both families.

Server-name resolution happens when building the client; running sessions do not refresh that candidate set. UDP uses separate family sockets and may try another address only after a local send failure. Successful sends do not trigger duplicate delivery attempts when a response is absent. These address-selection paths do not change the requested transport or routing policy.
