# Server DNS

Set `dns` in the server configuration to use explicit upstreams:

```yaml
password: replace-with-a-long-random-password
cert: server.pem
key: server.key
dns: ["1.1.1.1", "2606:4700:4700::1111"]
```

Omitting `dns`, or setting it to `null`, uses Tokio's system resolver. Custom resolution never falls back to the system resolver and does not change system DNS settings.

## Upstreams

Supply 1–8 IP addresses, optionally with ports: `127.0.0.1:5353` or `[::1]:5353`. Bare IPs use port 53. Empty lists, hostnames, URLs, unspecified or multicast addresses, and port zero are rejected.

Queries use ordinary UDP/TCP DNS. Truncated UDP responses can retry over TCP. DoH, DoT, and DoQ are not supported.

The last successful upstream is tried first; alternatives start after 50 ms, with at most two concurrent upstreams per record type. Transient failures do not cancel pending peers. NXDOMAIN or NODATA ends that record-type lookup. Ordering is not a strict priority policy.

Custom mode ignores the system hosts file and search domains. Names are lowercased and made absolute; Hickory retains its built-in special-use name handling. IP literals bypass DNS.

## Cache and concurrency

TCP and UDP sessions share one resolver policy per server instance. Hickory owns response caching; Zion coordinates pending work and transient failures.

| State | Key | Limit |
| --- | --- | --- |
| Responses | Query name, type, class; partitioned by upstream | Default 8192-entry budget divided across upstreams |
| Pending lookups | Normalized name | 128 distinct names |
| Transient failures | Query and upstream | 1024 entries, 500 ms backoff |

Lookups use hash indexes. A and AAAA are cached separately; destination ports are not part of the key. Positive TTLs are capped at one day, SOA-based negative TTLs at 60 seconds. Zero-TTL responses are not reused; CNAME chains follow the shortest applicable TTL. Entry limits are not byte limits.

Concurrent requests for the same name share A/AAAA work. Both record types run in parallel and are merged after both finish; either family's successful result can be used. Each type has a five-second deadline, and each upstream attempt has two seconds. Callers retain their own connection deadline. A caller leaving does not cancel shared work.

Caches are in memory and discarded when the policy is rebuilt. There is no stale-answer extension, disk cache, or live configuration reload.

## Scope

This setting resolves destination names received by the server. The client still uses its own system resolver to locate the Zion server. A destination already supplied as an IP is not resolved again.

It does not intercept device-wide DNS, application DoH, or port 53 traffic. The QUIC tunnel is encrypted; ordinary DNS between the server and its upstream is not.

Tests use local UDP/TCP responders for TTL expiry, negative caching, peer failures, concurrency, IPv6 upstreams, and resolver sharing across real QUIC sessions. Run `cargo test --locked --test dns`.
