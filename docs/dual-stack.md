# IPv4 / IPv6 双栈

代理的三段地址族相互独立：本机应用到 SOCKS、Mac 到 QUIC 服务端、服务端到目标。IPv4 QUIC 隧道可以承载 IPv6 目标流量，IPv6 隧道也可以承载 IPv4 目标流量；实际出站仍需要服务端具备对应地址族的路由与权限。

## 监听

服务端 CLI 与 JSON/YAML 的默认监听已从 `0.0.0.0:8443` 调整为 `[::]:8443`：

```yaml
listen: "[::]:38443"
password: replace-with-a-long-random-password
cert: server.pem
key: server.key
```

IPv6 wildcard 使用 socket2 显式设置 `IPV6_V6ONLY=false`，同一 UDP 端口接受 IPv4/IPv6，不依赖操作系统默认值。如果主机禁用 IPv6 或不支持此双栈 socket，启动报错；需要仅 IPv4 时显式设置 `0.0.0.0:38443`。绑定具体 IPv6 地址只服务该地址，不意味着也绑定所有 IPv4 地址。

本地 SOCKS 仍默认只监听 `127.0.0.1`，也可通过 CLI 配置 `[::1]:1080`；一个 SOCKS 实例仍只绑定配置中的一个地址。GUI 使用随机 IPv4 回环端口，这不影响其承载 IPv6 目标。没有扩大本地未认证代理的监听范围。

IPv4 和 IPv6 的公网防火墙、安全组规则相互独立，双栈监听不会自动开放两套规则。

## 地址选择与回退

服务器配置既接受域名，也接受 `[IPv6地址]:端口`。证书必须包含正确的 DNS SAN 或 IP SAN，连接 IP 而证书使用域名时继续配置 `server_name`，不会跳过证书验证。

- 保留 DNS 返回的候选，去重并交错 IPv4/IPv6，遵循首个结果的地址族偏好，每族最多 8 个。
- QUIC 客户端为两族分别准备出站 endpoint，按照 250 ms 间隔启动候选 TLS 握手；所有当前尝试已明确失败时立即启动下一候选。
- TLS 握手成功后只在获胜连接上发送一次代理操作，取消其他尝试，避免重复连接目标；密码和业务操作失败不会触发认证降级。
- 目标 TCP 也使用相同的候选竞速策略，DNS 与连接在同一个目标连接期限内。
- 显式指定出口网卡时，两族都遵循同一网卡选择，不会为了成功连接改走其他网卡。
- IPv4-mapped IPv6 地址归一为 IPv4，避免选错 UDP socket 或将响应源与授权目标匹配失败。

这是基于系统解析结果的交错连接竞速，没有独立并发查询 A/AAAA、地址历史排序、DNS 缓存或完整 RFC 8305 实现。服务器域名在客户端配置构建时解析，新的会话可在该候选集合内重新选择；尚无运行中的 DNS 刷新或已建立会话的跨地址迁移。所有候选仍受原有连接期限限制。

## UDP

每个出站 association 分别绑定 IPv4 和 IPv6 socket，同时接收两族响应；主机只有一种可用地址族时仍可使用该族。IPv6 出站 socket 显式设置 IPv6-only，避免混入 IPv4-mapped 响应。

域名 UDP 目标保留多地址；本族 socket 不可用或本地 `send_to` 明确失败时尝试下一个地址，成功发送后只授权实际目标的响应来源，继续执行原有目标上限和源地址限制。

UDP 没有远端确认：本地发送成功之后，如果网络静默丢包，不能据此自动判断应该改发另一地址，也不会对两个目标同时发送或在响应超时后自行重发业务数据。因此 UDP 不承诺与 TCP 相同的路径黑洞回退能力。

## 验证与环境边界

自动化验证包含：

- 同一个双栈 QUIC 端口同时接受 IPv4、IPv6 客户端，并发转发两族 TCP/UDP。
- 两族 SOCKS 回环入口的直接转发与隧道转发，同一个 UDP association 混合访问两族目标。
- 首选 QUIC 路径静默不响应时，在两个方向回退到另一地址族。
- 竞速失败／超时时取消尝试，竞速不会重复建立业务目标 TCP 连接。
- TCP 候选回退、UDP 缺少地址族或本地发送失败时的回退。
- IPv6 字面地址、IPv6 IP SAN 证书及域名候选配置。

验证不假定 `localhost` 必须有 AAAA；回退测试显式注入确定的候选，DNS 集成测试遵循各机器实际的 hosts / DNS。测试服务器 的 hosts 目前仅把 localhost 映射到 IPv4，不能靠该名称凭空得到 IPv6 候选。

当前 Mac 的物理 en1 没有公网 IPv6，且没有 IPv6 默认路由。因此即使本机和 Ubuntu 回环双栈测试通过，也不能据此声称已经完成 Mac → 测试服务器 的公网 IPv6 隧道实测。IPv4 隧道承载 IPv6 目标与公网 IPv6 承载隧道是不同的验证项。

增强模式及全局 IPv6 路由接管仍未实现，系统代理的覆盖范围见 [macOS 客户端说明](macos-client.md)。

2026-11-10 双栈初始实现验证（后续 DNS 新增测试见 [DNS 说明](dns.md)）：

| 检查 | 结果 |
| --- | --- |
| macOS Rust 测试 | 62 项通过 |
| 测试服务器 Ubuntu Rust 测试 | 61 项通过，少一项 macOS 专属网卡测试 |
| Swift 控制层测试 | 14 项通过，含随包真实 Rust 核心联调 |
| Rust fmt / Clippy | 通过，Clippy 警告视为错误 |
| 原生 release app 与签名结构 | 已更新并通过 |
| Mac 经 en1 的 IPv4 QUIC 隧道，混合访问 测试服务器 IPv4/IPv6 回环目标 | 并发通过，每族各 128 KiB TCP、半关闭及 5 个 UDP 往返 |
| Mac → 测试服务器 公网 IPv6 QUIC | 未测，本机没有 IPv6 出口 |

跨机测试使用临时本地凭据与临时远端服务，完成后均已清理；未调整 Surge、系统代理、路由、hosts 或公网防火墙。

远端 IPv6 回环目标可通过以下命令提供，探针的 SOCKS 端仍可使用 IPv4：

```sh
# 测试服务器 上启动 IPv6 回环 echo，记录输出端口。
python3 scripts/network-smoke.py --serve --target-host ::1

# Mac 上通过正在运行的客户端访问上述 IPv6 目标。
python3 scripts/network-smoke.py --socks 127.0.0.1:1080 --target-host ::1 --tcp-port TCP端口 --udp-port UDP端口
```
