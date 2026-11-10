# macOS 接管后端

客户端界面现在提供三个互斥选项：

- 系统代理：使用已有的本地 SOCKS5 核心和系统代理设置控制器。
- NetworkExtension：目标为 Apple Packet Tunnel 系统扩展。
- 辅助服务 TUN：目标为用户授权的 helper 管理 utun。

选择保存在 `~/Library/Application Support/Zion/connection.json`，与服务器元数据、Keychain 密码分开。默认保留系统代理；未知枚举或损坏文件会报错，不静默替换为另一种后端。

## 当前完成范围

| 部分 | 状态 |
| --- | --- |
| 概览、设置、菜单栏中的后端选择和持久化 | 已实现 |
| 选择与实际运行后端分离、连接互斥、恢复失败保留所有者 | 已实现并以替身测试 |
| 原有系统代理的真实核心进程接入 | 保留并验证 |
| 后端无关的 IP 包 → TCP/UDP → QUIC 共享引擎 | 已实现并以真实回环服务测试 |
| Swift → Rust 的内存凭据及包收发 C ABI | 已链接并做启动／停止／重启联调 |
| NetworkExtension 系统扩展提供器、部署和激活 | 尚未实现 |
| 特权 helper 的安装、XPC 服务及 utun／路由／DNS 管理 | 尚未实现 |
| 两种增强模式的真机网络接管 | 尚不可用 |

因此当前 app 可以选择并保存增强后端，但连接按钮会禁用，并说明系统组件尚未接入。已链接数据引擎不代表已创建虚拟网卡，也不代表已经安装或授权任何系统服务。当前机器没有可用的代码签名身份，后续系统扩展真机验证还需要完成签名条件。

## 公共数据层

Rust 的 `packet-tunnel` feature 使用 `netstack-smoltcp 0.2.5` 转换 IP 包，以同一份 Zion QUIC 客户端转发 TCP 与 UDP。该依赖要求 Rust 1.91，因此项目最低 Rust 版本同步提升到 1.91。

后续平台接线目标为：

```text
NetworkExtension packetFlow ─┐
                            ├─ 完整 IP 包 → 公共 packet 引擎 → Zion QUIC → Ubuntu
helper 创建的 utun + FD 适配 ─┘
```

平台侧负责接口、路由、DNS 设置和生命周期；共享引擎不调用系统网络配置。两种接管方式不会各自复制认证、TLS、QUIC 或 TCP/IP 协议实现。

公共引擎先验证远端证书及认证，再向调用方报告 ready。所有包队列有界，TCP 与 UDP 共用会话预算；原始 IP 包由成熟库解析，IPv4/IPv6 TCP 半关闭与 UDP（含空数据报）已验证。当前不支持 ICMP 代理、IP 分片，也没有完整验证所有 IPv6 扩展头。超过虚拟 MTU 或 QUIC Datagram 容量的 UDP 不会自动分片。

## 原生边界

`NativePacketEngine` 使用静态链接的 Rust 引擎，不启动额外的本地 SOCKS 监听器。临时配置将 CA、证书和私钥的 PEM 内容放入内存信封；Rust 验证其与已选配置一致，再直接交给 Rustls，不要求系统扩展访问用户选中的文件路径。

配置和 PEM 不写入后端选择文件，也不通过生命周期事件返回。回调数据只在同步调用期间借用，Swift 立即复制；包回调采用直接交付，不为每个数据包创建无界的 MainActor 任务。

停止时先移除可发送句柄，再在后台等待 Rust 线程结束，最后释放回调上下文。迟到事件通过 generation 隔离；重复启动不会覆盖仍然存活的句柄。

C 头文件位于 `macos/Sources/CZionPacket/include/CZionPacket.h`。该接口中的 destroy 不可从 Rust 回调线程自身调用，平台适配器也必须在结束引擎后再释放其关联资源。

## 构建与检查

```sh
cargo test --locked --features packet-tunnel
cargo clippy --locked --all-targets --features packet-tunnel -- -D warnings
python3 scripts/build-macos.py
ZION_PACKET_LIBRARY="$PWD/target/release/libzion.a" \
ZION_INTEGRATION_CORE="$PWD/target/macos/Zion.app/Contents/Helpers/zion-core" \
swift test --package-path macos
```

构建脚本启用 packet feature、链接静态库并将 Rust 和 Swift 的 macOS 最低部署目标统一到 14.0。独立执行 `swift build` 时，只有显式传入 `ZION_PACKET_LIBRARY` 才会链接原生包引擎；后端选择界面在未链接时仍可编译。

测试不创建 utun，不修改路由、系统 DNS、系统代理或 Keychain，不启动 GUI，也不安装 helper／系统扩展。系统集成的后续工作仍包括：端点绕环保护、双栈路由与 DNS 策略、授权安装、调用方身份校验、网络切换、租约与异常恢复。

本轮验证通过 macOS Rust 89 项、Ubuntu Rust 88 项及 Swift 23 项测试，并通过 Clippy、Rust 格式检查和 macOS 应用打包；两台机器均测试了共享包引擎的 IPv4/IPv6 TCP 与 UDP，未执行系统网络接管。
