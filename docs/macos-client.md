# macOS 原生客户端

首版采用 SwiftUI + AppKit 界面，通过独立进程集成现有 Rust 核心，最低支持 macOS 14；当前构建脚本面向本机架构。概览、服务器、活动、设置和菜单栏入口共享同一个连接状态。新增辅助功能可以增加独立页面。

## 构建

本机需要 Rust 和支持 Swift 6 的 Xcode 工具链：

```sh
cargo test --locked
swift test --package-path macos
python3 scripts/build-macos.py
```

产物为仓库内的 `target/macos/Zion.app`，包括原生可执行文件和 `Contents/Helpers/zion-core`。脚本使用 ad hoc 签名，无需 Team ID；这是本机构建方式，不包含 Developer ID、公证或 NetworkExtension entitlement，也不是已完成的分发流程。构建和测试不会启动 GUI。

只编译界面可执行：

```sh
swift build --package-path macos
```

开发时核心默认查找仓库的 `target/debug/zion`，也可用 `ZION_CORE_PATH` 指定；完整 app 优先使用其随包核心，显式环境变量仍可覆盖。

## 首次配置

添加服务器时只需填写名称、服务器地址和密码，不需要用户名。也可选择客户端证书认证；密码模式下的高级选项支持附加客户端证书，适用于两种认证同时要求的服务器。

- 私有 CA：选择服务端 CA 文件；公共 CA 默认使用核心的信任根。
- 证书名称：默认取服务器地址中的主机名，连接 IP 而证书使用域名时可覆盖。
- 出口网卡：默认不绑定；本机运行其他代理时可以按实际情况指定物理网卡，例如此前测试的 `en1`，不保证所有 Mac 的物理网卡名称相同。
- JSON 导入：读取现有 CLI 客户端字段，证书相对路径以导入文件目录解析，再进入编辑器保存。GUI 首版只导入 JSON；Rust CLI 继续支持 JSON/YAML。

服务器元数据保存在 `~/Library/Application Support/Zion/profiles.json`，密码保存在 macOS Keychain，私钥仍位于用户选择的文件中。新密码不写入元数据、命令行参数或活动日志。导入的原始配置文件不会被自动删除或脱敏。

## 核心控制协议

应用启动核心时使用：

```sh
zion-core client --config - --events-json
```

stdin 接收最多 64 KiB 的 JSON，随后关闭输入管道；凭据路径使用绝对路径。普通 CLI 的配置文件行为保持兼容，`-c -` 也可直接读取 stdin JSON，stdin 配置中的相对路径以当前工作目录解析。

stdout 只传输逐行 JSON 生命周期事件，诊断日志写入 stderr：

```json
{"event":"ready","listen":"127.0.0.1:49152"}
{"event":"stopped"}
```

启动错误发送 `{"event":"error","message":"..."}` 并返回非零状态。核心先绑定随机回环端口，再通过真实 QUIC 会话确认服务端证书及客户端认证，随后报告 ready；仅有进程存活不会显示“已连接”。该探测不是持续健康检查，也不代表后续每个目标都可访问。

控制器只接受回环 ready 地址，限制输出缓冲和启动时间，隔离前次进程的迟到回调。活动页保留最近 500 条实际日志；没有模拟流量、延迟或在线统计。

## 系统代理

用户点击连接后，应用等待核心 ready，再通过 SystemConfiguration 设置当前网络位置中启用的网络服务；实际写入时才请求 macOS 网络配置授权。

设置内容为本地 SOCKS5，暂时关闭这些服务上的 HTTP、HTTPS、PAC 和自动发现开关，移除原 SOCKS 用户名与密码，并保留原有例外规则和配置值。断开时恢复原快照，恢复失败时保留核心并提示重试；启用部分成功但回滚失败时也保留核心，进入“需要恢复网络”状态，禁止直接开始新连接；正常退出也先恢复设置。原 HTTP 等代理地址只是临时停用，正常恢复会一并还原。

恢复记录 `proxy-recovery.plist` 在写系统设置之前落盘，权限为 0600，可能包含原系统代理的认证字段，应按敏感本地文件保护。恢复时仅修改仍与 Zion 应用状态完全相符的服务；其他应用已经改过的配置不会被覆盖。上次异常退出留下的记录可在下一次启动后恢复。

当前实现处理连接时的网络服务快照，尚不持续监听新增服务、网络位置切换或其他代理软件的竞争修改。应用自身被强制结束时不能保证立即恢复系统设置，子进程也可能继续存在；恢复记录用于下次启动后处理，尚无独立守护进程提供崩溃清理。

**系统 SOCKS 代理只影响遵循该设置的应用，不等于全流量接管。** 忽略系统 SOCKS 配置的程序、部分 UDP 和自行联网的应用可能绕过代理。当前模式不是 kill switch。

## 增强模式的后续边界

界面现在可选择并保存 NetworkExtension 或辅助服务 TUN；两种系统端适配器仍未接入，连接按钮会明确禁用。公共包引擎和原生桥接已经加入，完成范围见 [后端说明](backends.md)。

后续需要 Apple Developer 签名和相应 entitlement，再实现 Packet Tunnel 扩展及宿主配置。扩展负责 IPv4/IPv6 路由、DNS、虚拟网卡生命周期；成熟的用户态网络栈负责 IP 包与 TCP/UDP 会话转换，复用 Rust 的出站隧道接口。协议、认证和 QUIC/TLS 继续留在 Rust，避免在 Swift 重新实现。

必须额外处理服务器出站绕过隧道、DNS 引导与泄漏、局域网策略、MTU、休眠唤醒、网络切换及扩展崩溃恢复；这些尚未实现或验证，不能用“全局代理已完成”描述当前版本。

## 验证范围

控制层自动化测试使用临时目录与假网络设置，常规进程测试使用假核心，不调用真实 Keychain 写入或系统代理写入；进程测试检查 stdin 配置、ready 解析、停止与重新连接。Rust 集成测试使用真实本机 QUIC 服务端验证 stdin 配置、认证成功/失败和退出事件，并覆盖原有 TCP/UDP 转发。

启用 `packet-tunnel` 后，当前 macOS 上 Rust 的 89 项测试、Swift 的 23 项测试、Clippy 和 Rust 格式检查均通过；Ubuntu 88 项通过。双栈与 DNS 验证分别见 [双栈说明](dual-stack.md) 和 [服务端 DNS](dns.md)。Swift 测试包含使用随包真实 Rust 核心及本机 QUIC 服务端的认证、进程控制和原生包引擎启动／停止／重启联调；未设置核心路径时真实核心测试会跳过，未链接静态库时不会测试原生包引擎。运行完整联调：

```sh
ZION_PACKET_LIBRARY="$PWD/target/release/libzion.a" \
ZION_INTEGRATION_CORE="$PWD/target/macos/Zion.app/Contents/Helpers/zion-core" \
swift test --package-path macos
```

原生界面已经通过 debug/release 编译，app 包执行代码签名结构校验。本轮按项目约定仅用源码、CLI 和自动化测试，没有启动 GUI、查看图片或改动用户当前系统代理。实际权限对话框、Keychain 授权体验、界面布局及系统代理接管效果仍需以后明确授权的交互验证。
