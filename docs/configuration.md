# JSON / YAML 配置

客户端与服务端使用同一套字段语义，支持 `.json`、`.yaml`、`.yml`。不需要用户名，不需要声明认证类型，其他网络参数使用默认值。原有证书命令行参数继续兼容；文件配置与命令行连接参数不能混用。

## 启动

```sh
zion client -c client.yaml
zion server -c server.yaml
```

将扩展名换成 `.json` 即可使用 JSON 配置。

## 密码认证

客户端最少两个字段：

```yaml
server: proxy.example.com:8443
password: replace-with-a-long-random-password
```

对应 JSON：

```json
{
  "server": "proxy.example.com:8443",
  "password": "replace-with-a-long-random-password"
}
```

这两个字段适用于服务端证书由内置 Mozilla 根证书信任的 CA 签发的情况。使用本项目生成的私有 CA 时，加一行：

```yaml
ca: ca.pem
```

服务端仍必须提供用于 TLS 加密和服务端身份验证的证书与私钥：

```yaml
password: replace-with-a-long-random-password
cert: server.pem
key: server.key
```

双方密码需一致；密码模式不要求客户端证书。密码通过 Ring HMAC-SHA256 生成认证证明，证明绑定当前 TLS 连接和命令，原始密码不会作为隧道字段发送，不能跨连接重放。TLS 1.3 验证和禁用 0-RTT 的策略保持生效。

## 客户端证书认证

客户端：

```yaml
server: proxy.example.com:8443
ca: ca.pem
cert: client.pem
key: client.key
```

服务端：

```yaml
ca: ca.pem
cert: server.pem
key: server.key
```

这里客户端的 `ca` 用于校验服务端，服务端的 `ca` 用于校验客户端。若服务端证书已经由内置公共 CA 信任，客户端可以省略 `ca`，但仍须提供自己的 `cert` 与 `key`。

若服务端同时配置 `password` 和 `ca`，则两种认证都必须通过；客户端也需要同时配置密码和证书对。不会在一个认证失败时自动降级到另一个。

## 可选字段与默认值

| 字段 | 客户端 | 服务端 |
| --- | --- | --- |
| `listen` | 默认 `127.0.0.1:1080`，只允许 loopback | 默认 `[::]:8443`，同时接受 IPv4/IPv6 |
| `ca` | 服务端信任根；省略时使用内置公共 CA | 客户端信任根；配置后强制客户端证书认证 |
| `server_name` | 默认从 `server` 的主机名或 IP 推导 | 不使用 |
| `interface` | 可指定 `en1`、`eth0` 等实际出口网卡 | 不使用 |
| `dns` | 不使用 | 可选 IP / IP:端口列表；省略时使用系统解析 |

`server` 使用 `主机名:端口` 或 `IP:端口`，IPv6 地址需使用 `[地址]:端口`。连接 IP 而证书签发给域名时，配置对应的 `server_name`：

```yaml
server: 203.0.113.10:8443
server_name: passage.example.com
password: replace-with-a-long-random-password
ca: ca.pem
interface: en1
```

如果证书包含连接 IP 对应的 IP SAN，则不需要额外的 `server_name`。`interface` 可显式指定本进程的出口网卡，不修改系统路由；网卡名称取决于机器。

证书路径相对配置文件所在目录解析，不受进程启动目录影响。未知字段、缺少认证、只配置 `cert` 或 `key`、空密码及超过 64 KiB 的配置文件均会拒绝。密码只能是字符串；包含特殊字符时可使用引号。

Unix 上应将包含密码的配置文件及私钥权限设为 `0600`。配置解析错误和 Debug 输出不回显密码内容。

## 私有 CA 初始化

```sh
zion credentials --server-name proxy.example.com --output credentials
```

将 `credentials/ca.pem` 复制到客户端配置目录；服务端获得 `server.pem` 与 `server.key`。证书认证模式下客户端还需 `client.pem` 与 `client.key`。示例配置在 [examples](../examples/) 中；示例中的密码和主机地址需要替换。

本命令不保存 CA 签名私钥，尚不提供后续签发、自动续期或证书吊销功能。

## IPv4 / IPv6

服务端默认使用显式双栈监听；仅 IPv4 主机可配置 `listen: "0.0.0.0:8443"`。客户端域名保留两族候选，QUIC/TCP 支持交错连接竞速，UDP 仅在本地发送失败或地址族不可用时回退。具体规则、测试及公网验证边界见 [双栈说明](dual-stack.md)。

## 服务端 DNS

可通过 `dns: ["1.1.1.1", "8.8.8.8"]` 指定独立上游，服务端 TCP/UDP 共享索引缓存与并发查询合并，不修改系统 DNS。空列表会报错，失败不会回退系统；目前支持普通 UDP/TCP DNS，详见 [DNS 配置与缓存机制](dns.md) 和 [示例](../examples/server-dns.yaml)。
