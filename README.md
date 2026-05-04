# ipv6-pool-proxy

`ipv6-pool-proxy` 是一个基于 Rust/Tokio 的 IPv6 随机子网出站工具，支持两种模式：

- `proxy`：提供传统 SOCKS5 代理服务，客户端通过 SOCKS5 接入。
- `dns`：提供 DNS 劫持解析服务，并在本机 TCP 443 提供 SNI Proxy，将被劫持域名的 HTTPS 流量通过随机 IPv6 地址出站。

## 功能特性

- SOCKS5 CONNECT 代理（`proxy` 模式）。
- 可选 SOCKS5 用户名/密码认证（仅 `proxy` 模式有效）。
- 使用指定 IPv6 CIDR 前缀随机生成本地出站 IPv6 地址。
- `dns` 模式通过 UDP DNS 服务返回劫持 IP。
- `dns` 模式内置 TCP 443 SNI Proxy，根据 TLS ClientHello 中的 SNI 识别目标域名并转发。
- 支持 `domain.conf` 精确域名、后缀、关键词、TLD 规则。
- 支持 `-ipv4_pass_through true|false`：目标只有 IPv4 时是否回落到本机默认 IPv4 出站。

## 重要系统要求

### 必须开启 IPv6 non-local bind

本程序会从 IPv6 子网中随机选择地址作为本地出站地址进行绑定，因此 Linux 系统必须开启 `net.ipv6.ip_nonlocal_bind=1`，否则随机绑定未显式配置到网卡上的 IPv6 地址时会失败。

临时开启：

```bash
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
```

持久化开启，推荐写入独立配置文件：

```bash
echo 'net.ipv6.ip_nonlocal_bind=1' | sudo tee /etc/sysctl.d/99-ipv6-pool-proxy.conf
sudo sysctl --system
```

也可以写入 `/etc/sysctl.conf`：

```bash
echo 'net.ipv6.ip_nonlocal_bind=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

验证：

```bash
sysctl net.ipv6.ip_nonlocal_bind
```

期望输出包含：

```text
net.ipv6.ip_nonlocal_bind = 1
```

### 非隧道 IPv6 子网通常需要配置 NDP Proxy

如果你的 IPv6 子网不是通过隧道方式获得，而是机房/运营商将一个 IPv6 子网路由或邻居发现到你的服务器网卡上，那么仅开启 `ip_nonlocal_bind` 通常还不够。上游网络需要知道随机 IPv6 地址对应的二层邻居，否则回包无法到达本机。

这种情况下通常需要安装并正确配置 `ndppd`：

```bash
sudo apt update
sudo apt install -y ndppd
```

示例 `/etc/ndppd.conf`，请把 `eth0` 和 IPv6 前缀替换为你的实际网卡和子网：

```conf
proxy eth0 {
    rule 2001:db8:1234:5678::/64 {
        auto
    }
}
```

启动并设置开机自启：

```bash
sudo systemctl enable --now ndppd
sudo systemctl status ndppd
```

注意：

- 如果 IPv6 子网来自 Hurricane Electric、WireGuard、GRE、SIT 等隧道，通常由隧道接口负责路由，可能不需要 `ndppd`。
- 如果 IPv6 子网来自原生上游网络，是否需要 `ndppd` 取决于上游是静态路由子网，还是通过 NDP 发现地址。无法访问时应优先检查路由、NDP、网卡名和防火墙。
- `ndppd` 配置错误会导致随机 IPv6 地址出站请求能发出但无法收到回包。

## 编译

需要 Rust 工具链。

```bash
cargo build --release
```

编译后的二进制通常位于：

```text
target/release/ipv6-pool-proxy
```

## 命令行参数

```text
Usage: ipv6-pool-proxy -m proxy|dns -l 0.0.0.0:1080 -u user:pass -p 2001:470:19:226::/64 [-c domain.conf] [-ipv4_pass_through true|false]
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-m`, `--mode` | `proxy` | 运行模式，可选 `proxy` 或 `dns`。 |
| `-l`, `--listen` | `0.0.0.0:1080` | `proxy` 模式为 SOCKS5 TCP 监听地址；`dns` 模式为 UDP DNS 监听地址。 |
| `-u`, `--user` | 无 | SOCKS5 用户名密码认证，格式为 `user:pass`。在 `dns` 模式下会被忽略。 |
| `-p`, `--prefix` | 必填 | 出站随机 IPv6 CIDR，例如 `2001:470:19:226::/64`。 |
| `-c`, `--config` | 二进制同目录下的 `domain.conf` | `dns` 模式域名规则文件路径。 |
| `-ipv4_pass_through`, `--ipv4_pass_through` | `false` | 当目标只有 IPv4 时，是否回落到本机默认 IPv4 出站。 |
| `-h`, `--help` | 无 | 显示帮助信息。 |

## proxy 模式

`proxy` 模式下，程序提供 SOCKS5 服务。客户端通过 SOCKS5 CONNECT 访问目标，目标会优先解析 IPv6，并通过指定 IPv6 子网中的随机地址出站。

无认证示例：

```bash
./ipv6-pool-proxy -m proxy -l 0.0.0.0:1080 -p 2001:db8:1234:5678::/64
```

开启用户名密码认证：

```bash
./ipv6-pool-proxy -m proxy -l 0.0.0.0:1080 -u user:pass -p 2001:db8:1234:5678::/64
```

如果目标域名只有 IPv4，默认会返回失败。开启 IPv4 回落：

```bash
./ipv6-pool-proxy -m proxy -l 0.0.0.0:1080 -p 2001:db8:1234:5678::/64 -ipv4_pass_through true
```

## dns 模式

`dns` 模式不是 SOCKS5 模式。它会启动两类服务：

1. UDP DNS 服务：监听 `-l` 指定的地址和端口。
2. TCP 443 SNI Proxy：监听 `-l` 指定 IP 的 TCP 443 端口。

例如：

```bash
./ipv6-pool-proxy -m dns -l 0.0.0.0:53 -p 2001:db8:1234:5678::/64 -c /etc/ipv6-pool-proxy/domain.conf
```

此时：

- DNS 服务监听 `0.0.0.0:53/udp`。
- SNI Proxy 监听 `0.0.0.0:443/tcp`。
- 用户需要把 DNS 指向本程序监听地址。
- 用户访问 HTTPS 域名时，若 DNS 查询命中 `domain.conf`，DNS 响应会返回本程序监听地址的 IP。
- 客户端随后连接该 IP 的 TCP 443，本程序读取 TLS ClientHello 中的 SNI，识别真实目标域名，然后作为 SNI Proxy 连接真实目标的 443 端口。
- 对命中 `domain.conf` 的 SNI 域名，真实目标连接会走随机 IPv6 子网出站。

指定规则文件：

```bash
./ipv6-pool-proxy -m dns -l 0.0.0.0:53 -p 2001:db8:1234:5678::/64 -c /etc/ipv6-pool-proxy/domain.conf
```

在 `dns` 模式中，若命中的域名只有 IPv4，默认失败。开启 IPv4 回落后，命中域名如果没有 IPv6 解析结果，会回落到本机默认 IPv4 出站：

```bash
./ipv6-pool-proxy -m dns -l 0.0.0.0:53 -p 2001:db8:1234:5678::/64 -c /etc/ipv6-pool-proxy/domain.conf -ipv4_pass_through true
```

注意：

- `dns` 模式下 `-u` / `--user` 会被忽略。
- `dns` 模式目前劫持 HTTPS/SNI 流量，即 TCP 443。
- `dns` 模式依赖客户端使用本程序提供的 DNS 解析结果访问目标。
- 如果监听标准端口 53/443，通常需要 root 权限或为二进制授予绑定低端口能力。

授予低端口绑定能力示例：

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/ipv6-pool-proxy
```

## domain.conf 格式

`domain.conf` 每行一条规则，支持 `#` 注释和空行。

示例：

```conf
# 仅劫持 google.com 本身，不包含子域名
google.com

# 劫持 google.com 以及任意层级子域名，例如 www.google.com、a.b.google.com
suffix:google.com

# 域名中包含 google 字符串即命中
keyword:google

# 劫持所有 .com 域名
tld:com
```

规则类型：

| 写法 | 说明 | 示例命中 | 示例不命中 |
| --- | --- | --- | --- |
| `google.com` | 精确匹配域名 | `google.com` | `www.google.com` |
| `suffix:google.com` | 匹配该域名及所有层级子域名 | `google.com`, `www.google.com`, `a.b.google.com` | `google.com.example.net` |
| `keyword:google` | 域名包含关键词即命中 | `www.google.com`, `googleapis.com` | `example.com` |
| `tld:com` | 匹配指定域名后缀 | `example.com`, `a.b.com` | `example.net` |

## systemd 示例

以下示例仅供参考，请根据实际路径、用户、监听地址和 IPv6 前缀调整。

创建 `/etc/systemd/system/ipv6-pool-proxy.service`：

```ini
[Unit]
Description=IPv6 Pool Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ipv6-pool-proxy -m dns -l 0.0.0.0:53 -p 2001:db8:1234:5678::/64 -c /etc/ipv6-pool-proxy/domain.conf -ipv4_pass_through true
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ipv6-pool-proxy
sudo systemctl status ipv6-pool-proxy
```

## 排障建议

### 绑定随机 IPv6 地址失败

检查是否已开启：

```bash
sysctl net.ipv6.ip_nonlocal_bind
```

应为：

```text
net.ipv6.ip_nonlocal_bind = 1
```

### IPv6 请求发出后无响应

优先检查：

```bash
ip -6 route
ip -6 addr
ip -6 neigh
```

如果不是隧道 IPv6 子网，请检查 `ndppd` 是否安装、运行，并确认 `/etc/ndppd.conf` 中的网卡名和 IPv6 前缀正确。

### dns 模式启动失败

`dns` 模式需要读取 `domain.conf`。如果没有通过 `-c` 指定，程序会从二进制文件同目录读取 `domain.conf`。请确认文件存在且规则格式正确。

如果监听 `0.0.0.0:53` 或 TCP `443` 启动失败，请检查是否具备低端口绑定权限，以及端口是否已被其它服务占用。

### DNS 命中但 HTTPS 无法访问

检查：

- 客户端 DNS 是否确实指向本程序。
- DNS 返回的 IP 是否为本程序 `-l` 指定的监听 IP。
- 本程序 TCP 443 是否可达。
- 目标是否使用 TLS SNI；没有 SNI 的 TLS 连接无法识别真实域名。

### 目标只有 IPv4 时失败

默认 `-ipv4_pass_through false`，目标只有 IPv4 时会失败。需要允许回落到本机默认 IPv4 出站时，请加入：

```bash
-ipv4_pass_through true
```
