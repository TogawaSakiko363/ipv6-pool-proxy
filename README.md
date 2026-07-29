# ipv6-pool-proxy

`ipv6-pool-proxy` 是一个基于 Rust/Tokio 的 IPv6 随机子网出站工具，可同时提供两种服务：

- **SOCKS5 代理**：通过 `-proxy` 指定监听地址，提供 SOCKS5 CONNECT 代理。
- **DNS 劫持 + SNI Proxy**：通过 `-dns` 指定监听地址，提供 UDP DNS 劫持解析 + TCP 443 SNI Proxy，将被劫持域名的 HTTPS 流量通过随机 IPv6 地址出站。

两种服务可以独立启动，也可以同时运行，共享同一个 IPv6 出站前缀。

## 功能特性

- SOCKS5 CONNECT 代理（`-proxy` 监听地址）。
- DNS 劫持 + SNI Proxy（`-dns` 监听地址，UDP DNS + TCP 443）。
- 可选 SOCKS5 用户名/密码认证（仅代理端口有效）。
- 使用指定 IPv6 CIDR 前缀随机生成本地出站 IPv6 地址。
- 支持 `domain.conf` 精确域名、后缀、关键词、TLD 规则。
- 支持 `-ipv4_pass_through true|false`：目标只有 IPv4 时是否回落到本机默认 IPv4 出站。
- 支持 `-w ip.conf` 入站 IP 白名单，作用于 SOCKS5、SNI Proxy 与 DNS UDP 三个入口；支持单 IP 与 CIDR、IPv4 与 IPv6 混写。

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
Usage: ipv6-pool-proxy [-dns <addr:port> ...] [-proxy <addr:port> ...] [options]
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-dns`, `--dns` | 无 | DNS UDP + SNI TCP 443 监听地址，可重复指定多个（见下方双栈说明）。 |
| `-proxy`, `--proxy` | `0.0.0.0:1080`（当两个都未指定时） | SOCKS5 代理监听地址，可重复指定多个。 |
| `-u`, `--user` | 无 | SOCKS5 用户名密码认证，格式为 `user:pass`。仅在配置了 `-proxy` 时生效。 |
| `-p`, `--prefix` | 必填 | 出站随机 IPv6 CIDR，例如 `2001:470:19:226::/64`。 |
| `-c`, `--config` | 二进制同目录下的 `domain.conf` | DNS 域名规则文件路径。当配置了 `-dns` 时自动启用。 |
| `-ipv4_pass_through`, `--ipv4_pass_through` | `false` | 当目标只有 IPv4 时，是否回落到本机默认 IPv4 出站。 |
| `-w`, `--whitelist` | 无 | 入站 IP 白名单文件路径。未传时不启用白名单（允许所有 IP 连入）；传了则只放行命中的来源 IP。 |
| `-h`, `--help` | 无 | 显示帮助信息。 |

### 多监听地址与双栈

`-dns` 和 `-proxy` 均可重复指定，每个地址启动一个独立监听器。重复指定相同地址会启动失败。

- 每个 `-dns` 地址启动一对服务：UDP DNS + TCP 443 SNI Proxy
- 每个 `-proxy` 地址启动一个 SOCKS5 TCP 监听器

双栈场景下推荐分别绑定 IPv4 和 IPv6 地址，而非使用 `[::]` 通配：

```bash
# SOCKS5 代理双栈
./ipv6-pool-proxy -proxy 0.0.0.0:1080 -proxy [::]:1080 -p 2001:db8:1234:5678::/64

# DNS 双栈（推荐绑定具体 IP 而非通配，见下方注意事项）
./ipv6-pool-proxy -dns 1.2.3.4:53 -dns [2001:db8::1]:53 -p 2001:db8:1234:5678::/64 -c domain.conf
```

DNS 模式下，每个监听地址的 IP 就是该 socket 劫持 DNS 查询时返回的答案地址：IPv4 socket 返回 A 记录，IPv6 socket 返回 AAAA 记录，类型不匹配时返回 NOERROR 空答案（NODATA）而非 NXDOMAIN，避免双栈客户端因某一族返回 NXDOMAIN 而放弃另一族的查询。

> **注意**：若 `-dns` 使用通配地址（`0.0.0.0` 或 `::`），DNS 劫持答案也会返回通配地址，客户端无法连接，启动时程序会打印警告。请绑定具体的可路由 IP。

## SOCKS5 代理模式

`-proxy` 指定 SOCKS5 代理监听地址。客户端通过 SOCKS5 CONNECT 访问目标，目标会优先解析 IPv6，并通过指定 IPv6 子网中的随机地址出站。

无认证示例：

```bash
./ipv6-pool-proxy -proxy 0.0.0.0:1080 -p 2001:db8:1234:5678::/64
```

不传 `-proxy` 时默认启动 `0.0.0.0:1080` 的 SOCKS5 代理：

```bash
./ipv6-pool-proxy -p 2001:db8:1234:5678::/64
```

开启用户名密码认证：

```bash
./ipv6-pool-proxy -proxy 0.0.0.0:1080 -u user:pass -p 2001:db8:1234:5678::/64
```

如果目标域名只有 IPv4，默认会返回失败。开启 IPv4 回落：

```bash
./ipv6-pool-proxy -proxy 0.0.0.0:1080 -p 2001:db8:1234:5678::/64 -ipv4_pass_through true
```

双栈监听（IPv4 和 IPv6 客户端各走独立 socket）：

```bash
./ipv6-pool-proxy -proxy 0.0.0.0:1080 -proxy [::]:1080 -p 2001:db8:1234:5678::/64
```

## DNS 劫持 + SNI Proxy 模式

`-dns` 为每个地址启动一对服务：

1. **UDP DNS 服务**：监听指定地址和端口。
2. **TCP 443 SNI Proxy**：监听指定 IP 的 TCP 443 端口（端口号固定为 443）。

单栈示例：

```bash
./ipv6-pool-proxy -dns 1.2.3.4:53 -p 2001:db8:1234:5678::/64 -c /etc/ipv6-pool-proxy/domain.conf
```

此时：

- DNS 服务监听 `1.2.3.4:53/udp`。
- SNI Proxy 监听 `1.2.3.4:443/tcp`。
- 用户需要把 DNS 指向本程序监听地址。
- 用户访问 HTTPS 域名时，若 DNS 查询命中 `domain.conf`，DNS 响应会返回本程序监听地址的 IP（本例为 `1.2.3.4`）。
- 客户端随后连接该 IP 的 TCP 443，本程序读取 TLS ClientHello 中的 SNI，识别真实目标域名，然后作为 SNI Proxy 连接真实目标的 443 端口。
- 对命中 `domain.conf` 的 SNI 域名，真实目标连接会走随机 IPv6 子网出站。

双栈示例（A 查询走 IPv4 socket 返回 A 记录，AAAA 查询走 IPv6 socket 返回 AAAA 记录）：

```bash
./ipv6-pool-proxy -dns 1.2.3.4:53 \
  -dns [2001:db8::1]:53 \
  -p 2001:db8:1234:5678::/64 \
  -c /etc/ipv6-pool-proxy/domain.conf
```

开启 IPv4 回落：

```bash
./ipv6-pool-proxy -dns 1.2.3.4:53 -p 2001:db8:1234:5678::/64 -c /etc/ipv6-pool-proxy/domain.conf -ipv4_pass_through true
```

## DNS + SOCKS5 同时运行

两个服务可以同时启动，共享同一个 IPv6 出站前缀：

```bash
./ipv6-pool-proxy -dns 1.2.3.4:53 -proxy 0.0.0.0:11001 -u alice:secret -p 2001:db8:1234:5678::/64 -c domain.conf
```

此时：

- DNS + SNI 监听 `1.2.3.4:53/udp` 和 `1.2.3.4:443/tcp`
- SOCKS5 代理监听 `0.0.0.0:11001/tcp`（带密码认证）
- 两者使用相同的 IPv6 前缀随机出站

这个模式完全替代了旧版 `-m dns -l 1.2.3.4:53 -s 0.0.0.0:11001` 的用法。

注意：

- `-u` / `--user` 仅在配置了 `-proxy` 时生效，纯 DNS 模式下会被忽略。
- DNS 模式依赖客户端使用本程序提供的 DNS 解析结果访问目标。
- **`-dns` 必须绑定具体可路由 IP**，不能用 `0.0.0.0` / `::` 等通配地址，否则 DNS 劫持答案会返回不可连接的地址，启动时程序会打印 `[warn]` 警告。
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

## ip.conf 入站白名单

通过 `-w ip.conf` 启用入站白名单。启用后，**只有命中白名单的来源 IP** 才能与本程序建立连接，作用范围覆盖：

- SOCKS5 代理 TCP 端口；
- SNI Proxy TCP 443 端口；
- UDP DNS 端口。

未命中的来源连接会被立即关闭（TCP RST）或丢弃（UDP），程序不返回任何应用层应答。TCP 白名单拒绝和过载丢连接均会在 stderr 打印一行日志（`[whitelist deny tcp]` / `[overload]`）。

文件每行一条规则，支持 `#` 注释和空行。规则同时支持 IPv4 / IPv6 的单地址与 CIDR：

```conf
# 单 IPv4，等价于 1.1.1.1/32
1.1.1.1

# IPv4 CIDR
1.1.1.0/24
10.0.0.0/8

# 单 IPv6，等价于 ::1/128
::1

# IPv6 CIDR
2001:db8::/32

# 任意 IPv6
::/0
```

启动示例：

```bash
./ipv6-pool-proxy -proxy 0.0.0.0:1080 -p 2001:db8:1234:5678::/64 -w /etc/ipv6-pool-proxy/ip.conf
```

启动日志会显示载入条目数，便于发现配置错误：

```text
... whitelist: enabled (4 entries)
```

注意：

- **不传 `-w`** 等价于不启用白名单，所有来源 IP 均放行（保持旧行为）。
- **传了 `-w` 但文件为空** 会启用白名单且 0 条目，此时**任何来源都会被拒绝**，程序不会自动放行 `127.0.0.1` 之类，需要显式写入白名单。
- **`-w` 指定的文件不存在** 会启动失败，避免误以为生效。
- 当监听地址是 `[::]` 这类双栈地址时，IPv4 客户端在内核层会以 `::ffff:1.2.3.4` 形式被 accept；程序内部已自动归一化为 `1.2.3.4`，因此白名单中**直接写 IPv4 地址即可**，无需写 v4-mapped IPv6 形式。
- 白名单只控制"谁能连入"，不影响出站随机 IPv6 行为。

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
ExecStart=/usr/local/bin/ipv6-pool-proxy \
  -dns 1.2.3.4:53 \
  -dns [2001:db8::1]:53 \
  -p 2001:db8:1234:5678::/64 \
  -c /etc/ipv6-pool-proxy/domain.conf \
  -ipv4_pass_through true \
  -w /etc/ipv6-pool-proxy/ip.conf
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

### DNS 模式启动失败

DNS 模式需要读取 `domain.conf`。如果没有通过 `-c` 指定，程序会从二进制文件同目录读取 `domain.conf`。请确认文件存在且规则格式正确。

如果监听 `:53` 或 TCP `443` 启动失败，请检查是否具备低端口绑定权限，以及端口是否已被其它服务占用。

如果启动时看到 `[warn] dns listener ... is a wildcard IP`，说明 `-dns` 使用了 `0.0.0.0` 或 `::` 通配地址，DNS 劫持答案将返回不可连接的地址。请改为绑定具体的可路由 IP，例如 `-dns 1.2.3.4:53`。

### DNS 命中但 HTTPS 无法访问

检查：

- 客户端 DNS 是否确实指向本程序。
- DNS 返回的 IP 是否为本程序 `-dns` 指定的监听 IP。
- 本程序 TCP 443 是否可达。
- 目标是否使用 TLS SNI；没有 SNI 的 TLS 连接无法识别真实域名。

### 目标只有 IPv4 时失败

默认 `-ipv4_pass_through false`，目标只有 IPv4 时会失败。需要允许回落到本机默认 IPv4 出站时，请加入：

```bash
-ipv4_pass_through true
```

### 启用白名单后客户端无法连接

排查顺序：

1. 查看启动日志中的 `whitelist: enabled (N entries)`，确认 N 不为 0；
2. 客户端的真实出口 IP 是否在白名单中（NAT、CGNAT、IPv6 临时地址都可能让出口 IP 与你以为的不同）；
3. 如果服务监听 `[::]`（双栈），客户端是 IPv4，白名单**直接写 IPv4 地址**即可，不要写成 `::ffff:1.2.3.4`；
4. 白名单未命中时连接被静默关闭，不会有日志，可在服务器上用 `ss -tn`、`tcpdump` 或防火墙日志辅助验证连接是否到达本机。
