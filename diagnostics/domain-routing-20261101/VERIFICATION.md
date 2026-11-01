# 域名分流修复验证（2026-11-01）

交付：`bin/mihomo-rust-openwrt-arm64-domain-routing`，AArch64 Linux musl 静态 ELF，stripped，28,085,032 字节。压缩包和 SHA-256 同目录。

SHA-256：`e8f850e5f0f21cc6fd07d4eeed79d02bd2fde84c3ddbaff34eeaa0602e4378be`。

## 问题与修复

针对 OpenClash 的 redir-host DNS、redir/TProxy 透明代理，以及启用 TLS/HTTP/QUIC 的 sniffer 配置核对了当前 Go `dns/enhancer.go`、`tunnel/tunnel.go` 和 `component/sniffer/dispatcher.go`。发现并修复：

1. DNS wire 应答转发没有记录真实地址到域名的映射，预处理只查 fake-IP。加入共享、容量有界、带 TTL 的映射，支持 A/AAAA、CNAME、HTTPS/SVCB 地址 hints。真实地址保留供拨号，虚拟地址清除后按域名连接。
2. sniffer 只有配置和面板字段，没有数据平面调用。接入 TCP 的 TLS SNI、HTTP Host 和 UDP QUIC Initial/CRYPTO，支持分片、乱序和先到的 0-RTT，遵守端口、skip-domain、force-dns-mapping、parse-pure-ip 和目标覆盖开关。已消费字节/数据报回放保持原样。
3. 连接建立只更新元数据副本。现在在规则匹配和拨号前更新连接上下文，让 `/connections` 的域名、嗅探域名、规则和代理链与实际选路一致。
4. 透明 UDP 回复 socket 的永久缓存会截走后续入站数据，却没有对应读取循环。回复后释放，保证连续 QUIC 数据报继续进入 TProxy。转发状态锁不再跨 DNS/网络回调持有。
5. 真实 redir 上游错误现在带实际 proxy、chain 和 target。最终网络夹具用会截断 SOCKS 应答的节点验证错误仍被保留，同时明确指出失败节点和域名。

完整支持条件和容量见 `docs/rust-rewrite/domain-routing.md`。本轮保留此前 TUN 默认地址、Huber 支持、Smart、eBPF 以及工作区已有整理；未推送或发布远端版本。

## Docker 验证

| 检查 | 结果 |
| --- | --- |
| 运行时 / DNS / 核心 / API 单元 | 511 通过，1 项外部 MMDB 夹具测试 ignored |
| 完整传输层 | 245 / 245 |
| 应用透明代理 / TUN / DNS / UDP 会话 / 重载 | 4 / 38 / 11 / 2 / 2 通过 |
| **最终 ARM64**：真实 REDIRECT/TPROXY 域名路由 | 93 / 93 |
| **最终 ARM64**：TUN 就绪、TCP/UDP 和分段 TLS SNI | 21 / 21 |
| **最终 ARM64**：Clash UI/API/DNS | 55 / 55 |
| **最终 ARM64**：真实 Model-large Smart | 39 / 39 |
| **最终 ARM64**：竞速、地区证据及高级 Smart | 62 / 62 |
| **最终 ARM64**：eBPF | 39 / 39 |
| 原有 TUN fake-IP 转发 | 通过，198.18.0.4 |

域名路由实测在 Docker 内创建独立 network namespace 和 veth，使用真实 iptables REDIRECT、TPROXY、策略路由、TCP/TLS/UDP socket 及两个可识别出口的 SOCKS5 夹具。客户端按 IP 访问，通过返回内容确认实际节点，再独立查询 `/connections` 确认规则、host、sniffHost 和代理链。

93 项覆盖：关闭 sniffer 时的 redir-host 映射、UDP/TCP DNS、CNAME、HTTPS hints、本地 hosts、provider 规则、TTL 到期及重新查询、普通 UDP；启用 sniffer 时的 TLS 443/8443、HTTP 端口范围与分段/长 body、force-dns-mapping、skip-domain、端口过滤、override=false；七组上游 QUIC 抓包（单包、乱序、分片、先到 0-RTT、九包混合），逐包校验出口及 SHA-256；上游 EOF 错误上下文。

QUIC 抓包提取自仓库中的 Go `component/sniffer/sniff_test.go`，不是依据 Rust 生成的预期数据；原始夹具为 `rust/crates/mihomo-runtime/src/sniffer-quic-fixtures.json`。TLS/HTTP 客户端产生真实网络流量。单元测试另验证映射 TTL/清缓存/共享快照、CNAME 最短 TTL、无关答案排除、DNS 压缩环和截断应答、IPv6 hints、TCP 字节回放及一秒嗅探期限。

TUN 实测使用真实 /dev/net/tun 和 SO_MARK 策略路由；分段 ClientHello 的域名规则指向代理，MATCH 指向 REJECT，从实际返回数据确认嗅探发生在路由前。最终三份网络/高级实测 JSON 内的 sha256 已与交付文件核对。

## 用户指定的 Smart 大模型

下载 [公开 Model-large.bin](https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin)：26,787,747 字节，534 棵树，30 特征，`objective=huber`。SHA-256：`832920df1290454710dd04aa4c7d4b5324edfd7816a7c9ad2272708b5d5a13a8`。

使用独立 LightGBM 4.6.0 对同一模型比较 160 组输入，最大绝对误差为 0；最终 ARM64 文件用该模型执行完整 Smart 学习、更新、坏模型回退和持久化回归。没有使用或保存用户节点凭据。

## 内存

同一隔离 Docker 容器（CPUs=2）、相同静态目标和 557 棵树基准模型，两版各三轮取中位数，每轮 32 次 API 查询。单位 KiB。

| 场景 | 空闲 RSS（旧 → 新） | API 后 RSS（旧 → 新） | API 后匿名内存（旧 → 新） |
| --- | --- | --- | --- |
| idle | 8212 → 8592 | 8388 → 8764 | 1132 → 1136 |
| smart-18-groups | 12736 → 12988 | 12912 → 13160 | 5448 → 5452 |

新域名映射由快照共享，最多 4096 个 IP，QUIC 待识别流最多 64 个并有每流容量阈值。该内存对比衡量空闲和 API 轮询，不代表所有网络负载下的峰值。原始数据见 `memory-before.json`、`memory-after.json`。

## 交付和范围

构建命令、工具链、完整源文件/产物 SHA-256 在 `manifest.json`。主要实测入口为 `scripts/domain-routing-smoke.py`、`scripts/openclash-tun-smoke.py`，须在隔离且具备 CAP_NET_ADMIN、TUN、iptables、iproute2 的 Linux 容器内运行。

替换后应重建连接。终端已有 DNS 缓存中、旧核心没有记录的答案，需要新 DNS 查询或可识别的 TLS/HTTP/QUIC 域名才能恢复；实际 ECH 内层域名不可由明文嗅探恢复。捕获测试主要覆盖 QUIC v1，未独立验证所有 v2/draft-29 组合。映射和嗅探不会保证恢复完全绕开核心 DNS且没有可见域名的流量。

本轮没有访问用户路由器或真实节点；Docker 结果证明所列选路和数据完整性行为，仍需 OpenWrt 真机复测。
