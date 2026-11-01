# 移动 WiFi 多客户端代理修复（2026-11-01）

交付：`bin/Clash.Core`，aarch64 OpenWrt/Linux musl 静态、stripped ELF。

SHA-256：`a755451af893d892adbbc7834c8b6e444d8e4f8688f5cadc5680780ca4a754e9`。

## 日志结论

用户配置的关键组合为：

- `allow-lan: true`
- `mixed-port: 7890`
- `redir-port: 7891`
- `tproxy-port: 1536`
- `tun.stack: mixed`
- `tun.auto-route: true`
- `tun.strict-route: true`
- `tun.auto-redirect: false`
- `tun.auto-detect-interface: true`
- `dns-hijack: any:53` 与 `tcp://any:53`
- `mode: Rule`

日志中其他 WiFi 客户端是 `192.168.0.212`，共出现 204 条 TCP 和 12 条 UDP；原始日志中的大量连接目标为 `192.168.1.1:50016`。这说明设备确实收到了 WiFi 客户端流量，但不能单凭这份日志证明上游端口改写本身来自 Rust 核心。

## 根因与修复

1. Rust 原生支持判定把 Linux 上 `stack: mixed` 且 `auto-redirect: false` 当成缺口，启动时尝试切换到旧 Go 核心；设备没有旧核心时无法正常提供原生 LAN/TUN 路径。现在 Linux/Android 的 mixed TUN 可以走原生 passive TCP bridge 和 packet UDP relay。
2. Android 配置模板中的 `exclude-package` 在 Linux/移动 WiFi 核心上没有可执行语义，却会触发 legacy fallback。现在 Linux 只将其视为 inactive template 字段；真正的 Android 包过滤仍保留平台能力边界。
3. `mode: Rule`、`GLOBAL`、`Direct` 等大小写写法没有归一化，导致规则配置可能落入 fallback 分支。现在配置读取和运行时 `set_mode` 都转换为小写。
4. `any:53` 和 `tcp://any:53` 被统一当成 DNS 劫持标志，但此前没有连接到内置 DNS 解析计划，并且把用户代理名 `DNS` 当成 proxy 名，最终出现 `proxy not found: DNS`。现在 TCP/UDP DNS 劫持使用内部标志，直接进入核心 DNS packet/TCP 解析，不污染用户代理配置。
5. `auto-detect-interface` 以前只查看主路由表。移动 WiFi/Android 的 netd 经常把蜂窝默认路由放在额外策略表；现在扫描 `/system/bin/ip`、`/sbin/ip` 和全部路由表，跳过 TUN 与 loopback，选择实际蜂窝出口。直连 LAN 目标和 UDP 代理 socket 还会按已连接网段选择接口，避免把 LAN 流量绑定到蜂窝接口。
6. 自动路由的 DNS 规则条件原来会错误地匹配所有目的端口；现在只把非 DNS 流量保留在 TUN 路由，DNS 目的走主表，保持局域网和核心 DNS 回路。

## Docker 结果

隔离 Docker 网络命名空间模拟了两台独立 WiFi 客户端 `192.168.0.212` 和 `192.168.0.213`、蜂窝出口、mixed 监听、fake-IP DNS、TCP/UDP 代理和 TLS 源站。

| 测试 | 结果 |
| --- | --- |
| 最终 Rust 核心：两台 LAN 客户端 TCP、UDP、DNS 劫持、fake-IP 后续连接、TLS 4 MiB 下载 | 13 / 13 |
| 原版 Go 核心：相同拓扑与配置 | 13 / 13 |
| OpenClash TUN 回归 | 21 / 21 |
| 域名分流回归 | 93 / 93 |
| TC eBPF 回归 | 39 / 39 |
| TUN 相关 Rust 应用回归 | 41 / 41 |
| controller 回归 | 13 / 13 |
| UDP session 回归 | 2 / 2 |
| runtime/core/DNS/config/tun 库回归 | 397 / 6 / 53 / 24 / 9 |

两台客户端的 4 MiB TLS 内容 SHA-256 均为 `2b07811057df887086f06a67edc6ebf911de8b6741156e7a2eb1416a4b8b1b2e`，来源地址在代理连接记录中保持为对应客户端地址。最终 Rust 与 Go 对照原始结果在 `raw/`。

另外模拟了 OEM/netd 的独立策略路由表。该夹具的代理地址没有完整的真实蜂窝邻接路由，不能作为设备结论；代码已经覆盖扫描额外路由表的行为。移动 WiFi 真机仍需用新版文件复测。

## 部署

替换设备上的核心为仓库中的 `bin/Clash.Core`，使用对应的 `bin/Clash.Core.sha256` 校验文件验证。`-v` 应包含 `linux aarch64` 和 `with rustc`。

验证数据、构建日志和源文件哈希在本目录的 `manifest.json`、`raw/` 和相邻日志中。没有修改设备或发布远端版本。


最终候选还使用用户原样的 `mode: Rule`、嗅探设置和 `exclude-package` 模板字段完成了同一套 13 项 LAN 检查；Rust/Go 两侧均通过。`rust-oem-routing.json` 是最小 netd 策略路由模拟，因夹具没有完整的代理邻接路由而不计入通过项。
