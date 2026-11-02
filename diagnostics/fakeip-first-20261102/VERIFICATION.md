# fake-IP 首次访问修复与耗时对照

交付：`bin/Clash.Core`，OpenWrt/Linux aarch64 musl 静态 ELF，已 strip；压缩版为 `bin/Clash.Core.gz`。

SHA-256：`5ac7183cc097eeda2ccc88ea383a34d2db7df980b38f710dbf83a290d1dae446`。

旧版保存在 `bin/Clash.Core.before-fakeip-first`，SHA-256 为 `1f68e801f17b7abfe2cee57df4b37133d020f9d1e3e494f41256968df8fc1f46`。

## 已复现的原因

1. `dns.ipv6: false` 此前未进入解析运行时。首次连接的真实地址解析仍发送 A 和 AAAA 查询；即使 A 已成功，后续 AAAA 超时也会丢掉 A 结果，导致连接失败。
2. 多个 DNS 上游按顺序查询。排在前面的服务器无响应时，健康的后续服务器也必须等待它超时。HTTPS 等原始记录查询还会直接接受 SERVFAIL/REFUSED，无法尝试另一个健康上游。
3. UDP DNS listener 在接收循环内同步等待远程查询。一个慢 HTTPS/SVCB 查询会阻塞后面的本地 fake-IP 应答。
4. UDP 连接的真实 DNS 解析在锁外进行，完成后却把旧的 fake-IP 快照整体写回。若这期间另一域名刚分配地址，该映射就会被覆盖，后续访问出现 `fake DNS record ... missing`。

这些问题均由隔离 Docker 夹具复现，未依赖公网 DNS 或用户节点。

## 本次修改

- 运行时读取 `dns.ipv6`。关闭 IPv6 时真实地址解析只查询 A，客户端的 AAAA 查询返回正常空响应；显式开启 IPv6 时仍支持双栈。双栈查询中一个地址族失败时保留另一地址族的成功结果，并按记录类型检查地址缓存。
- 对同一 nameserver/policy 选出的 DNS 上游并发查询，使用先完成的有效响应。SERVFAIL/REFUSED 会尝试其他上游；NXDOMAIN 和显式 `rcode://` 策略保留原义。真实地址解析的传输错误可进入已配置的 fallback。
- UDP DNS listener 在接收线程直接完成本地 fake-IP 应答，远程查询交给有并发上限的任务执行。
- 连接解析采用最新的共享 DNS 快照，完成后只合并真实解析缓存，不再覆盖全局 fake-IP 地址分配；连接快照不执行 fake-IP 持久化写入。配置重载的显式状态恢复仍由原有独立入口处理。

并发上限：每个 DNS 请求最多 4 个上游 worker，全局最多 64 个；每个 UDP DNS listener 最多 64 个远程任务。上游 worker 栈为 512 KiB。获胜后停止尚未发出的查询，已在进行的网络 I/O 按现有超时退出；自定义不支持独立 I/O 克隆的 transport 使用顺序查询。本次没有做整机内存或公网吞吐基准。

主要代码：`mihomo-dns/src/exchange_race.rs`、`runtime.rs`、`upstream.rs`、`types.rs`、`support.rs`，以及应用的 `listener_service_runtime_udp.rs`、`listener_udp_session_ops.rs` 和 runtime 的 `tunnel_runtime.rs`。

## ARM64 Docker 对照结果

脚本：`scripts/fakeip-first-smoke.py`。通过 fake-IP DNS 分配地址后，以 SOCKS5 访问该地址，真正建立 TCP/HTTP 或 UDP 连接；同时模拟不可用 DNS、AAAA 丢包、SERVFAIL、DoH 和解析期间的新地址分配。

| 场景 | 旧版 | 本次版本 |
| --- | --- | --- |
| A 成功、AAAA 无响应，`dns.ipv6: false` | 约 1.217 秒后连接失败 | 约 0.188 秒成功，无 AAAA 上游请求 |
| 第一个 DNS 不响应，第二个正常 | 首次连接约 1.236 秒 | 约 0.189 秒 |
| 第一个 DNS 不响应，第二个为 HTTPS DoH | 首次连接约 1.208 秒 | 约 0.189 秒 |
| 上游慢 HTTPS 查询期间，其他本地 fake-IP 应答 | 约 551 毫秒 | 约 0.36 毫秒 |
| 首个 DNS 返回 SERVFAIL 的 HTTPS 查询 | 向客户端返回 SERVFAIL | 尝试健康上游，返回正常响应 |
| UDP 解析期间新分配域名，随后访问该地址 | 映射丢失，连接失败 | 映射保留，连接成功 |
| 首访夹具合计 | 10/20 | **20/20** |

这些耗时包括本地代理建连与 listener 调度，是控制故障条件下的对照，不代表所有公网网站都具有相同比例的提速。DoH 使用本地生成的测试证书，通过该核心进程的 `SSL_CERT_FILE` 信任，证书校验保持开启。

最终候选还完成了以下回归，所有原始结果都记录了与交付文件相同的 SHA-256：

| 回归 | 结果 |
| --- | --- |
| DIRECT、SOCKS5、Shadowsocks、VLESS TLS 的 fake-IP 游戏 UDP | 各 10/10 |
| Hysteria2 交错访问两台服务器及延迟主动推送 | 11/11 |
| 同一 UDP 源端口切换 DIRECT/SOCKS5 路由 | 10/10 |
| 32 秒后服务端主动回包、同时轮询 `/connections` | 8/8 |
| 游戏 UDP 合计 | 69/69 |
| 两台 LAN 客户端及 TCP/UDP/TLS | 13/13 |
| OpenClash TUN | 21/21 |
| 域名分流 | 93/93 |
| 规则/provider API | 30/30 |

Rust 库检查：DNS 58、runtime 398、API 66、config 24、core 6、TUN 9 项通过；runtime 有 1 项依赖外部 MMDB 的测试忽略。应用检查：DNS 9、TUN 45、UDP session 2 项通过。日志在本目录；这些是本次相关检查，不是完整工作区或全协议等价性声明。

## 使用与证据

用本次 `Clash.Core` 替换设备实际启动的内核，保留可执行权限后重启。无需为本次修复调整现有配置。

```sh
sha256sum Clash.Core
./Clash.Core -v
```

版本行应包含 `linux aarch64`、`with rustc 1.88.0`。版本号仍为 `0.1.0`，请以 SHA-256 区分构建。

本目录 `raw/baseline.json.gz`、`raw/final-first.json.gz` 保存首访原始结果；其他 `raw/final-*.json.gz` 为运行回归。`manifest.json` 记录构建、源文件、内核和证据校验值。

移动 WiFi 真机未被访问，实际网站和游戏仍需替换后复测。
