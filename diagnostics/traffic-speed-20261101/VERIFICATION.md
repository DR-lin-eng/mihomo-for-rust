# 实时速度与 /connections 修复验证（2026-11-01）

交付：`bin/mihomo-rust-openwrt-arm64-traffic-connections-fix`，静态、stripped AArch64 musl ELF，28,150,568 字节；`.gz` 为 12,685,655 字节。包含此前 yacd 规则页、域名分流、TUN、Smart 和 eBPF 改动。

SHA-256：`34ebff007f5863c4fa3dbaf4ca92e3e1f90cad7e6d88a2a84512721805cf4338`。

本轮原始采样、构建/测试日志、逐源文件及产物校验值位于 `connections-fix/`。此前速度修复的记录保存在 `VERIFICATION-traffic-fix.md`，其旧产物与原始数据继续保留。

## 发现与修复

对照 Go 的 `tunnel/statistic/manager.go`、`tunnel/statistic/tracker.go` 和 `listener/listener.go`，检查了实际转发计数到 HTTP/WebSocket API 的完整路径。

1. **长连接期间累计值不更新、累计字节被用作速度。** TCP 原先在正常结束后才把整条连接字节加入全局，错误连接还会漏计。现在每次成功写入更新单连接和全局计数，包括部分写入成功后发生错误的情况；结束时不再补加。`up/down` 使用单调时钟共享的最近完整一秒窗口，单位 B/s，读取不消费样本，不依赖面板刷新频率。
2. **/connections 缺少 UDP。** 新增活动 UDP 流行，合并相同入站、来源和目的地址的报文，记录解析/嗅探后的域名、实际已准备的代理链与 provider 链、规则和计数。开始时间输出 RFC3339 UTC 字符串，与 Go 的时间字段一致。
3. **UDP 封装长度混入单连接计数。** SOCKS、加密或 packet-addr 路径可能返回含头部的长度。上行和下行统一限制到实际 payload 长度，保留短写结果，全局及活动行使用同一字节数。
4. **并发快照来自不同时刻。** 全局与单连接字节在同一个统计锁内更新，`/connections` 在该锁内同时读取全局累计和活动行。锁内不进行网络 I/O。仍在传输时，不会因为两次独立采样造成单连接数字领先于同一响应中的全局数字。
5. **UDP 生命周期不完整。** 活动行使用单调时钟，在获取快照或注册新流时清理空闲超过 30 秒的流；历史累计保留。控制器 DELETE 会取消待回包，后续报文建立新流；缓存的 TUN UDP 会话在之后发送前重建。顶层 `mixed-port`、`socks-port` 现在启用 UDP ASSOCIATE，避免只有自定义 listener 能处理该命令。

## Docker 验证结果

所有最终产物实测都运行 `bin/mihomo-rust-openwrt-arm64-traffic-connections-fix`，其 SHA 与交付文件一致。夹具使用隔离 Docker 网络命名空间及本地固定数据，不使用真实订阅或节点凭据。

| 检查 | 结果 |
| --- | --- |
| runtime / core / DNS / API 库测试 | 396 / 6 / 53 / 66 通过 |
| 应用 controller / TUN / UDP session 定向回归 | 13 / 38 / 2 通过 |
| 最终 ARM64：mixed → DIRECT | 110 / 110 |
| 最终 ARM64：mixed → SOCKS5 provider/select 链 | 110 / 110 |
| 最终 ARM64：真实 REDIRECT → DIRECT | 110 / 110 |
| 最终 ARM64：真实 REDIRECT → SOCKS5 provider/select 链 | 110 / 110 |
| 最终 ARM64：域名分流 | 93 / 93 |
| 最终 ARM64：OpenClash system TUN | 21 / 21 |
| 最终 ARM64：真实 TC eBPF | 39 / 39 |
| 最终 ARM64：yacd /rules、provider 时间戳与刷新回滚 | 30 / 30 |

库和应用定向测试共 **574 项通过**；1 项需要外部 MMDB 夹具的测试 ignored。最终 ARM64 实测共 **623 项通过**，其中速度/活动连接四种组合共 440 项。曾尝试应用全量 541 项，但若干长时间运行的协议测试结束前进程持续无输出，之后主动终止；未将这次未完成运行计入成功。上表应用结果来自另行完整结束的定向回归。

## 实测方式与数值

`scripts/traffic-speed-smoke.py` 使用独立 TCP 接收端、UDP echo、SOCKS 代理及客户端字节计数进行核对，保持 TCP 连接打开，分别执行单向与双向有节奏传输。四组测试同时采样 `/traffic` 的 HTTP 100 ms 轮询、HTTP 250 ms 流、WebSocket 100 ms 和 700 ms，并通过 `/connections` 的 HTTP 30 ms 轮询和 WebSocket 50 ms 检查每个快照的内部一致性。

| 传输 | 预期上传 B/s | 测得上传中位数 B/s | 预期下载 B/s | 测得下载中位数 B/s |
| --- | --- | --- | --- | --- |
| 仅上传 | 524,288 | 524,288 | 0 | 0 |
| 仅下载 | 0 | 0 | 262,144 | 262,144 |
| 两个全双工 TCP 合计 | 393,216 | 393,216 | 786,432 | 786,432 |
| tunnel UDP payload | 16,384 | 16,384 | 32,768 | 32,768 |
| SOCKS5 入站 UDP payload | 16,384 | 16,384 | 32,768 | 32,768 |

上表为稳定段读数。判定对实际调度允许 15% 误差，四种入口/出口组合的稳定中位数均匹配预设。还逐项验证：连接暂停后速度归零，关闭 TCP 不重复计数；UDP 传输期间和结束后的活动行及全局 payload 值一致；实际域名、规则、provider/代理链和时间正确；DELETE 取消人为延迟的回包，后续流使用新 ID；空闲后活动行消失而全局累计保留。原始带单调时间戳的采样在四份 `traffic-connections-arm64-*.json` 中，提取结果为 `connections-fix/measurements.json`。

## 使用与边界

替换 OpenClash 内核时使用本次 `traffic-connections-fix` 文件，压缩包需解压后使用。`up/down` 为最近完整一秒的 B/s，停止传输后通常一至两秒归零。累计值以核心客户端视角统计业务 payload，并不包含 IP/TCP/TLS/代理封装和重传开销，因此不等于网卡线速。

`/connections` 的活动行只覆盖当前仍被追踪的流。已经关闭、清理或过期的流，其历史字节继续包含在全局累计中，所以全局累计可以大于当前活动行合计。分别请求 `/traffic` 和 `/connections` 时，也会存在两个请求之间的正常传输增量。本轮验证覆盖 Docker 中的本地确定性数据与实际 Linux REDIRECT/TUN/TC eBPF 路径，尚未代替 OpenWrt 真机与真实外网节点复测。

没有修改路由器，也没有提交或发布远端版本。构建命令、完整源文件哈希及日志在 `connections-fix/manifest.json` 和相邻日志中。
