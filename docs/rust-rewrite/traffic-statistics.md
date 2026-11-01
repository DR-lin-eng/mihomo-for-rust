# 实时流量统计（2026-11-01）

当前 ARM64 静态内核为 `bin/Clash.Core`，附 `.gz`、`.sha256`，包含此前 yacd 规则页、域名分流、流量统计，以及最新 TUN HTTPS 背压修复。流量统计版本仍保留为 `bin/mihomo-rust-openwrt-arm64-traffic-connections-fix`。实时速度及连接列表验证报告见 `diagnostics/traffic-speed-20261101/VERIFICATION.md`；TUN HTTPS 前后对照见 `diagnostics/tun-https-20261101/VERIFICATION.md`。

## API 含义

`GET /traffic`、其 HTTP 流和 WebSocket 流使用相同的共享数据：

| 字段 | 单位与含义 |
| --- | --- |
| `up` / `down` | 最近一个完整一秒窗口中的上传/下载字节数，即 B/s |
| `upTotal` / `downTotal` | 核心累计转发的上传/下载字节，包括仍打开的连接 |
| `/connections` 的 `uploadTotal` / `downloadTotal` | 与 `/traffic` 的累计值相同 |
| 单连接 `upload` / `download` | 该连接累计转发的字节数 |
| 单连接 `start` | 与 Go 一致的 RFC3339 UTC 时间字符串 |

采样使用单调时钟。不同刷新间隔和不同面板读取同一份一秒结果，读取不会清空采样计数。`interval` 控制推送频率，不改变 B/s 的含义。启动后首个完整采样前速度为零；停止传输后，经过完整空窗口速度归零，通常需要一到两秒。累计值保持不变。

## 修复

此前 `traffic_snapshot()` 把累计字节数同时返回为 `up` / `down`。TCP 又仅在双向 relay 正常结束后将整条连接流量加入全局累计。因此长连接传输时全局常为零，关闭时突增，闲置时仍把累计值显示为速度。

现在，TCP 每次成功写入就更新单连接和全局计数，包括部分写入成功后发生错误的情况；连接关闭时不再补加一次。全局和单连接计数在同一个统计锁内更新，`/connections` 也在该锁内获取全局和活动行快照，避免并发传输时返回不同时刻的数据。锁内不进行网络 I/O。

UDP 活动流按入站、来源和目的地址追踪，使用解析/嗅探后的域名及实际已经准备好的代理链、provider 链和规则。上行和下行都按 payload 字节计数，去掉 SOCKS、加密或 packet-addr 封装返回长度的开销。相同流的多个报文合并计数；使用单调时钟，在快照或新流注册时清理空闲超过 30 秒的活动行，全局累计值保留。控制器关闭 UDP 流后取消待回包，后续报文建立新的流；TUN 缓存的会话也会在后续发送前重建。顶层 `mixed-port` 和 `socks-port` 支持 UDP ASSOCIATE。

活动行合计只覆盖当前列表中的流量。连接已经关闭、过期或被控制器清理后，其历史字节仍包含在全局累计中，因此全局累计可以大于当前活动行合计。分别读取 `/traffic` 和 `/connections` 时也会存在两次请求之间的正常传输增量。

采样状态按核心共享，无额外计时线程或每连接速度历史队列。

统计单位为业务转发字节，不等于网卡上包含 IP/TCP/TLS/代理封装和重传开销的线速。所有接口都以客户端视角区分上传和下载。

## 验证

`scripts/traffic-speed-smoke.py` 创建独立 TCP/UDP 夹具，在连接保持打开时传输限速数据，并比较：

- 单向上传、单向下载、两个全双工连接的实际字节和共享速度。
- HTTP 100 ms 轮询、HTTP 250 ms 流、WebSocket 100 ms 和 700 ms 的采样一致性。
- 长连接暂停归零、累计值即时更新、关闭不重复计数、UDP 方向与计数。
- HTTP 30 ms 和 WebSocket 50 ms 连接快照在传输期间的内部计数一致性。
- UDP 的活动行、域名、实际代理/provider 链、开始时间、延迟回包取消和空闲过期。

最终静态 ARM64 文件在 mixed/真实 REDIRECT 入口与 DIRECT/SOCKS5 出口的四种组合中各通过 110 项检查，共 440 项。测试同时覆盖 tunnel UDP 和 SOCKS5 入站 UDP。单元测试另覆盖部分写入、write-zero、读写失败时已完成字节保留、并发统计快照、闲置窗口和多个读取者。API、域名分流、TUN 等回归结果及验证边界见验证报告。
