# 实时速度修复验证（2026-11-01）

交付：`bin/mihomo-rust-openwrt-arm64-traffic-fix`，静态、stripped AArch64 musl ELF，28,150,568 字节；`.gz` 为 12,627,611 字节。

SHA-256：`90860874bcf6cd82c656340264f4528d45be12be396c9c43615c0b753fe9e619`。

## 根因和修复

旧内核 `traffic_snapshot()` 直接把 up_total/down_total 赋给 up/down，未计算每秒速度。TCP 全局总量又只在 relay 正常结束后加一次，因此仍存活的连接产生流量时全局为零；发生异常的连接可能丢失全部全局累计。对照 Go `tunnel/statistic/manager.go` 的 PushUploaded/PushDownloaded、每秒采样及 `hub/route/server.go` 的 `/traffic` 确认：速度是上一秒字节数，累计值应在传输期间更新。

修复后，每次成功写入同步更新全局与单连接字节数；部分写入之后出错也保留已经转发的字节。关闭时不再补加。TCP 和 UDP 使用统一的共享采样窗口，按单调时钟输出最近完整一秒的 B/s，读取不消费采样、不以订阅者刷新频率计算。暂停一个完整空窗口后速度归零，累计值保留。无需新增计时线程或按连接建立速度历史队列。

## 修复前复现

用上一版实际 ARM64 文件（SHA `e8f850e5f0f21cc6fd07d4eeed79d02bd2fde84c3ddbaff34eeaa0602e4378be`）发送 65,536 字节上传和 32,768 字节下载，保持连接打开：单连接已经分别记录这些值，但 `/traffic` 及 `/connections` 的全局累计均为 0。关闭连接后 up/down 变为 65,536 / 32,768，闲置两秒后仍不归零。原始结果为 `traffic-speed-before.json`。

## 最终文件实测

| 检查 | 结果 |
| --- | --- |
| 运行时单元（包含速率窗口与失败/部分写入计数） | 393 通过，1 项外部 MMDB 测试 ignored |
| API 单元 | 65 / 65 |
| 应用控制器 / TUN / UDP 会话 | 13 / 38 / 2 通过 |
| **最终 ARM64**：mixed 入口定量速度 | 64 / 64 |
| **最终 ARM64**：真实 REDIRECT 定量速度 | 64 / 64 |
| **最终 ARM64**：Clash UI/API | 55 / 55 |
| **最终 ARM64**：域名分流 | 93 / 93 |
| **最终 ARM64**：TUN | 21 / 21 |

速度夹具在连接持续存活时按固定节奏传输字节，通过独立服务器收到的上传字节和客户端收到的下载字节核对累计值，另查询 `/connections` 逐连接计数。单向、全双工及 UDP 阶段分别检查 HTTP 100 ms 轮询、HTTP 250 ms chunked 流、WebSocket 100 ms 和 700 ms；所有客户端同时订阅。

mixed 和 REDIRECT 两条入口的稳定段测量一致：

| 传输 | 预期上传 B/s | 测得上传中位数 B/s | 预期下载 B/s | 测得下载中位数 B/s |
| --- | --- | --- | --- | --- |
| 仅上传 | 524,288 | 524,288 | 0 | 0 |
| 仅下载 | 0 | 0 | 262,144 | 262,144 |
| 两个全双工连接合计 | 393,216 | 393,216 | 786,432 | 786,432 |
| UDP payload | 16,384 | 16,384 | 32,768 | 32,768 |

原始样本带单调时间戳，保存在 `traffic-arm64-mixed.json` 和 `traffic-arm64-redir.json`；提取结果为 `measurements.json`。判定对有节奏的真实调度允许 15% 误差；上表为实际稳定段中位数。暂停归零、累计值在连接未关闭时正确、关闭后不重复计数以及多个读取者不争用样本均逐项检查。REDIRECT 仅在隔离特权 Docker 容器的 loopback fixture 连接上安装精确源/目的端口规则，测试后删除。

应用控制器旧断言同步到此前已对齐的 Clash API（meta 为布尔值、restart 返回 204、Selector 用 now 和实际选择状态、Match 为 PascalCase）；保留控制命令和实际出口验证，未为此改变生产 API。

## 范围和使用

替换内核后现有面板可继续使用。`up/down` 单位为 B/s，采用最近完整一秒窗口，因此速度更新约一秒，暂停后通常一到两秒归零；`upTotal/downTotal` 是累计 payload 字节数。它不等同于包含封装、链路头和重传的网卡线速。

保留前一版文件及工作区此前修改；没有改动路由器或发布远端版本。构建命令、完整源码与产物 SHA 在 `manifest.json`。主要测试脚本：`scripts/traffic-speed-smoke.py --core <core> --output <json>`；加 `--inbound redir` 需隔离的特权 Linux 容器及 iptables。本轮未代替 OpenWrt 真机或外网吞吐上限测试。
