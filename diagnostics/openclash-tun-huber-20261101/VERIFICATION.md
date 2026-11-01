# OpenClash TUN 与 Huber 修复验证（2026-11-01）

交付内核：`bin/mihomo-rust-openwrt-arm64-openclash-fix`，AArch64 Linux musl 静态 ELF，stripped，28,019,496 字节。SHA-256：`445d3212f16f5dad94171055952878e5b9c430fc11557e4223a3ebd247c241f2`。压缩文件与 `.sha256` 同目录。

## 根因和行为

OpenClash [e553e82](https://github.com/vernesong/OpenClash/tree/e553e82e01c697aefbe1555261a503f425e00ccd) 的初始化脚本用 `ip route list | grep utun` 判断 IPv4 TUN 就绪，而不只检查接口存在。它生成的配置使用 `device: utun`、`auto-route: false`、`auto-redirect: false`，由插件管理策略路由。

Go `config/config.go::parseTun` 会从 DNS fake-IP 地址取主机部分并建立 `/30` 接口地址，默认是 `198.18.0.1/30`；即使 DNS 为 redir-host、auto-route 为 false，也会生成内核直连路由。旧 Rust 对未显式配置 inet4-address 的顶层 TUN 留空，接口虽 UP，地址和主路由为空，OpenClash 因而一直等待并重启核心。

`openclash-tun-before.json` 使用上一版内核及相同 TUN 参数复现了接口 UP、IPv4 地址空、路由空、OpenClash 判定 false；也复现了关闭探测连接产生的 `failed to fill whole buffer`。修复在构建顶层 TUN 运行计划时补齐默认地址，保留显式地址，并从自定义 fake-IP 地址导出相应 `/30`。内核会输出 `[TUN] interface utun started ipv4=... auto-route=false`。

Huber 报错来自模型加载器只接受 regression。Huber 改变训练损失，推理仍为回归树叶值求和；现在接受 `objective=huber` 及其参数，继续执行特征缩放和模型校验。验证使用原生 LightGBM 4.6.0 训练的固定 Huber 夹具；带/不带 StandardScaler 各 160 组预测与原生实现完全一致。

HTTP/SOCKS/mixed 客户端在握手完成前断开会记录 Debug。真实上游连接/转发失败、完整但畸形的请求继续记录 Error，并附带协议、监听地址及客户端地址。该分类由结构化错误类型判定，未把相同文字的上游截断一并降级。

## 验证

所有构建和运行验证均在 Docker 内执行；测试过程中使用隔离 Linux 网络、真实 TUN fd、真实 TCP/UDP socket、SO_MARK 和 SOCKS5 fixture。测试认证信息为固定夹具，不使用用户凭据。

| 检查 | 结果 |
| --- | --- |
| 运行时完整单元测试 | 382 通过，1 项需要外部 MMDB 夹具的测试 ignored |
| TUN 单元 | 9 / 9 |
| API 单元 | 65 / 65 |
| 应用 TUN / DNS / 重载 | 38 / 11 / 2 通过 |
| CLI TUN 支持检查 | 31 / 31 |
| 最终 ARM64：OpenClash 同配置 TUN | 19 / 19 |
| 最终 ARM64：UI/API/DNS | 55 / 55 |
| 最终 ARM64：Huber 模型完整 Smart 流程 | 39 / 39 |
| 最终 ARM64：高级 Smart | 62 / 62 |
| 最终 ARM64：eBPF | 39 / 39 |
| Huber 原生数值对照 | 320 组，最大误差 0 |
| 原发布 regression 模型对照 | 160 组，最大误差 0 |
| 原有 TUN 代理转发和 fake-IP 脚本 | 均通过；fake-IP 首个地址为 198.18.0.4 |

TUN 的 19 项验证包含 OpenClash 原检查条件、默认/自定义地址、保持插件管理策略路由、标记 TCP 和 UDP 经 TUN 转发、原始目的地址、关闭清理、探测连接无 Error 刷屏、畸形请求仍报错，以及真实上游截断仍返回 502 并记录错误。最终 TUN、高级 Smart JSON 记录了交付二进制 SHA-256。

现有路由生成测试按实际 `ip rule add` 语法、DNS 规则和过滤器跳转位置核对；mixed 多缺口测试按当前 auto-route/auto-redirect 条件核对。这些是与当前实现一致的断言修正。

## 复现和边界

- `scripts/openclash-tun-smoke.py --core <core> --output <json>`：在具有 /dev/net/tun、CAP_NET_ADMIN、iproute2 的隔离 Linux 容器执行。
- `scripts/smart-huber-model-fixtures.py --base-model <Model.bin> --output-dir <dir>`：使用 LightGBM 4.6.0 生成固定 Huber 夹具。
- `scripts/smart-model-verify.py --model <model> --rust <smart-model example> --output <json>`：原生与 Rust 各 160 组推理比较。

OpenClash 脚本原文摘录及版本见 `openclash-reference.json`，构建命令、源码与产物校验值见 `manifest.json`。`openclash-huber-models/` 包含公开训练夹具与生成参数。保留先前内核文件及工作区已有整理，没有修改路由器配置或发布远端版本。

本轮验证覆盖与 OpenClash 相同的就绪条件和真实 Linux 数据转发，未代替 OpenWrt/LuCI 真机运行、用户实际 Model.bin 或真实节点网络复测；也不宣称所有 TUN stack 语义与 Go 完全相同。
