# REALITY / sing-box 兼容性跟进

本轮根据真实节点的 `server did not send a ServerHello` 和 `truncated vless response` 反馈，增加了旧版与新版 sing-box 的独立 Docker 互通验证。没有获取或连接报告中的三个失败节点，因此下面结论仅限可复现场景，真实节点仍需替换新版本复测。

## 已验证并修复的问题

- 旧版 REALITY 要求首个 ClientHello TLS 记录使用 `03 01`。此前 Rust 使用 `03 03`，sing-box 1.11.0 的旧实现会走伪装站点回退，无法完成 REALITY 认证。现在首个记录采用浏览器常见的 `03 01`；ClientHello 自身的 legacy_version 仍为 `03 03`，协商仍为 TLS 1.3。
- REALITY 不再固定仅提供 `h2`。未配置 ALPN 时使用 `h2,http/1.1`，配置值传入 TCP 和 UDP 握手。独立 rustls 服务端在修复前复现了 `NoApplicationProtocol`，修复后 HTTP/1.1 伪装站点互通通过。
- `support-x25519mlkem768` 现在实际控制 supported_groups、key_share 和混合密钥生成，默认关闭以对齐 Go 版的旧服务端兼容行为。测试中 Xray 26.10.29 使用开启模式，sing-box 1.14.4 开关两种模式均通过，sing-box 1.11.0 验证关闭模式。
- Vision UDP 默认使用 XUDP，与 Go 版一致。修复前 sing-box 对普通 UDP 请求报告 `flow mismatch: expected xtls-rprx-vision, but got none`，现在默认配置与显式 XUDP 配置均通过。显式 packet-addr/packet-encoding 选择予以保留，其服务端支持仍取决于节点。
- REALITY 复用保留部分 TLS 记录的读取缓冲。读取超时后重试不再丢弃此前收到的记录头或密文。ServerHello 也可跨多个 TLS 记录重组。
- 错误日志会显示 TLS 告警名称、编号与握手阶段；VLESS EOF 会显示已收到和期望的响应头字节数。VLESS 版本和 REALITY 证书证明继续校验。

## Docker 验证

使用 Rust 1.88.0 完成 245 项完整传输层测试、354 项运行时测试，以及 VLESS 筛选的 81 项应用库测试和 11 项二进制测试。

| 服务端 | 客户端密钥组模式 | 伪装站点 ALPN | 通过场景 |
| --- | --- | --- | ---: |
| Xray 26.10.29 | ML-KEM 开启 | h2/http/1.1 | 12 |
| sing-box 1.14.4 | ML-KEM 关闭 | h2/http/1.1 | 12 |
| sing-box 1.14.4 | ML-KEM 开启 | h2/http/1.1 | 12 |
| sing-box 1.14.4 | ML-KEM 关闭 | 仅 http/1.1 | 6 |
| sing-box 1.11.0 | ML-KEM 关闭 | h2/http/1.1 | 12 |

合计 54 个互通场景。场景覆盖 TLS 与 REALITY 外层连接、内层明文 HTTP/TLS 1.2/TLS 1.3、服务端先发、UDP 和 XUDP；每个 HTTP 场景校验双向各 512 KiB 数据完整性。

新版标准回归入口为 `sh scripts/docker-vision-interop.sh`，同时覆盖 Xray 和 sing-box 的两种密钥组模式。独立脚本 `scripts/vision-interop.py` 支持 `--server sing-box --sing-box /path/to/sing-box --mlkem off` 指定旧版服务端，并可用 `--camouflage-alpn http/1.1` 指定伪装站点模式。

Windows 产物为 `bin/mihomo-rust-windows-amd64-reality-compat.exe`，目标 `x86_64-pc-windows-gnu`；同名 ZIP 内为 `mihomo.exe`。已完成 Docker release 交叉编译、PE32+ x86-64 文件头及 DLL 导入表校验，未进行 Windows 实机或原三个节点测试。

版本、测试结果、源码摘要及产物 SHA256 见 `diagnostics/reality-compat-20261031/` 和产物旁的 `.sha256` 文件。
