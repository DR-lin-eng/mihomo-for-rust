# REALITY + Vision response version 23 修复（2026-10-31）

`unexpected vless response version 23` 的可复现原因是 REALITY 的 TLS 1.3 解包把空应用记录中的 content type `0x17` 作为 VLESS 数据返回。Xray 会把伪装站点的 session-ticket 记录替换为空应用记录，其解密后的内容是 `17 00 00 ...`：`17` 是内容类型，后续为填充，业务数据为空。旧实现仅删除最后一个字节，使 `17` 进入 VLESS 版本字段。

修复统一按 RFC 8446 §5.2 解析 `content || type || zero padding`，先定位尾部最后一个非零类型字节，再截取前面的业务内容。空应用记录不再返回伪造数据；应用内容末尾的零字节保留；带填充的握手记录和关闭告警同样按类型处理。VLESS 仍严格要求合法版本头，没有添加跳过版本校验的兼容分支。

完整回归另发现 TLS `close_notify` 与业务响应一起到达时，客户端会在消费缓冲数据前返回 EOF。修复为先读尽 rustls 明文缓冲，再报告 EOF，并添加确定性回归测试。

Docker 验证使用 Rust 1.88.0 和官方 Xray 26.10.29：

- 修复前确定性复现了相同的 `unexpected vless response version 23`。
- 完整传输层 238 项测试通过；应用 VLESS 筛选测试通过。
- Xray 12 项场景全部通过：TLS/REALITY 两种外层连接，各覆盖明文 HTTP、内层 TLS 1.2/TLS 1.3、服务端先发数据、UDP、XUDP。
- 每种内层 HTTP 场景校验双向各 512 KiB 的完整数据；Xray 日志确认两种外层连接的双向 Vision `command=2`。
- Windows 修复版通过 Docker 的 release 交叉编译与 PE32+ x86-64 文件头、DLL 导入表校验；未进行 Windows 实机测试。

Windows 产物为 `bin/mihomo-rust-windows-amd64-response23-fix.exe`，目标为 `x86_64-pc-windows-gnu`。同名 ZIP 内为 `mihomo.exe`，SHA256 校验值见同名 `.sha256` 文件。

回归入口：`sh scripts/docker-vision-interop.sh`，默认验证 TLS 和 REALITY 两种连接。通过 `VISION_SECURITY=tls` 或 `VISION_SECURITY=reality` 可选择单种外层连接。结果日志和源文件摘要保存于 `diagnostics/vision-response23-20261031/`。
