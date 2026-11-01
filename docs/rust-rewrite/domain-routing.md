# 透明代理域名分流（2026-11-01）

当前 OpenWrt ARM64 文件：`bin/mihomo-rust-openwrt-arm64-traffic-fix`，附 `.gz` 和 `.sha256`，并包含实时速度修复（`docs/rust-rewrite/traffic-statistics.md`）。本次域名修复验证报告位于 `diagnostics/domain-routing-20261101/VERIFICATION.md`。

## 修复的连接路径

此前的真实 DNS 应答转发没有记录 redir-host 的 IP → 原始查询域名映射；元数据预处理只查 fake-IP。`sniffer` 配置已解析、API 也显示已启用，但未接入 TCP/UDP 连接。TCP 连接建立函数又只修改元数据副本，面板仍使用处理前的 IP 和规则信息。这些缺口会让透明连接落到 MATCH。

现在，客户端通过核心查询 DNS 后，A/AAAA、CNAME 后面的地址以及 HTTPS/SVCB 的 IPv4/IPv6 hints 会建立共享的反向映射。映射使用原问题域名、应答 TTL 和 CNAME 链中最短 TTL，容量最多 4096 项；不接受无关 answer、过期记录、失败/截断应答或格式无效的记录。DNS 原始应答的记录、标志和 TTL 继续原样返回。

redir、tproxy 和 TUN 流量会在规则匹配前恢复域名。真实 IP 映射标为 `dnsMode: mapping`，保留原目标 IP 供实际拨号；fake-IP 映射则清除虚拟 IP，让出站按原域名连接。路由后的元数据写回连接对象，`/connections` 的 host、sniffHost、规则和实际代理链与选路使用的数据一致。

## 嗅探

按现有 `sniffer:` 配置启用，不需要新增字段：

- TLS：解析 ClientHello 的明文 SNI，支持 TCP 分段及跨 TLS record 的 ClientHello。
- HTTP：解析 Host、绝对 URL 或 CONNECT authority，支持端口范围。
- QUIC：识别 Initial 的 ClientHello，认证/解密公开初始密钥保护的 CRYPTO 帧，按五元组和 DCID 重组乱序片段。0-RTT 数据不解密；先到的 0-RTT 保留到目标确定后转发。

`parse-pure-ip`、`force-dns-mapping`、`force-domain`、`skip-domain`、`skip-src-address`、`skip-dst-address`、端口白名单及每协议 `override-destination` 均参与判断。`override-destination: false` 时仅使用 sniffHost 匹配规则，继续拨原 IP；true 时按识别出的域名发起连接。skip-domain 会保留已有 DNS 映射，不用被跳过的 SNI 覆盖它。

TCP 嗅探只有一秒整体期限、最多读取 64 KiB；HTTP 头上限 32 KiB，已读内容会逐字节回放，并恢复原读取超时。TUN 的被动 TCP 流也支持此读取期限。QUIC 重组最多保留 64 个候选流，按每流 24 KiB 待转发数据、16 KiB CRYPTO、8 包和三秒阈值控制；超阈值回退，关闭时释放队列。完整转发和乱序行为使用 Go 上游公开抓包验证。

加密的 ECH 内层 SNI不在明文嗅探范围内；仅能使用可见 SNI 或 DNS 映射。绕开核心 DNS、没有可用映射且没有可识别应用域名的连接仍按 IP 规则处理。保留的 Go 抓包主要验证 QUIC v1；代码还识别 v2/draft-29 的盐和标签，未在本轮独立验证所有版本组合。

## UDP 和错误日志

修复了透明 UDP 回复 socket 被永久缓存却没有读取后续入站数据的问题：回复结束后释放该 socket，后续数据继续进入 TProxy 监听器。UDP 转发不再跨 DNS/网络调用持有转发状态锁，目标覆盖后正确恢复客户端看到的原服务器地址。

真实 redir 上游 EOF 仍记录为错误，包含 `proxy`、`chain` 和 `target`，可以定位失败节点。客户端发往 HTTP/SOCKS 的不完整握手与上游故障仍分开记录；不会因文本同为 EOF 而一起降级。

## 验证及使用

最终 ARM64 文件在隔离 Docker 网络中通过 93 项域名路由实测、21 项 OpenClash TUN 实测、55 项 API、39 项 Model-large Smart、62 项高级 Smart 和 39 项 eBPF 检查；相关单元、传输层和应用测试见验证报告。

替换内核后应重新建立连接；旧连接继续沿已选定出口转发。终端已经缓存、且旧核心没有记录的 DNS 答案不会在升级时自动变为域名映射，需要新的 DNS 查询或可用 SNI/Host。现有 sniffer 和 OpenClash 路由配置可以继续使用。未代替用户路由器、真实节点和所有网站的实测。
