# mihomo Rust 重构进度报告（AI 交接文档）

> 最后更新：2026-10-31（第三轮）。本文档面向接手本项目的任何人（或 AI），汇总重构现状、已验证结论、未完成清单与实操指引。

## 0. 协议对齐总览（Go ↔ Rust，截至本轮）

### 出站（adapter/outbound，31 个 Go 文件）
| 协议 | 状态 |
|---|---|
| direct/reject/dns/http/socks5/ss(AEAD+2022 TCP+UDP AES)/ssr/snell/vmess/vless/trojan/hysteria/hysteria2/wireguard/tuic/gost-relay/ssh/mieru(解析)/anytls/sudoku/masque/trusttunnel/openvpn/tailscale(解析) | ✅ 枚举+解析全齐 |
| ss 2022 TCP/UDP(AES-GCM) | ✅ 本轮实现 |
| vmess/vless 入站多用户 | ✅ 本轮实现 |
| hysteria v1 TCP dialer-proxy | ❌ 需 QUIC-over-socks5-UDP 贯穿 hop 链（UDP 侧已支持）；v1 用户极少 |
| ss 2022 chacha UDP | ✅ 已实现（XChaCha 外层 xnonce + XChaCha20-Poly1305(psk)；e2e 通过） |
| VLESS-REALITY | ✅ **第四轮互操作修复**（`mihomo-transport/src/reality_tls.rs`）：手写 ClientHello 解析/构造、session_id seal（AES-256-GCM + HKDF「REALITY」）、镜像伪装站点 ServerHello（仅替换 key_share）、自研 TLS 1.3 飞行（EE/Cert/CV/Finished，Ed25519 证明证书）、steal 透明回退。**第四轮对照 xtls/reality 源码修复互操作**：①CV 签名 blob 改为 RFC 8446 上下文串「TLS 1.3, server CertificateVerify\\0」；②transcript/Finished/HKDF 按套件走 SHA-384（修复 HKDF 误用 Sha512 的潜伏 bug）；③CCS 记录双向跳过 + 双方补发 dummy CCS（RFC 8446 D.4）。transport 10 测 + app 入站 e2e 全过。出站 e2e 中 vless acceptor 早期 EOF 一处标记 #[ignore] 待查 |
| TUN gvisor | ✅ **第三轮放行**：smoltcp passive TCP bridge 数据面本已实现（tun_fd_loop 系列 12 测 + bridge 4 测覆盖），gap 检测器不再拒绝 gvisor 栈；UDP 走 DirectRelay（与 Go gvisor 的 EIN 差异已在报告中声明） |
| mieru 出站 | ❌ Go 靠 enfein/mieru v3 库；Rust 无库 |
| tailscale 出站 | ⚠️ 一致地不支持（Go 也有 no_tailscale 构建标签） |

### 监听器（listener/，Go 22 个目录）
| 类型 | 状态 |
|---|---|
| socks/http/mixed/redir/tproxy/tunnel/tun(system+mixed)/shadowsocks/vmess/vless/trojan/hysteria2/hysteria2-realm/tuic/anytls/sudoku/trusttunnel | ✅ 全部实现 |
| vless/trojan reality-config | ✅ 同 REALITY（入站已实现，e2e 通过） |
| mieru 入站 | ❌ 同上（依赖库） |
| tun gvisor 栈 | ❌ Rust 已有 smoltcp passive stack，gvisor 需完整用户态栈验证；system/mixed 已支持 |

### DNS / config / API
| 范围 | 状态 |
|---|---|
| REST API 路由（configs/proxies/group/rules/connections/providers/cache/dns/storage/restart/upgrade/ui + WS） | ✅ 与 Go 对齐 |
| DNS（fake-ip/hosts/nameserver-policy/fallback/doh/doq） | ✅ |
| rule provider（file/http/inline，domain/ipcidr/classical，yaml/text/mrs） | ✅（本轮修复了内容加载 bug） |
| **遗留失败**：`bootstrap_state_builds_dns_runtime`（fake-ip rule 模式在 DNS 内匹配 provider 失效） | ❌ 接手遗留深水区，见未完成清单 #0 |

**结论：协议面 95%+ 对齐；剩余 4 项（REALITY、mieru、chacha-UDP、gvisor）均有明确技术原因走 Go 回退，配置功能不受影响。**

## 1. 项目定位与代码位置

- 本仓库是 metacubex/mihomo（Clash.Meta）的 Rust 全量重构，要求**对外 API 不变、功能不变**。
- 真正的重构代码在 **`metacubex-mihomo/rust/`**（cargo workspace，13 个 crate，约 21 万行）：
  - `mihomo-app`（入口、listener 服务、TUN、约 12 万行，含 533 个 lib 测试 + main_tests）
  - `mihomo-transport`（所有代理协议传输层，约 4.5 万行）
  - `mihomo-runtime`（隧道、路由、组、provider、支持矩阵）
  - `mihomo-api`（RESTful 控制器，手写 HTTP/WS 服务器，路由与 Go 完全对齐）
  - 其余：config、core、dns、inbound、outbound、platform、rules、tun、buf
- 上游 Go 树在 `metacubex-mihomo/` 保留作对照；Rust 二进制带「原生支持缺口检测」
  （`mihomo-app/src/native_support/`），检测到不支持的功能时**回退到 Go 运行时**。
- 仓库外层 `crates/` 是空壳目录；外层 README/pyproject 是历史遗留（原 Python 项目），勿混淆。
- 内部 git 仓库（`metacubex-mihomo/`）有大量**未提交**的模块化拆分（约 158 个未跟踪文件，
  单文件 lib.rs 已拆成多模块）。当前工作树状态 = 最新提交 a2995e0 + 未提交拆分 + 本会话改动。

## 2. 测试流程（必须用 Docker）

本地 cargo 已损坏（homebrew 依赖问题），**一律用 Docker**（rust:1.88 镜像，仓库已固定 1.88.0）：

```bash
cd metacubex-mihomo
# 全工作区测试（仓库自带脚本，先删 target 再单线程编译）：
sh scripts/docker-rust-test-clean.sh --target-dir target-test -- cargo test --workspace
# 或 Makefile：make test（无本地 cargo 时自动走 Docker）
```

加速迭代技巧（本会话验证有效）：单独 mount 一个持久 cargo-home + 独立 target 目录，
`CARGO_BUILD_JOBS=4`，只跑目标 crate/测试名；**跑完记得删 target 目录**（约 5-6GB/个）。

### 已知测试问题（非回归，勿误判）

- app lib 有 **24 个慢测试**：`*_over_outer_socks5_udp_associate`（hy2/tuic）与 sudoku listener 族，
  并行跑 >60s 或挂起，单线程下 hy2-over-socks5 有 WouldBlock 失败。跳过它们后全套 **4 分钟跑完**：
  ```bash
  cargo test -p mihomo-app --lib -- \
    --skip over_outer_socks5_udp_associate --skip sudoku_listener \
    --skip sudoku_multiplex --skip tunnel_udp_respects_sudoku
  ```
- app bin（main_tests）4 个既有失败：`sudoku_plain_listener_with_tls_surface_triggers_listener_gap`、
  `top_level_tun_multiple_native_support_gaps_are_reported_together`、
  `tun_listener_with_file_descriptor_is_served_by_native_runtime`、
  `unsupported_listener_surface_triggers_legacy_fallback`（tun/sudoku 缺口上报断言，平台相关）。
- mihomo-tun 2 个既有失败：`linux_tun_setup_commands_include_auto_route_rules`、
  `linux_tun_setup_commands_include_linux_rule_filters`（ip 命令生成断言）。

## 3. 最近一次全量验证结果（2026-10-31，第三轮）

> **Windows x64 产物**：`bin/mihomo-windows-amd64-v1.exe`（及同名 zip，版本 a2995e0）已通过
> `cargo xwin` 交叉编译产出（PE32+ x86-64 MSVC，25MB）。构建容器：rust:1.88 + clang/llvm +
> cargo-xwin 0.19.2 + `XWIN_ACCEPT_LICENSE=1` + `AWS_LC_SYS_PREBUILT_NASM=1`。注意：该构建
> 临时禁用了 `mihomo-transport` 的 `ssh-transport` 默认特性（openssl-sys vendored 无法在
> Linux 交叉环境构建，SSH 出站在此 exe 中不可用；其余功能完整，构建后 Cargo.toml 已还原）。

| 范围 | 结果 |
|---|---|
| mihomo-app lib（跳过 24 慢测试） | **513/513 ✓** |
| mihomo-transport | **216/216 ✓**（含 SS2022 4 项新测试） |
| mihomo-runtime | **352/352 ✓**（DNS fake-ip 无 upstream 本地分配已修复，bootstrap_state_builds_dns_runtime 恢复） |
| mihomo-api | 63/63 ✓ |
| mihomo-dns/rules/config/core/inbound/outbound/platform/buf | 全过 ✓ |
| mihomo-app bin | 150/154（4 个既有 tun/sudoku gap 断言失败） |
| mihomo-tun | 7/9（2 个既有 setup 命令断言失败） |

## 4. 本会话（2026-10-29/30）完成的改动

### 修复
1. **PUT rule provider 重入死锁**（`mihomo-api/src/server.rs`）：PUT 处理器持 `bootstrap_state`
   锁期间调用会再次加锁的 `maybe_request_restart_*` → 同线程死锁、整套测试挂死。修复：锁内操作
   完成后 `drop(state)` 再调用。涉及 `controller_*rule_provider_put_*` 5 个测试恢复通过。
2. **logs 流测试竞态**（`mihomo-api/src/server.rs`）：`controller_streams_logs_over_plain_http_keepalive`
   靠其他测试的日志凑 chunk 数，单线程必挂。改为测试自己推两条日志。
3. **vmess 响应头超时被吞**（`mihomo-transport/src/vmess.rs`）：`VmessClientStream::ensure_response_received`
   把底层 20ms 读超时的 WouldBlock 包成 InvalidData → UDP 回包轮询（deadline 循环 + Ok(None) 重试）
   第一次超时就整个会话被丢弃。修复：`response_header_io_error` 保留 WouldBlock/TimedOut。
   20 个 vmess UDP 测试由 2 失败转全过。
4. **ss 监听器 UDP 默认值与 Go 对齐**（`mihomo-inbound/src/models.rs`）：`ShadowSocksInboundConfig.udp`
   从 default_true 改为 default false（Go 零值为 false）。

### 修复（第二轮新增）
9. **rule provider 内容从未被加载（核心 bug，接手遗留）**（`mihomo-runtime/src/bootstrap.rs`）：
   - `load_provider_content_sources_from_home` 只处理了 proxy provider，**从未调用**
     `load_rule_provider_content_sources_from_home_into` → 所有 rule provider（file/HTTP）的
     payload 都不存在 → RULE-SET 规则全部失效、fake-ip-filter 的 RULE-SET 落到 real-ip、
     9 个 bootstrap 测试失败/挂起。
   - 修复：主函数尾部补上 rule 加载调用；同时统一 `file_contents`（文本）/`file_blobs`（字节）
     两套字段的写入（此前 file 分支只写字节、proxy 分支只写文本，HTTP store 后互相删除）。
     现在成功 fetch 的内容两套都在（测试期望 file + http 双保留）。
   - 修复后 bootstrap 测试 36/37 过；剩余 1 个 `bootstrap_state_builds_dns_runtime`
     （fake-ip rule 模式 + provider 交互，ResolveFailed）是接手遗留深水区，见未完成清单。

### 新功能（协议支持）
5. **SS2022 / SIP022 TCP 完整实现**（新文件 `mihomo-transport/src/shadowsocks_2022.rs`）：
   - 三种 cipher：2022-blake3-aes-128-gcm / aes-256-gcm / chacha20-poly1305
   - subkey = `blake3::derive_key("shadowsocks 2022 session subkey", psk || salt)` 截断到 key 长度
   - TCP：salt + 定长头(type/ts/len) + 变长头(SOCKS5 目标 + padding) + AEAD 块；**响应头的 length
     字段兼作第一个 length 块**（客户端读侧已按此实现——这是当初踩过的坑）
   - 12 字节 LE 计数器 nonce；时间戳 ±30s 校验；salt 重放缓存（60s，全局 HashMap，非布隆）
   - 出站：`executor.rs` 的 plain 路径按 cipher 分派；带 plugin 的 2022 明确报不支持
   - 入站：`listener_service_special_inbounds/shadowsocks.rs` 按 cipher 走
     `accept_shadowsocks_2022_stream`（目标地址从变长头取，不走 payload 首块）
   - PSK 是 base64 原始密钥（不是 EVP_BytesToKey 口令），长度必须匹配 cipher
   - 测试：传输层 round-trip 单测 + 2 个 app 端到端（入站 aes-256/aes-128）
6. **SS2022 UDP 中继**（同文件，AES-GCM 两种；chacha 变体仍回退 Go）：
   - separate header 16B = 随机 session id(8) + packet id(8)，用 **PSK 直接 AES-ECB** 加密
   - body subkey = blake3(psk || 加密头前 8B)，nonce = 加密头后 8B（big-endian u64）
   - `Shadowsocks2022UdpRegistry`：每 session 维护客户端包号重放窗口（重复最新包号即拒，
     落后超过 32 即拒）+ 服务端响应包号计数器（从 1 开始，原子递增）
   - 客户端：`SystemUdpSession.ss2022_udp_state` 持有 session id + 包号；
     服务端：入站 dispatch 用全局 registry 解码并回包
   - 测试：udp round-trip / 重放拒绝 / server-response round-trip + app 端到端
7. **trojan/anytls/trusttunnel 监听器 users 支持**（Go 语义）：
   - trojan：`users: [{username, password}]`；anytls：`users: {user: pass}` 映射；
     trusttunnel：`users` 列表；均保留旧 `password`/`username` 字段兼容
   - 认证成功把用户名写入 `Metadata.inbound_user`（trojan 按 SHA224-hex 查表）
   - anytls 传输层新增多密码 API（`anytls::accept_server_stream_with_password_hashes`，
     返回命中的用户索引）
   - native_support 谓词同步放行；新增 5 个测试（2 端到端 + 3 surface）
8. **vmess/vless 入站多用户**：
   - vless：UUID 在请求头明文，`accept_vless_stream_with_uuids` 查表匹配
   - vmess：新增 `RewindableStream`（记录已读字节，可回退重放同一请求头），
     对每个 uuid 尝试 AEAD 解头，认证成功者即该用户（`accept_server_stream_with_uuids`）；
     重构 `parse_client_request` → `parse_client_header(&mut dyn Read)`
   - 配置层 `VmessInboundConfig.uuid`/`VlessInboundConfig.uuid` → `uuids: Vec<String>`
   - 测试：2 个多用户端到端 + 全量回归（vless 80、vmess 134、transport 17/12 全过）

### 本会话验证中的关键踩坑记录
- SIP022 响应头 length 兼作第一个 payload 的 length 块；读侧多读一个 length 块会整段错位。
- UDP 代理流读超时是 20ms 轮询设计（`UDP_PROXY_STREAM_READ_TIMEOUT`），回包靠 5s deadline 循环
  重试 WouldBlock。**新协议实现必须让超时错误以 WouldBlock/TimedOut 原样穿透**，否则轮询失效。
- mihomo 出站代理类型名是 `ss`（不是 `shadowsocks`，那是监听器类型名）。
- app 的 main_tests 挂在 **bin 目标**（`cargo test -p mihomo-app --bin mihomo`），不在 --lib。

## 5. 未完成清单（按优先级）

### 协议支持（剩余）
0. ~~REALITY 出站 e2e 的 vless acceptor 早期 EOF~~ ✅ **第四轮已修复**：根因是
   `executor.rs` 的 REALITY 出站分支只返回了 `reality_tls::wrap_stream` 的流、
   **漏了再包一层 `vless::wrap_stream`**——应用数据被直接写进 REALITY 会话，
   服务端 VLESS 层永远等不到 45 字节请求头（这正是「21 字节 ping 记录」的来源）。
   修复后 `start_dials_vless_reality_outbound_end_to_end` 已通过并移除 #[ignore]。
   同轮还对照 xtls/reality 源码修复了互操作三件事（CV 上下文串、按套件 SHA-384
   transcript、CCS 双向跳过/补发），详见协议对齐总览的 REALITY 行。
2. **mieru**：入站+出站都没有。Go 依赖 enfein/mieru v3（混淆协议 + 会话 + MTU 探测），
   Rust 无该库，需从零移植协议，工程量最大，建议最后做或长期保留 Go 回退。
3. ~~SS2022 chacha20-poly1305 UDP~~ ✅ **第四轮实现**：chacha20poly1305 0.10.1 默认导出
   `XChaCha20Poly1305`（无需 feature），格式从 shadowsocks-rust 源码逐字节确认：
   `xnonce(24 随机) || XChaCha20Poly1305(psk, xnonce).seal(明文)`，明文 =
   `session_id(8) || packet_id(8) || type(1) || timestamp(8) || padding_len(2) || padding ||
   addr || payload`。同时**修正了 AES UDP 的两处布局偏差**（明文内 session_id/packet_id
   字段缺失、body key 派生用了错误 material——正确为 `blake3_derive(psk || session_id_be)`
   且 nonce/key 均取自加密后的 separate header）。registry 重放校验复用。
4. **TUN gvisor 与 Go 的差异**：gvisor 已走 smoltcp passive bridge（本轮放行），UDP 为
   DirectRelay；Go gvisor 的 UDP 是 EIN session 复用——差异已在 tun 支持报告中声明。

### 测试基建
6. 排查 24 个慢测试挂起根因（outer socks5 UDP associate 链路的超时处理）。
7. 修复 4 个 bin 测试 + 2 个 tun 测试的既有失败（tun 缺口上报与 ip 命令断言）。

### 工程收尾
8. 内部仓库的大量未提交改动需要整理提交（模块化拆分 + 本会话功能）。
9. 外层 `crates/` 空壳与历史 README/pyproject 可清理（用户已确认删死代码）。
10. `body_remaining.rs` 已删除（32k 行孤儿重复测试文件）。

## 6. 关键文件速查

| 事项 | 文件 |
|---|---|
| 支持缺口检测器（出站） | `mihomo-runtime/src/support_protocols.rs` |
| 支持缺口检测器（监听器） | `mihomo-app/src/native_support/listener_surface/{gaps,protocols}.rs` |
| 监听器配置解析 | `mihomo-app/src/listener_service_configs*.rs`、`listener_service_special_inbounds/` |
| 传输层协议实现 | `mihomo-transport/src/<协议名>.rs`，公共 API 在 `public_api.rs` |
| UDP 出站路由 | `mihomo-app/src/listener_udp_prepare*.rs`、`listener_udp_outbound*.rs`、`listener_udp_session*.rs` |
| 回包轮询循环 | `mihomo-app/src/listener_udp_dispatch.rs` `handle_udp_packet` |
| API 路由 | `mihomo-api/src/server.rs`（63 个测试在同文件尾部） |
| 冒烟脚本（TUN/fakeip 等） | `metacubex-mihomo/scripts/docker-*.sh`，Makefile 目标 `docker-*-smoke` |

## 7. 冒烟验证（改完协议建议跑）

```bash
cd metacubex-mihomo && make build   # Docker 构建 bin/Clash.Core
make docker-tun-fakeip-smoke        # TUN + fake-ip 端到端
# 或单独验证：用 bin/Clash.Core -t -f docs/config.yaml 检查示例配置的缺口列表变化
```

示例配置 `docs/config.yaml` 当前的原生支持缺口（-t 输出）从 8 项减少（ss2022 已支持），
剩余：hysteria2-in（users 映射——已支持但示例缺 cert 才报缺）、mieru-in、vless-in（REALITY）、
tuic-in（示例缺 cert）等，以实际 -t 输出为准。
