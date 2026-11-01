# Rust 核心与 Mihomo / OpenClash 兼容性核对（2026-11-01）

本轮确认了多项控制平面兼容问题，并修复面板连接、节点类型识别、配置更新、DNS 代理解析中的阻断。测试证明指定范围内的功能可用；这份 Rust 核心仍不是官方 Go 核心的完整等价替代品。

最终验证：API / 配置 / DNS 的 **130 项单元测试**、应用层 **11 项 DNS 集成测试**、**2 项配置重载测试**、最终 ARM64 文件的 **55 项运行验收**及 **6 项启动参数检查**全部通过；官方参照也通过对应的 55 项检查。真实面板验证了连接、节点切换、模式修改，以及对最终交付文件重载配置后的继续访问。构建与逐项结果见 `diagnostics/ui-api-compat-20261101/`，截图见 `output/playwright/ui-api-compat-20261101/config-after-reload.png`。

产物为 `bin/mihomo-rust-openwrt-arm64-ui-api-fix`（25,135,888 字节，静态链接、已 strip），同时提供 `.gz` 与 `.sha256`。二进制 SHA-256：`3e2367d7dac7af571793f66b352dfada0b0155c0c622611401d6f176039cde23`。源码校验记录在 `manifest.json`；版本号仍为 `0.1.0`，请使用此校验值区分旧构建。

核对来源：

- [官方 API 指南](https://wiki.metacubex.one/api/)、[通用配置](https://wiki.metacubex.one/config/general/)、[DNS 配置](https://wiki.metacubex.one/config/dns/)。Meta-Docs 固定版本为 `2a6ba6b04a9eecdbe5c88c4e4a09776659c0878b`，已保存原始 Markdown 至 `diagnostics/ui-api-compat-20261101/official-*-guide.md`。
- 官方 Docker 核心：`metacubex/mihomo@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c`；实际版本 `v1.19.33 linux arm64`。
- OpenClash 固定版本 `e553e82e01c697aefbe1555261a503f425e00ccd`。检查了启动脚本、`yml_change.sh`、LuCI 控制器的实际调用，而非仅依赖 API 清单。
- 本仓库 Go 实现：`main_legacy.go`、`hub/route/`、`constant/`、`component/updater/update_ui.go`。
- 真实面板：MetaCubeXD `v1.273.1`，构建分支提交 `28a9589f6239bbafc24e87bbf5e5b4997fe42e59`。

| 核对项目 | 本轮前的差异 | 当前行为 / 验证边界 |
| --- | --- | --- |
| OpenClash 启动 | 使用 `clash_meta -d DIR -f CONFIG` | 保持支持；最终产物为静态 ARM64 ELF |
| Go 风格参数 | 仅支持单横线、分离的参数值 | 补充双横线、`-flag=value`、布尔显式值、帮助输出 |
| 环境变量 | 忽略 `CLASH_HOME_DIR`、配置及控制器覆盖变量 | 补充官方 `CLASH_*` 默认值，显式 CLI 参数优先 |
| 数据目录 | 单独指定 `-f` 会把数据目录改成配置文件父目录 | 改为官方的 HOME / USERPROFILE、XDG 与 `-d` 规则 |
| `-t` | 只完成配置 / 注册表检查，规则和 DNS 错误可能延后暴露 | 增加完整规则及 DNS 运行时构建校验 |
| `/version` | `meta` 为字符串 | 改为布尔值 `true`；版本保留 Rust 项目自身版本 |
| `/proxies`、`/group` | 类型为 `select`、`url-test`、`ss` 等 YAML 写法 | 改为 `Selector`、`URLTest`、`Shadowsocks` 等官方 API 名称 |
| 代理组公共字段 | 缺少存活、历史、UDP 等信息 | 补充公共字段；UDP 能力跟随所选成员；Selector 不再误报 `fixed` |
| `/rules` 与连接规则名称 | 暴露配置中的大写连字符名称 | 按 Go 的 `RuleType.String()` 序列化为 `DomainSuffix`、`Match` 等 |
| `/configs` 的 TUN 信息 | 没有 `enable` 字段 | 补充 `enable`；面板可读到实际开关 |
| CORS / 私有网络预检 | 缺失 | 普通响应、鉴权失败、HTTP 流及预检均添加 CORS；支持配置允许来源与私有网络选项 |
| 控制器鉴权 | Bearer 与 WebSocket token 已有实现 | 保留并复测；Unix socket 与官方一样不要求 Bearer |
| 外部 UI 文件 | `/ui/name/` 读取目录会报错 | 支持目录重定向与 `index.html`；限制路径越界；真实面板可加载 |
| `external-ui-name` | 易被误认为应该修改静态根目录 | 静态根仍为 `external-ui`；`name` 对应其下的面板目录，与 OpenClash 布局一致 |
| OpenClash 修改日志级别 | `PATCH /configs` 只接收 `mode` | 支持日志级别；改变实际日志过滤与 API 快照 |
| 修改监听配置 | 没有实现完整应用流程 | 支持端口、LAN、TUN 等官方配置补丁；先校验再重新绑定；失败时恢复旧配置 |
| OpenClash 重载 | 未实现 `PUT /configs?force=true` | 支持 `path` 与 YAML `payload`；成功后返回 204；错误配置返回错误 |
| SIGHUP 重载 | 启动新监听后才释放旧监听，容易端口冲突 | 复用先校验、释放、重新绑定及失败恢复流程；保留 fake-IP 映射，旧监听重复关闭不会清理新运行时默认网卡 |
| 重载后流连接 | 旧控制器的流可能继续引用旧状态 | 关闭旧 HTTP / WebSocket 流，使面板重连读取新运行时 |
| Windows 控制命令轮询 | 最长可能等待一小时 | 改为 50 ms 轮询；本轮未运行 Windows 实机验证 |
| HTTP 代理与 UDP 入口并存 | 因 HTTP 不支持 UDP 而拒绝启动或尝试 Go 回退 | 允许 HTTP 的 TCP 能力与控制器正常启动；不宣称 HTTP CONNECT 提供 UDP |
| DNS HTTPS（65）记录 | 解析器拒绝未知类型 | 原始报文交给远端上游；支持 HTTPS/SVCB/TXT/PTR 等非地址记录 |
| DNS 传输路由 | 监听与 API 存在使用系统传输绕过代理的路径 | DNS UDP/TCP、API 查询、外部 DoH 共用应用传输；`#代理组` 与 `#RULES` 生效 |
| DNS `respect-rules` | 与 `proxy-server-nameserver` 混淆 | 未设置 respect-rules 的普通上游走 DIRECT；显式代理片段覆盖；设置后按规则路由 |
| DNS 上游主机名 | 直接调用系统地址解析 | 通过 hosts / `default-nameserver` 引导解析；避免把一般 nameserver 当作引导递归使用 |
| DNS 锁 | 网络 I/O 时持有共享解析器锁，存在递归加锁风险 | 本地 hosts / fake-IP 分配使用共享锁，网络查询释放锁后执行 |
| DNS 错误 | 未知记录类型的失败可能伪装为空 NOERROR | 传播上游错误；UDP/TCP 监听返回 SERVFAIL；保留远端 NXDOMAIN |
| DNS 监听协议 | 仅 UDP | 增加同端口的 TCP DNS 服务 |

HTTPS（65）是 DNS 资源记录类型，DoH / DoT 是传输协议，两者独立。查询不会仅因为类型为 65 就自动选用 TLS；实际传输和代理由所选 nameserver、片段参数及 `respect-rules` 决定。测试中的 DoH、DoT 使用可信测试证书，没有关闭证书验证。代理服务记录了实际 CONNECT 连接；还验证了 `respect-rules: false` 的无片段上游不会被 `proxy-server-nameserver` 意外强制代理。

验证入口为 `scripts/ui-api-conformance.py`。它在 Docker 中启动隔离的 DNS / DoH / DoT / HTTP CONNECT 服务，然后对官方与 Rust 执行同类操作。原始结果保存在 `diagnostics/ui-api-compat-20261101/`；其中运行期端口和 fixture-secret 仅属于测试夹具。端口绑定失败时，官方会返回 204 并记录监听错误，Rust 返回错误并恢复旧配置；此项明确按两种实现的实际约定分别验证，不计为相同的行为。官方缓存可能修改 TTL / 标志，因此没有把 Go 与 Rust 的整个 DNS 报文要求为逐字节一致。

真实浏览器验证使用独立来源的面板与 API：面板地址 `http://127.0.0.1:19092/metacubexd/`，API 地址 `http://127.0.0.1:19091`，覆盖了 Bearer + CORS、概览实时数据、中文策略组切换和配置页模式更新。启动前对默认 9090 地址的探测失败属于面板自动发现过程，不是选定后端的 API 错误。重启测试容器期间的连接中断也已与持续错误区分；面板另有一次对自身静态服务器 `/api/control/info` 的可选探测返回 404，该请求不发往核心。

仍有下列差异，不能据此宣布完整替换：

- 自动下载缺失的 external-ui、`POST /upgrade/ui`、`POST /configs/geo`、`POST /upgrade/geo` 及核心在线升级尚未实现。管理更新请求明确返回 501；已安装的 UI 静态文件可用。
- Windows named pipe 控制器尚未实现。HTTP / TLS / Unix 控制器有测试；Windows 实机和 OpenWrt 真机没有在本轮代为操作。
- GeoSite / GeoIP DAT 仅有先前实现的有限支持。MMDB 国家 / ASN 查询、复杂嵌套 geodata 引用及自动数据库更新仍不能宣称达到 Go 的能力；用户现有 `country.mmdb`、`asn.mmdb` 文件不等于 Rust 已能正确使用它们。
- `providers/proxies` 当前只提供显式配置的 provider，未合成 Go 的 `default` / `Compatible` provider；部分非必需元数据（如 adapter id、provider 更新时间）也有差异。
- HTTP 流请求显式携带 `Connection: close` 时仍采用单次快照；普通 HTTP 流和 WebSocket 流已经复测。
- DNS 的高级片段选项（ECS、h3、网络接口绑定等）、DHCP / Tailscale 上游，以及原有 DNS 地址缓存与全部官方默认值未完整对齐。本轮覆盖的无附加选项 DoH / DoT / UDP / TCP 路径可用。
- TUN 的 gVisor、ICMP、路由 / 防火墙和真实 OpenWrt 透明转发仍存在此前记录的实现差距；TUN 默认 stack / 自动路由设置也尚未全部对齐；控制器与面板测试不证明这些数据平面能力已对齐。

涉及监听项的 PATCH 及 PUT 会重建运行时并关闭原有连接，尚未达到 Go 的原位更新行为。

后续 [Smart 支持说明](smart-support.md) 记录了独立 Smart 策略组、LightGBM 推理及 Smart API 的新增实现；其中 MMDB 读取仅用于 Smart 元数据，原规则系统兼容边界仍按本文所述。

本轮产物适合继续进行指定范围的 OpenClash 测试，尚不能代替真机验证和上述剩余兼容工作。原有工作区修改保持保留，未提交、推送或部署到路由器。
