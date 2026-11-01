# yacd 规则页修复验证（2026-11-01）

交付：`bin/mihomo-rust-openwrt-arm64-yacd-rules-fix`，静态、stripped AArch64 Linux musl ELF，28,150,568 字节；`.gz` 与 `.sha256` 同目录。

SHA-256：`116fed08e88c8ac1206983df293bab550fcea810162d82b0aa759dc28d1879dc`。

## 根因

用户日志中的核心异常为 `RangeError: Invalid time value`，位置在规则页调用日期格式化函数时。规则页除了 GET /rules，还加载 GET /providers/rules。Go `rules/provider/provider.go` 对规则集返回 updatedAt 字段；旧 Rust `ApiRuleProviderSnapshot` 缺失该字段。

固定 [yacd v0.3.7](https://github.com/MetaCubeX/Yacd-meta/tree/082072fe6cfb4f571b6d9b514ae7af90489b2ce1) 的 `src/components/rules/RuleProviderItem.tsx` 直接调用 `formatDistance(new Date(updatedAt), new Date())`，没有缺值保护。使用旧 ARM64 内核与该版本真实前端在本地浏览器复现了完全相同的 Invalid time value；日期库 bundle `index-84fa0cb3.js` 和偏移 10129 与用户日志一致。用户完整面板 bundle 不同，测试使用固定官方标签重建，而非声称获取了路由器上每个相同哈希的资源。

## 修复

- 规则集列表和单项详情补齐 RFC3339 updatedAt。内联保存加载/成功更新时间，文件使用实际 mtime，HTTP 初始缓存保留缓存时间，成功下载后刷新。未知时间沿用 Go 的 `0001-01-01T00:00:00Z`。
- 时间元数据与规则内容一起保存、克隆和回滚。普通 GET 不产生新的更新时间。离线回退不伪装为新下载。
- 读取 HTTP 缓存时只加载内存，移除此前每次读取又重写缓存文件的行为。
- 新下载的 classical payload 在覆盖缓存前先编译校验；格式合法但规则语义无效的响应不会破坏缓存、数量或更新时间。
- 规则的 hitAt/missAt 继续使用有效 RFC3339；统一格式化并检查整数范围，异常时间使用合法零时间。

## 最终文件验证

| 检查 | 结果 |
| --- | --- |
| API / 运行时单元 | 459 通过，1 项外部 MMDB 夹具测试 ignored |
| 应用控制器 | 13 / 13 |
| **最终 ARM64** 规则集时间/刷新 API | 30 / 30 |
| **最终 ARM64** 通用 Clash API/DNS | 55 / 55 |
| **最终 ARM64** 实时速度 | 64 / 64 |
| **最终 ARM64** 实际 yacd v0.3.7 规则页 | 正常显示，刷新成功，控制台 0 错误 |

30 项规则接口检查覆盖 File/HTTP/Inline、列表与详情一致性、RFC3339、保留原文件和缓存 mtime、重复 GET 稳定、成功刷新、语义错误回滚、离线缓存回退、规则命中/未命中时间及禁用接口。最终 API 和速度实测 JSON 内的 SHA 已与交付文件核对。

Playwright 浏览器验证使用同一份官方 v0.3.7 前端：旧内核进入错误页并出现日期 RangeError；修复后规则集和规则列表正常。再将夹具切到交付的静态 ARM64 文件，重新打开规则页并点击 HTTP 规则集刷新按钮，显示从 1 rule 变为 2 rules、更新时间变为 less than a minute ago。JavaScript Date 对三个规则集时间均得到有限值，控制台 0 错误。

截图：`output/playwright/yacd-rules-20261101/before.png` 和 `fixed-arm64.png`。夹具的文件 mtime 故意固定在 2000 / 2001 年以验证保留实际时间，截图中的旧年份是测试输入；刷新后的 HTTP 时间对应当前时间。浏览器日志见 `browser-before-console.txt`、`browser-fixed-console.txt`。

## 前端与构建复现

前端为官方 tag v0.3.7（commit 082072fe6cfb4f571b6d9b514ae7af90489b2ce1），Docker Node 18、pnpm 7.26.2，按 frozen lockfile 安装。旧锁文件的 r2.cnpmjs.org 镜像证书过期，在隔离副本中将 72 处 tarball 地址改为官方 registry.npmjs.org，保留全部版本与 integrity；没有修改前端组件源码。原始/替换后锁文件、组件和产物 SHA 在 `frontend-reference.json`。

Rust 使用 Docker、rustc 1.88.0，命令、目标及源码/产物 SHA 在 `manifest.json`。API 夹具脚本为 `scripts/yacd-rules-smoke.py`，附 --serve / --ui 可供浏览器复现；只用本地 HTTP 规则源和固定测试鉴权。未复制用户贴出的控制密钥到测试配置或证据。

## 使用与边界

现有 yacd 面板无需替换，更新内核并刷新规则页即可。此次验证发生在本地隔离 Docker 和真实浏览器中，未访问用户路由器。保留之前域名分流、TUN、Huber 和实时速度改动；未推送或发布远端版本。
