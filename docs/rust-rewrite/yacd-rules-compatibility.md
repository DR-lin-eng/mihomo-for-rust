# yacd 规则页兼容（2026-11-01）

当前 OpenWrt ARM64 内核为 `bin/mihomo-rust-openwrt-arm64-yacd-rules-fix`，附 `.gz` 和 `.sha256`。验证报告见 `diagnostics/yacd-rules-20261101/VERIFICATION.md`。

规则页会同时请求 `/rules` 和 `/providers/rules`。yacd v0.3.7 的规则集卡片直接执行 `formatDistance(new Date(updatedAt), new Date())`。此前规则集接口缺少 `updatedAt`，导致浏览器抛出 `RangeError: Invalid time value` 并显示错误页。

现在规则集列表和单项详情都包含 RFC3339 的 `updatedAt`：

- 内联规则集使用加载及成功刷新时间。
- 文件规则集使用实际文件修改时间。
- 从本地缓存加载的 HTTP 规则集保留缓存时间；成功下载刷新后更新。
- 未知时间使用 Go 的零时间 `0001-01-01T00:00:00Z`，不会返回空字符串、缺失字段或毫秒数字。

读取 HTTP 缓存只加载到内存，不再重写文件；普通 API 查询不会改变更新时间。离线回退保持原缓存和时间。新的 classical 规则内容在覆盖缓存前编译校验，语义错误的刷新不会覆盖正在使用的缓存。

独立构建官方 yacd v0.3.7，用旧内核复现了同样的日期异常；最终 ARM64 文件能正常显示规则页、更新时间，并通过按钮刷新规则集。浏览器控制台零错误，另有规则集 API 30 项、通用 API 55 项和实时速度 64 项回归通过。截图保存在 `output/playwright/yacd-rules-20261101/`。

现有 yacd 面板可以继续使用。替换内核后刷新页面即可，本轮未修改用户路由器或面板文件。
