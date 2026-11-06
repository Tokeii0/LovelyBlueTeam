# 来源与依赖

本仓库整理自本地 LovelyLivelog、LovelyPost、JSP Cleaner 和防护配置。LovelyPost 在此分发版本中显示为 LovelyLog，模块名及相对路径一并调整；原始目录未改名。

当前没有为原始代码补授新的开源许可证。对外公开或再许可时，应由权利人确定许可证；本次交付不声称所有原始材料已经取得第三方再分发授权。

Python 应用使用标准库。LovelyLog 的 Go 依赖与版本见其 go.mod / go.sum；依赖许可以各上游项目为准。未捆绑 Go/Python/Node/Nginx、GeoIP 数据库、抓取的 1Panel 页面脚本或供应商 API 文档副本。

GeoIP 可选数据来自 ip2region 项目，需按其官方说明取得适配数据和许可。本地缺失该数据库只会停用地域标签，不影响核心日志处理。

新增 `honeypots` 整理自本地 VPN 与 UDS Agent 项目。沿用其门户 CSS、界面 HTML、UDS 命令行模拟和部分文档布局；以示例品牌替换原机构/厂商外观文字不代表取得该厂商授权。旧 Windows 宿主及第三方界面依赖不分发，新 Go 模块仅使用标准库。公开发行的授权判断仍由权利人确认。
