# Lovely UDS 离线演示与文档蜜罐

在上级 `honeypots` 目录运行：

```powershell
go run ./uds-agent --help
go run ./uds-agent --help --json
go run ./uds-agent status --json
go run ./uds-agent patient TEST-PATIENT-001 --json
go run ./uds-agent lis TEST-LAB-001 cbc --json
go run ./uds-agent invoke ChannelService.ListAll --json
go run ./uds-agent --config uds-agent/config.example.json list --json
go run ./uds-agent/cmd/portal
```

门户默认 `http://127.0.0.1:8802`，账号/密码都是 `demo`。文档界面复用原项目导航和示例，以合成机构替换原现场信息。门户只有文档与演示认证 API，业务接口由 CLI 离线模拟；补充业务设计文档不代表已实现相应接口。

`status / test / sync / auth / run / conntest` 均为本地模拟；指定目标也不会发起连接。`auth` 的 CLI 输出是 `DEMO-ONLY-` 标记，不能用作门户会话。`patient / lis / invoke` 返回合成对象。`--proxy` 明确拒绝；不自动加载配置，只有显式 `--config` 才读取指定的小型 JSON 文件，且仅允许 `profile=synthetic`。

`diagnose` 会在当前目录生成 ZIP，仅含合成日志、通道和示例环境；`export <文件>` 显式导出合成通道。文件已存在时拒绝覆盖，失败以非零退出码返回。请在工作目录运行这两个命令，避免运行产物进入源码仓库。

门户会话使用随机临时标记，30 分钟过期、注销即失效、上限 256 个。Cookie 设置 HttpOnly / SameSite=Strict；在 HTTPS 反代后启动时加 `-secure-cookies`。HTTP API、页面和访问事件均有大小限制与最小化处理，见[模块说明](../README.md)。

面向 Agent 时可先读取 `--help --json` 发现命令，再在获准范围内执行固定子命令。当前解析器会忽略部分未知参数，帮助和版本不执行模拟；`--json` 不应混用 `--verbose`，解析失败时还需检查 stderr。`ok` 与 `reachable` 等字段描述合成流程，不证明真实网络或业务影响。详细调用契约、执行端记录与对照实验见[AI 渗透测试蜜罐设计](../../docs/ai-pentest-honeypots.md)。
