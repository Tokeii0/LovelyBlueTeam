# 部署与验收

新增隔离蜜罐独立部署，见 [VPN / UDS 启动与部署](../honeypots/README.md)。它们不读取业务数据或原客户端配置；VPN / UDS 门户分别监听 127.0.0.1:8801 / 8802，Nginx 独立样例为 8811 / 8812。勿与业务代理共用运行数据目录。

## 1. 初始化

运行 `python scripts/bootstrap.py`，它只在文件缺失时从示例创建本地配置，不覆盖既有文件。两应用可运行在 Windows；JSP Cleaner 仅 Windows。Livelog 运行只需 Python 3.10+，正文工作台构建需要 Go 1.25+。生产环境使用仍受维护的工具链版本。

在 `apps/lovelylivelog/.env` 设置自己的 `PANEL_URL`、`PANEL_API_KEY` 与接口前缀。优先使用 HTTPS；限制面板 API 的可访问来源，按平台能力划分只读采集和处置权限。面板时间与采集端时间应同步。

保留 `AI_ANALYSIS_MODE=local`、`AUTO_BLOCK=false`。`AI_ENABLED=true` 表示分析工作线程开启，本地模式不调用外部模型。`IP_ALLOWLIST` 由维护者填入管理出口、CDN/代理及其他可信地址。不要使用仓库测试 IP 作为真实保护名单。

## 2. 启动与停止

```powershell
python apps/lovelylivelog/server.py --no-browser
# 停止本目录实例
python apps/lovelylivelog/server.py --stop
```

编辑 `apps/lovelylog/config.local.json`，将 `log_path` 改为面板主机实际的绝对 post.log 路径。`livelog_env` 相对于配置文件所在目录解析；不要把上一个现场的密钥复制到新环境。源码运行 `go run . -config config.local.json`，或先 `go build -trimpath -o LovelyLog.exe .` 再用启动脚本。Ctrl+C 正常退出并落盘。

## 3. Agent 与设备

默认接收器只监听 127.0.0.1:8788。同机 Nginx 可用 [Agent TLS 示例](../configs/nginx/examples/agent-tls.conf.example) 转发到它，并填写可达的 `AGENT_PUBLIC_URL`。Nginx 在另一台机器时，应绑定专用管理网地址并通过主机防火墙仅允许代理入口访问。不要直接将无 TLS 的采集端口暴露到公网。

在 Livelog 页面登记独立服务器与日志路径，生成每台 Agent 的独立令牌。源码代理可运行 `python agent.py --config config.json`；需要 Windows 单文件包时按模块说明构建。验收断网队列、重连补传、轮转、跨日和重复请求计数。线上生成的代理包含凭据，只供目标主机使用，不进入发布包。

Syslog 按页面指定设备来源、协议和端口配置；只接收授权管理网设备。AF 与消息推送默认关闭，先测试连接再启用；同步删除能力默认关闭，不操作其他系统创建的规则。特殊“访问即加黑”规则仅用于 `SITE_RULE_DOMAIN` 指定的无业务诱饵站点，默认关闭，禁止用于正常业务门户。

## 4. Nginx / Tomcat

具体风险、配置文件、验证标准及回滚步骤见[缓解措施手册](mitigation-guide.md)。

通用 Nginx 主配置是本机测试入口，部署生产 TLS 需填写证书、站点和后端地址并执行 `nginx -t`。不要替换现有整份配置；先备份，再合并对应 http/server/location 上下文。OpenResty Lua 需要兼容运行时；已有 `rewrite_by_lua_block` 时将调用合并进同一块，避免 location 层覆盖继承。Tomcat 规则先在单独上传应用验证。

## 5. 切换模型与处置

DeepSeek 模型接入、AI Agent 自动执行风险和 Computer Use 演练说明见 [AI Agent 工作流](ai-agent-workflows.md)。

仅在核对送审数据、模型连接和成本后设置 AI 提供方、模型名与密钥，再将模式切为 `ai`。自动封禁单独打开，先观察人工结果；验证置信阈值、请求证据时间窗、至少两条近期证据、白名单及误封解除。不要通过修改系统时间或复写日志日期让历史数据触发实时处置。

## 6. 验收表

| 检查项 | 通过标准 |
| --- | --- |
| 管理入口 | 8787/8790 只在本机可用，跨源请求被拒绝 |
| 数据链路 | 计数、断点、原始时间、轮转与离线队列符合预期 |
| 本地模式 | 模型调用计数不增长，不自动新增 WAF / AF 规则 |
| 解析与脱敏 | 已知合成正文可还原，未知密文保留限制，送审预览无敏感值 |
| 防护规则 | 正常上传、登录、回调、预检正常；恶意路径被阻断 |
| 运维 | 磁盘阈值、备份恢复、退出重启、配置回滚和人员交接已演练 |

不在本次源码整理中对接或修改真实面板、Nginx、AF、防火墙及生产服务。
