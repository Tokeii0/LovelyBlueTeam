# Lovely 蓝队蜜罐与离线演练

整合 VPN 与 UDS Agent 两个原项目的门户、界面及接口仿真，组成独立于业务网络的演练模块。两个项目共用一个 Go 模块，全部运行依赖为标准库，最低 Go 1.25。

设计背景见[蜜罐与红队心理学](../docs/honeypot-design.md)。关于 AI Agent 未充分核实就执行命令、触发演练行为的风险，以及 DeepSeek Harness / Computer Use 的角色，见 [AI Agent 工作流](../docs/ai-agent-workflows.md)。门户 HTTP 事件与离线 CLI 执行记录须分别核对。

| 组件 | 启动命令（在本目录） | 默认入口 |
| --- | --- | --- |
| [VPN 门户与连接演示](vpn/README.md) | `go run ./vpn` | `http://127.0.0.1:8801` |
| [UDS 文档门户](uds-agent/README.md) | `go run ./uds-agent/cmd/portal` | `http://127.0.0.1:8802` |
| UDS 离线 CLI | `go run ./uds-agent status --json` | 本地终端 |

门户演示凭据为 `demo / demo`；VPN 连接页的演示工号为 `00000000`、密码 `demo`。这只是合成环境的浏览流程，不是业务账号认证，也不是管理平台。不要输入真实账号。

## 整理范围

VPN 保留原门户的页面布局、连接状态界面和资源导航，将 Windows 原生宿主改为浏览器演示。UDS 保留命令解析、通道清单、患者与检验结果生成、诊断包、配置导出、文档页面；所有命令只使用内置合成数据。`--help`、`--version` 和错误命令没有后台动作。

原项目的截图、桌面文件、账号目录枚举、进程内存读取、宿主档案上传、混淆地址/令牌、弱 JWT 密钥和二进制下载链路没有纳入公开源码。旧 `/api/host`、截图与文件上传协议不可用；旧客户端不能接入公开版。原始二进制、图像、备份、部署包、运行数据和历史重复目录也未复制。

CLI 输出带 `synthetic: true` 或文字提示；姓名为测试患者、身份证为全零、电话为 `TEST-PHONE`，地址为明确的合成文字。文档网段只是显示数据，不作为连接目标。门户不提供可执行文件下载。

## 事件与蓝队流程

服务默认向 stdout 输出 JSONL 事件；启动信息写 stderr。可显式使用 `-events runtime/vpn-events.jsonl` 或 `-events runtime/uds-events.jsonl` 写文件。文件模式不自动轮转，需设置保留周期和磁盘阈值。容器示例使用 Docker 日志轮转。

事件只包含 UTC 时间、组件名、固定路由类别、标准化方法、状态、耗时和 `peer_tag`。来源标签是直接 TCP 对端 IP 的 HMAC 摘要，随机密钥仅存内存，每次重启变化。它仍是内部事件数据；并非可证明匿名的数据，也不能用于人员归因。请求正文、查询串、原始路径、原始 IP、账号、口令、Cookie、UA 和终端信息不写入事件。

服务不信任 `X-Forwarded-For`；经反代时来源标签将聚合为代理地址。需要关联来源时，使用自有 WAF 的受控日志并另行脱敏。按[蜜罐值守手册](../playbooks/honeypot-operations.md)关联时间、路由与边界设备事件。当前事件格式没有额外接入 LovelyLivelog 自动封禁，应先人工研判。

合成事件示例见 [examples/honeypot-events.jsonl](../examples/honeypot-events.jsonl)。事件请求上限为 16 KiB，UDS 演示会话最长 30 分钟、最多 256 个；重启失效。来源头不会改变日志标签。

## 部署

本机启动后直接访问上表回环入口。Nginx 示例是[独立配置](../configs/nginx/honeypots/nginx.conf)，监听 8811/8812 并代理 8801/8802。先在专用运行目录创建 `logs` 和 `temp`，复制配置，再执行 `nginx -p <运行目录>/ -c nginx.conf -t` 和启动命令。不要覆盖正在运行的业务配置。

反代保留包含端口的 Host，供浏览器同源校验；不转发来源伪造头。其访问日志同样不记录账号、正文、查询串或原始 IP。Nginx 运行错误日志仍按内部运维数据管理。[proxy_set_header 官方说明](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)解释了这些请求头设置。

远程部署应使用独立主机/容器、禁止连接业务网段、由边界设备提供 TLS 和访问限制；UDS 在 HTTPS 代理之后加 `-secure-cookies`。当前 HTTP 回环例子不包含生产证书或认证管理功能。

容器示例（需要 Linux 容器引擎）：

```powershell
docker compose -f deploy/compose.yml build
docker compose -f deploy/compose.yml up -d
docker compose -f deploy/compose.yml logs --tail 30
docker compose -f deploy/compose.yml down
```

构建阶段使用 `golang:1.27.3-bookworm`，运行镜像为无 shell 的 `scratch`、非 root 用户、只读根目录；主机端口只绑定回环。构建镜像标签已对照 [Docker 官方 Go 镜像清单](https://github.com/docker-library/official-images/blob/master/library/golang)核对，部署时可用 `GO_IMAGE` 构建参数替换为批准的镜像摘要。本次本机没有容器引擎，容器构建与启动尚需目标环境验收。

## 验证与发布

```powershell
go test ./...
go vet ./...
# 仓库根目录：真实回环进程与 CLI 集成验证
python scripts/test_honeypots.py
python scripts/test_honeypots.py --nginx /path/to/nginx
python scripts/release_scan.py
```

统一验证已覆盖这些 Go 测试和集成脚本。回归测试检查请求/会话边界、日志最小化、旧载荷拒绝和离线输出；不运行旧程序或原始采集代码。生成的日志、诊断 ZIP、导出 JSON 和二进制只应保存在工作目录，不可加回发布源码。
