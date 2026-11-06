本仓库提供代理源码；以下 EXE 操作适用于自行构建并生成的专属代理包。源码也可用 Python 运行。

Windows Nginx / Tomcat 日志代理 v1.1.2（Windows 10/11、Windows Server 2016 及以上，64 位）

1. 在平台的“服务器汇总”中点击“接入服务器”，选择 Nginx 或 Tomcat，填写服务器名称、平台接收地址和真实日志路径，然后下载专属代理包。
2. 解压到该 Windows 服务器，检查 config.json 中的文件路径。支持 * 通配符；路径中推荐使用 /。UTF-8 为默认编码，可改为 gbk / gb18030。
3. 临时运行：双击 run.cmd。无需安装 Python。首次已有文件默认读取最近 200 条，随后只读取新增内容；后续新建的日期文件从开头读取，跨重启保留。
4. 开机运行：先停止 run.cmd 的前台采集，以管理员身份运行 install.cmd。程序与已有读取位置、离线队列复制到 C:\ProgramData\OnePanelLogAgent，通过 Windows 计划任务持续运行，不需要保持登录。安装后编辑该目录下的 config.json；任务更新沿用已安装队列。
5. 停止和移除：以管理员身份运行下载包中的 uninstall.cmd。配置、读取位置和待上传日志会保留。

平台接收端使用 8788 端口，网页仍在平台本机的 8787 端口。代理地址应填写平台服务器可达的 IP / 域名；不能在其他服务器上填 127.0.0.1。按部署网络放通接收端口，或使用 HTTPS 反向代理并填写对应 HTTPS 地址。

重启会沿用读取位置；重复日志不会仅因内容相同而删除。日志轮转时会尝试补读同目录 access.log* / error.log* 中的旧文件。源文件已被删除的未读内容无法恢复。
断网期间继续采集，保存在 runtime\agent.sqlite3；仅收到平台确认后移除待上传记录。队列默认最多 256 MB，满后暂停读取，补传后恢复。runtime\agent.log 保存连接失败信息，不记录接入令牌。

config.json 和专属下载包含这台代理的接入令牌，应只交给对应服务器管理员。令牌只允许上传本代理日志，不能读取平台日志或操作 1Panel / WAF。每台服务器应在平台分别生成自己的包。
程序只采集配置的文本日志，没有远程命令执行功能。服务器汇总独立于 1Panel 网站的 AI 自动加黑流程。

Tomcat 路径示例（按实际安装目录修改；* 自动匹配日期）：
访问日志：D:/tomcat/logs/localhost_access_log.*.txt
运行/错误日志：D:/tomcat/logs/catalina.*.log
其他应用日志：D:/tomcat/logs/localhost.*.log
每个模式跟踪最近修改的 100 个匹配文件。空文件会继续等待新增内容；首次只读取所选行数，并非完整历史导入。运行日志中的普通文本和异常堆栈逐行保留。

按日期 -1 采集（v1.1.0）：适用于按天改名的访问日志，例如 access_2030-01-02.log。
在 config.json 的访问日志来源中填写：
  {"path": "C:/nginx/logs/access_{date}.log", "kind": "access.log", "mode": "daily", "daysAgo": 1}
{date} 按 dateFormat（默认 %Y-%m-%d）替换为“今天 - daysAgo 天”。每天 runAfter（默认 00:30）之后执行一次，完成后记入 runtime/agent.sqlite3，不会重复上传。
Windows 版 Nginx 改名日志后若未 reopen，会一直写入旧文件（例如 01-03 的日志全在 access_2030-01-02.log 末尾）。因此代理不按文件名找日志：同目录下 {date} 匹配的所有日期文件和 access.log 中，自目标日 0 点以来被修改过的都会读取，只保留目标日期 time_local 的记录；大文件先按时间定位到该日开头，读过该日即停止，不会因为旧文件越写越大而变慢。neighbors 设置已不再需要。
清洗：去掉其他日期、静态资源（png/js/css 等）和 OPTIONS 预检；正常请求按 IP + 路径聚合并保留真实次数、首尾时间和首尾原始请求；可疑请求（路径穿越、注入、actuator / swagger / .git 等探测）原样保留不合并。
送 AI：可疑请求、少数客户端才出现的错误请求，以及这些 IP 访问最多的 3 条正常请求作为上下文；其余行上传后仅存档（平台显示“清洗后仅存档”）。另有一行 custom.log 清洗报告。
清洗规则在平台“清洗规则”页维护，代理每次按日清洗前自动下载（平台不可达时用上次下载的副本）；config.json 中的 dropPaths 正则仍可用，作为附加的丢弃规则。
手动补跑某一天（文件不存在时显示“文件尚未生成”，每 5 分钟重试）：
  LogAgent.exe --config config.json --day 2030-01-02
