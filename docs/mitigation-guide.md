# Nginx、OpenResty 与 Tomcat 缓解措施

本章按风险、配置位置和验收方法整理仓库已有的缓解措施，用于缩小暴露面、阻断明确的异常路径并辅助应急处置。授权、参数化查询和上传存储隔离仍需由业务应用落实。

## 部署前确认

记录入口代理、实际 `server/location`、Tomcat Host/Context、上传落地目录与静态访问路径，备份配置和哈希。先验证正常登录、上传、下载、回调、OPTIONS 与会话 URL 重写，形成变更前基线。仓库的 Nginx 主配置仅监听本机测试端口，不应整份覆盖生产配置。

## Nginx：入口路径、代理与日志

| 目标 | 现有配置 | 验收重点 |
| --- | --- | --- |
| 敏感文件和部分管理接口 | [20-guards.conf](../configs/nginx/http.d/20-guards.conf) 匹配版本库目录、`.env` 和指定 Actuator 路径 | 目标路径被拒绝，普通资源仍可用；其他管理接口需单独控制 |
| 上传目录脚本限制 | 同一文件对示例 `/uploads`、`/files` 中的 JSP/JSPX/JSPF、PHP/PHTML、ASP/ASPX 作判断 | 正常附件可访问，脚本、大小写后缀和已纳入策略的编码形式被拒绝 |
| 路径歧义缓解 | `$uri` 检查规范化路径；`$request_uri` 去除查询串后检查点段与多层编码 | 查询参数不被误当路径，异常请求在进入后端前被阻断 |
| 防护顺序 | [app.conf](../configs/nginx/servers/app.conf) 在 server 层执行 `if ($bt_denied) { return 403; }` | 现有跳转、正则与 `^~` location 不造成规则落空 |
| 来源可信边界 | 边缘重设转发头；多层代理按 [trusted-proxy.conf.example](../configs/nginx/examples/trusted-proxy.conf.example) 指定可信上游 | 客户端自带 X-Forwarded-For 不能冒充可信来源 |
| 日志最小化 | [10-logging.conf](../configs/nginx/http.d/10-logging.conf) 默认写 JSON，省略查询、认证头、Cookie、UA 与正文 | 合成敏感标记不出现在默认访问日志；IP 和路径仍受访问控制 |
| 请求边界 | [nginx.conf](../configs/nginx/nginx.conf) 提供正文大小与读写超时样例 | 按业务容量调整；这些参数不构成完整限流或抗 DDoS 策略 |
| 采集端 TLS | [agent-tls.conf.example](../configs/nginx/examples/agent-tls.conf.example) 只转发采集 API 并限制来源 | 证书、令牌、来源范围正确，不额外暴露本机管理界面 |

保持 `map` 在 `http` 层，拦截在目标 `server` 层且位于提前跳转之前。官方说明 server 级 rewrite 指令先于 location 阶段执行；location 的前缀与正则选择还需结合现有配置审查。[Nginx rewrite 模块](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html)、[location 指令](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)。

可选 POST 取证日志在 [post-body.logging.conf.example](../configs/nginx/examples/post-body.logging.conf.example) 中，默认未启用。启用时限定站点、范围和保留期；正文缓冲到磁盘时 `$request_body` 可能为空，不能据此断言原请求没有正文。

## OpenResty：上传与 JSON 参数

### 上传扩展名缓解

[upload_extension_guard.lua](../configs/openresty/upload_extension_guard.lua) 校验 multipart 边界、分块、文件缓冲、`filename` / `filename*` 与编码形式；当前拦截后缀为 JSP、JSPX、JSPF、B64。

它是补充黑名单，不能证明其他扩展名安全。业务层仍需验证允许的文件类型与内容、生成服务端文件名、限制大小，将上传存储与可执行应用目录分离，并校验对象访问权限。JSON 包装或其他媒体类型的上传需要独立策略。

### 特定 JSON 协议约束

[query_portal_guard.lua](../configs/openresty/query_portal_guard.lua) 面向示例 `/business-api/gateway` 与 `example.portal.queryList`，检查目标字段的整数/数字字符串语义、正文大小、压缩和缺失情况。部署者须映射自己的 URI、方法和协议；不能把一个字段的校验推广成通用 SQL 防护。

按 [OpenResty 说明](../configs/openresty/README.md) 将调用合并到已有 `rewrite_by_lua_block`，确认 `lua_package_path`、`ngx.re` 与 `cjson.safe`。保留原 WAF 和其他阶段处理器，回归更深 location 的继承行为。通过 Lua Mock 只能证明被测逻辑，不代表目标 OpenResty 已完成加载验收。

## Tomcat：上传应用与路径规范化

### 独立上传应用拒绝脚本访问

将 [upload-web.xml](../configs/tomcat/upload-web.xml) 的 `security-constraint` 合并到专门承载上传资源的应用 `WEB-INF/web.xml`。它使用空 `auth-constraint` 拒绝匹配的 JSP/JSPX/JSPF URL；示例 schema 为 Servlet 3.1，应使用目标应用兼容的描述符格式。

不要替换全局 `conf/web.xml`，也不要直接套到需要正常 JSP 的业务应用。确认 Context 与真实文件路径后，测试脚本后缀、路径参数、大小写与代理转发结果。该约束不能阻止其他入口加载已经存在的恶意类。

### RewriteValve 路径约束

在目标 Host 或 Context 显式启用 `org.apache.catalina.valves.rewrite.RewriteValve`，再合并 [rewrite.config](../configs/tomcat/rewrite.config)。Host 级规则放到对应 Host 配置目录；Context 级规则放到该应用的 `WEB-INF/rewrite.config`。具体作用域和文件位置以目标版本的 [Tomcat RewriteValve 文档](https://tomcat.apache.org/tomcat-9.0-doc/rewrite.html)为准。

本仓库规则检查原始 `REQUEST_URI`，阻断点段及非预期分号参数，并保留符合限制的字面 `;jsessionid=`。同时验证直连与反代入口，检查代理是否提前规范化路径、Context 是否参与匹配，以及正常会话重写是否受影响。不能只看 XML 解析成功或浏览器跳转结果。

### 配套加固与处置

按实际业务限制管理入口、非必需应用、运行账号权限与网络出入口；配置和可执行应用目录应尽量与运行账号可写区域分开。这些是部署检查项，仓库脚本不会自动改动现网。[Tomcat 安全说明](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html)。

遇到 JSP / 内存组件线索时，先保全文件、请求、进程及运行状态证据，再修复入口、清理持久化并在受控窗口重启复测。JSP Cleaner 只辅助文件巡检，不能根据后缀确认恶意，也不能清理已加载的类或 Filter。

## 验证矩阵

| 用例 | 检查点 |
| --- | --- |
| 正常页面、静态资源、附件下载 | 内容与状态符合基线，不因规则合并失效 |
| 正常上传与业务回调 | 文件类型、正文大小及字段约束适配实际业务 |
| 正常 `;jsessionid=` | 会话 URL 重写按预期工作 |
| 敏感目录与脚本路径 | 在预期层被拒绝，后端没有执行 |
| 点段、混合编码与分号变体 | 对照原始路径、各层规范化结果和实际命中 |
| 查询串中的相似文本 | 不因把查询误当路径而阻断正常请求 |
| 转发头伪造 | 后端看到的来源符合可信代理配置 |
| 日志数据最小化 | 默认日志不包含合成正文、令牌和查询标记 |
| 重启与回滚 | 配置恢复、进程状态与正常业务均能核对 |

本机检查命令：

```text
python scripts/test_nginx.py --nginx /path/to/nginx
python scripts/test_honeypots.py --nginx /path/to/nginx
python tests/openresty/verify_upload_guard.py
python tests/openresty/verify_query_guard.py
```

Lua 检查先按 [测试说明](../tests/openresty/README.md) 安装依赖。Tomcat 当前只有配置审查和 XML 静态验证，没有目标容器运行证明，由部署验收补齐。

## 加载与回滚

1. 保存原配置、版本和哈希，填写[变更与回滚记录](../templates/change-and-rollback.md)。
2. 合并规则并做语法检查；Nginx 使用对应安装路径和配置入口执行 `nginx -t`。
3. 在隔离环境跑正常/异常对照，用上游日志核实请求是否真正到达后端。
4. 按维护窗口加载配置；Nginx 受控 reload，Tomcat 按部署方式重新加载或重启目标应用/实例。
5. 复核进程、规则、错误率、登录和回调；异常时恢复备份并再次验证，不用整体关闭防护代替定位。

记录结论时区分“语法有效”“规则已加载”“请求被拦截”和“业务修复已完成”。完成相应证据核对后再写入对应结论。
