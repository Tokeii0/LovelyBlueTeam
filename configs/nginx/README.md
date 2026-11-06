# Nginx 配置

跨 Nginx、OpenResty 与 Tomcat 的风险对应、验收矩阵及加载回滚步骤见[缓解措施手册](../../docs/mitigation-guide.md)。

`nginx.conf` 是本机验证用配置：监听 127.0.0.1:18080，反代到本机 18081。不接触真实后端，也不默认启用 TLS、正文日志或外部出口。先创建 logs 和 temp 目录再使用 `nginx -p <此目录>/ -c nginx.conf -t`；自动测试脚本会在临时目录完成这些步骤。

| 文件 | 放置上下文 | 作用 |
| --- | --- | --- |
| http.d/10-logging.conf | http | JSON 日志格式，与两应用字段兼容 |
| http.d/20-guards.conf | http | 敏感路径、上传目录脚本、分号点段与多重编码路径判断 |
| servers/app.conf | http 内独立 server | 反代、日志、安全响应头与返回式拦截 |
| examples/agent-tls.conf.example | http 内独立 server | 带来源限制的 Agent TLS 入口 |
| examples/trusted-proxy.conf.example | http/server | 仅信任明确上游代理的真实 IP |
| examples/post-body.logging.conf.example | server/location | 可选原始 POST 正文取证日志 |

现网集成先导出和备份有效配置，确认 server/location 命中关系，再合并。路径检查放在 server 的提前跳转之前；`location ^~ /` 会影响正则 location 的选择，因此本模板使用 server 层 return 拦截。**Nginx 规则不是完整 WAF，也不能修复应用授权或参数化查询。**

默认日志省略查询串、认证头、Cookie、UA 与正文。路径和来源地址仍需按敏感数据管理；省略字段会降低某些检测能力。POST 正文日志仅在明确取证范围启用，不能当成已脱敏日志；后续还需本地访问控制、字段遮盖与对外发布审查。

仅检查已知静态资源、脚本目录和异常路径，不对所有分号一律阻断；正常 `;jsessionid=` 需单独回归。未默认复制现场 UA/IP 黑名单、302 跳转、业务回调豁免或整体禁用上传规则，它们依赖现场业务与证据。JSON 字段与 multipart 检查见 [OpenResty](../openresty/README.md)。

上线流程：备份配置及哈希 → `nginx -t` → 正常业务与异常路径回归 → reload → 检查新 worker、错误率与业务指标。失败时恢复原配置，重新 `nginx -t` 并 reload。TLS 证书、上游验证、WebSocket、上传容量与超时按实际应用填写，不使用此测试入口代替生产 TLS 配置。

测试命令：`python scripts/test_nginx.py --nginx /path/to/nginx`。它只启动本机临时实例和合成后端，不 reload 现网进程。

配置语法依据：[日志模块](https://nginx.org/en/docs/http/ngx_http_log_module.html)、[map 模块](https://nginx.org/en/docs/http/ngx_http_map_module.html)、[反向代理模块](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)、[真实 IP 模块](https://nginx.org/en/docs/http/ngx_http_realip_module.html)。
