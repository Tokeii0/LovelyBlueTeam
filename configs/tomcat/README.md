# Tomcat 上传应用缓解

分层防护、RewriteValve 作用域、验收矩阵与回滚步骤见[缓解措施手册](../../docs/mitigation-guide.md)。

`upload-web.xml` 仅用于专门存放上传资源的独立 Web 应用。已有 WEB-INF/web.xml 时只合并 security-constraint，并使用该应用对应的 Servlet schema；不要覆盖 Tomcat 全局 conf/web.xml 或需要正常 JSP 的业务应用。

`rewrite.config` 需要显式启用 Tomcat RewriteValve。它检查原始请求路径，阻断点段和非预期分号参数，保留规范的字面 `;jsessionid=`。不同 Tomcat 版本、代理规范化与大小写行为需要在隔离环境实测。它不能替代授权、上传校验和文件系统权限。

上线前列出 Context 映射、上传实际落地目录与静态服务路径，保全现有配置及哈希。测试正常页面、附件下载、session URL 重写、大小写脚本后缀和编码变体。只有完成配置加载检查与业务验收才能记录缓解生效；XML 能解析不代表 Tomcat 已应用规则。

处置 JSP/内存马还需进程与内存调查。删除文件不会清理已加载的类和 Filter；取证后在受控窗口修复、重启并复测。回滚时恢复备份配置，在同样的业务用例上验证。
