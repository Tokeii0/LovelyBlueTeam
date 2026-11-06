# 可选 OpenResty 防护

部署位置、业务修复边界和对照验收见[缓解措施手册](../../docs/mitigation-guide.md)。

这里保留两段从处置经验整理的 Lua 防护逻辑。原生 Nginx 不支持 `rewrite_by_lua_block`；启用前确认 ngx_lua、ngx.re 和 cjson.safe 可用，并在自己使用的 OpenResty 版本上验证。

`upload_extension_guard.lua` 是 multipart 解析模块，检查 filename / filename*、编码、重复参数、边界、分块读取与截断。当前扩展名策略为 JSP/JSPX/JSPF/B64，是补充黑名单；上线前按业务补充策略，并在应用层实施文件类型白名单、随机文件名、独立存储和不可执行目录。JSON、压缩请求及其他媒体类型需要独立策略。

```nginx
# 在现有 server 的 rewrite_by_lua_block 开头合并，不能另写第二个同阶段块。
rewrite_by_lua_block {
    local guard = require "upload_extension_guard"
    local allowed, status, reason = guard.check(ngx)
    if not allowed then
        ngx.log(ngx.WARN, "upload_guard reason=", reason or "unknown")
        return ngx.exit(status or 500)
    end
    -- 原有逻辑继续保留在这里
}
```

将模块放到明确配置的 `lua_package_path`。不要直接覆盖 WAF 的 access_by_lua_file，也不要在更深 location 中新增 rewrite_by_lua_file 覆盖已有 server 级逻辑。

`query_portal_guard.lua` 是**特定 JSON 协议的示例**：目标方法、URI 和 container_type 必须映射到自己的业务，默认模板使用 `example.portal.queryList` 与 `/business-api/gateway`。约束整数或数字字符串、大小、压缩和缺失正文；它并不验证用户权限，也不是通用 SQL 防火墙。参数化查询和服务端授权才是根本修复。

回归需包含正常文件、混合大小写、双扩展名、filename*、分块边界、坏报文、文件缓冲、正常数字/空字段、字符串注入及 JSON 类型变化。上传和 SQL 模块的运行时覆盖情况以 [验证记录](../../docs/validation.md) 为准。
