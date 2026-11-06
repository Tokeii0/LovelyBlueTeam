-- OpenResty rewrite phase guard for the observed queryList injection.
-- Keep the existing access_by_lua_file WAF handler.
local TARGET_METHOD = "example.portal.queryList"
local MAX_BODY = 1024 * 1024
local URI_PATTERN = [[^/business-api(?:;[^/]*)?/gateway(?:$|/|;)]]

local function canonical_original_path()
    local path = (ngx.var.request_uri or ""):match("^[^?]*") or ""
    path = ngx.unescape_uri(path)
    local parts = {}
    for part in path:gmatch("[^/]+") do
        if part == ".." then
            if #parts > 0 then table.remove(parts) end
        elseif part ~= "." then
            parts[#parts + 1] = part
        end
    end
    return "/" .. table.concat(parts, "/")
end

local current_match, _, current_error = ngx.re.find(ngx.var.uri or "", URI_PATTERN, "ijo")
local original_match, _, original_error = ngx.re.find(canonical_original_path(), URI_PATTERN, "ijo")
if current_error or original_error then
    ngx.log(ngx.ERR, "query_portal_guard: URI matcher failed")
    return ngx.exit(500)
end
if not current_match and not original_match then return end

-- Inspect any body-bearing method, including a GET body; do not use Content-Type
-- to decide whether the request can bypass JSON validation.
local method = ngx.req.get_method()
local declared_length = tonumber(ngx.var.content_length)
if declared_length and declared_length > MAX_BODY then return ngx.exit(413) end
local encoding = ngx.var.http_content_encoding
if encoding and encoding ~= "" and encoding:lower() ~= "identity" then
    return ngx.exit(415)
end

ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body then
    local filename = ngx.req.get_body_file()
    if filename then
        -- Only read the bounded Nginx request-body temporary file, never a
        -- client-supplied path. Reading does not replace/discard the body.
        local file = io.open(filename, "rb")
        if not file then
            ngx.log(ngx.ERR, "query_portal_guard: body file unavailable")
            return ngx.exit(500)
        end
        body = file:read(MAX_BODY + 1)
        file:close()
    end
end
if not body or body == "" then
    if method == "GET" or method == "HEAD" or method == "OPTIONS" then return end
    return ngx.exit(400)
end
if #body > MAX_BODY then return ngx.exit(413) end

local json = require "cjson.safe"
local object = json.decode(body)
if type(object) ~= "table" or type(object.head) ~= "table" then
    return ngx.exit(400)
end
local head = object.head
if head.method ~= TARGET_METHOD and head.method_code ~= TARGET_METHOD then return end
if head.method and head.method_code and head.method ~= head.method_code then
    return ngx.exit(400)
end
if type(object.body) ~= "table" then return ngx.exit(400) end

local value = object.body.container_type
-- Absent / empty values preserve the existing optional-filter behavior.
-- Numeric values are a type restriction, not a confirmed business enum.
if value == nil or value == "" then return end
if type(value) == "number" and value >= 0 and value <= 2147483647
        and value == math.floor(value) then
    return
end
if type(value) == "string" and #value <= 10 and value:match("^[0-9]+$")
        and tonumber(value) <= 2147483647 then
    return
end

-- Do not log request bodies, account fields, tokens, or query results.
ngx.log(ngx.WARN, "query_portal_guard: rejected nonnumeric container_type")
return ngx.exit(403)
