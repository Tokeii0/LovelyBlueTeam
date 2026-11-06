-- Buffered multipart upload guard for OpenResty. No payload execution or rewriting.
-- This is an additional extension policy, not a replacement for application validation.
local M = {}
local BLOCKED = { jsp = true, jspx = true, jspf = true, b64 = true }
local CHUNK = 65536
local MAX_HEADERS = 16384
local MAX_PARTS = 1000

local function trim(s)
    return (s:gsub('^[ \t]+', ''):gsub('[ \t]+$', ''))
end

local function token(s)
    return s ~= '' and not s:find('[^!#$%%&\'*+%.%^_`|~%w%-]')
end

-- Parse semicolon parameters without splitting quoted filenames at semicolons.
-- Duplicate parameters and ambiguous syntax are rejected rather than guessed.
local function parameters(s)
    local p = s:find(';', 1, true)
    local main = trim(p and s:sub(1, p - 1) or s):lower()
    local fields = {}
    if not p then return main, fields end
    while p <= #s do
        if s:sub(p, p) ~= ';' then return nil end
        p = p + 1
        while s:sub(p, p):match('[ \t]') do p = p + 1 end
        if p > #s then return nil end
        local start = p
        while p <= #s and s:sub(p, p) ~= '=' and s:sub(p, p) ~= ';' do p = p + 1 end
        local key = trim(s:sub(start, p - 1)):lower()
        if not token(key) or s:sub(p, p) ~= '=' or fields[key] ~= nil then return nil end
        p = p + 1
        while s:sub(p, p):match('[ \t]') do p = p + 1 end
        local value
        if s:sub(p, p) == '"' then
            p = p + 1
            local out, closed = {}, false
            while p <= #s do
                local c = s:sub(p, p)
                if c == '"' then
                    p, closed = p + 1, true
                    break
                elseif c == '\\' then
                    local following = s:sub(p + 1, p + 1)
                    if following == '"' or following == '\\' then
                        out[#out + 1] = following
                        p = p + 2
                    else
                        -- Preserve legacy Windows path separators so they cannot disappear.
                        out[#out + 1] = c
                        p = p + 1
                    end
                else
                    out[#out + 1] = c
                    p = p + 1
                end
            end
            if not closed then return nil end
            value = table.concat(out)
            while s:sub(p, p):match('[ \t]') do p = p + 1 end
            if p <= #s and s:sub(p, p) ~= ';' then return nil end
        else
            start = p
            while p <= #s and s:sub(p, p) ~= ';' do p = p + 1 end
            value = trim(s:sub(start, p - 1))
            if not token(value) then return nil end
        end
        fields[key] = value
    end
    return main, fields
end

local function filename_allowed(value, extended)
    if #value > 4096 then return nil, 400, 'filename_too_long' end
    if extended then
        local charset, _, encoded = value:match("^([^']+)'([^']*)'(.*)$")
        if not charset or (charset:lower() ~= 'utf-8' and charset:lower() ~= 'us-ascii') then
            return nil, 415, 'unsupported_filename_encoding'
        end
        value = encoded
    end
    -- Check both the plain and extended filename. Never prefer one over the other.
    for _ = 1, 4 do
        local decoded, count = value:gsub('%%(%x%x)', function(h)
            return string.char(tonumber(h, 16))
        end)
        value = decoded
        if count == 0 then break end
    end
    if value:find('%%%x%x') or value:find('=?', 1, true) then
        return nil, 400, 'ambiguous_filename_encoding'
    end
    if value:find('%c') or value:find('[\\/:]') then
        return nil, 403, 'unsafe_filename_path'
    end
    value = value:lower()
    -- Deliberately deny a forbidden extension at ANY extension segment:
    -- a.jsp.jpg, a.jsp;, a.jsp. and a.jspx are all rejected.
    for ext in value:gmatch('%.([a-z0-9]+)') do
        if BLOCKED[ext] then return nil, 403, 'forbidden_upload_extension' end
    end
    return true
end

local function check_part(block)
    local headers = {}
    for line in (block .. '\r\n'):gmatch('(.-)\r\n') do
        if line:find('[\r\n%z]') then return nil, 400, 'invalid_part_header' end
        local key, value = line:match('^([^:]+):(.*)$')
        if not key or not token(key) then return nil, 400, 'invalid_part_header' end
        key = key:lower()
        if headers[key] then return nil, 400, 'duplicate_part_header' end
        headers[key] = trim(value)
    end
    local disposition, fields = parameters(headers['content-disposition'] or '')
    if disposition ~= 'form-data' or not fields or fields.name == nil then
        return nil, 400, 'invalid_content_disposition'
    end
    for key in pairs(fields) do
        if key:sub(1, 8) == 'filename' and key ~= 'filename' and key ~= 'filename*' then
            return nil, 400, 'unsupported_filename_parameter'
        end
    end
    if fields.filename ~= nil then
        local ok, status, reason = filename_allowed(fields.filename, false)
        if not ok then return nil, status, reason end
    end
    if fields['filename*'] ~= nil then
        local ok, status, reason = filename_allowed(fields['filename*'], true)
        if not ok then return nil, status, reason end
    end
    if headers['content-transfer-encoding'] then
        return nil, 415, 'encoded_multipart_part'
    end
    local ct = (headers['content-type'] or ''):lower()
    if ct:find('^multipart/') then return nil, 415, 'nested_multipart' end
    return true
end

local function scan(read, boundary)
    local prefix = '--' .. boundary
    local delimiter = '\r\n' .. prefix
    local buffer, state, parts = '', 'start', 0
    while true do
        local chunk, err = read()
        if err then return nil, 500, 'body_read_error' end
        local eof = chunk == nil
        buffer = buffer .. (chunk or '')
        while true do
            if state == 'start' then
                if #buffer < #prefix + 2 then break end
                if buffer:sub(1, #prefix) ~= prefix then return nil, 400, 'invalid_multipart_start' end
                local ending = buffer:sub(#prefix + 1, #prefix + 2)
                buffer = buffer:sub(#prefix + 3)
                if ending == '\r\n' then state = 'headers'
                elseif ending == '--' then state = 'closed'
                else return nil, 400, 'invalid_multipart_start' end
            elseif state == 'headers' then
                local pos = buffer:find('\r\n\r\n', 1, true)
                if (pos and pos - 1 > MAX_HEADERS) or (not pos and #buffer > MAX_HEADERS + 3) then
                    return nil, 400, 'part_headers_too_large'
                end
                if not pos then break end
                parts = parts + 1
                if parts > MAX_PARTS then return nil, 400, 'too_many_parts' end
                local ok, status, reason = check_part(buffer:sub(1, pos - 1))
                if not ok then return nil, status, reason end
                buffer, state = buffer:sub(pos + 4), 'body'
            elseif state == 'body' then
                local search, found, incomplete = 1, false, false
                while true do
                    local pos = buffer:find(delimiter, search, true)
                    if not pos then break end
                    if #buffer < pos + #delimiter + 1 then
                        buffer, incomplete = buffer:sub(pos), true
                        break
                    end
                    local ending = buffer:sub(pos + #delimiter, pos + #delimiter + 1)
                    if ending == '\r\n' or ending == '--' then
                        buffer = buffer:sub(pos + #delimiter + 2)
                        state = ending == '--' and 'closed' or 'headers'
                        found = true
                        break
                    end
                    search = pos + 1 -- A lookalike inside file bytes is not a boundary.
                end
                if not found then
                    if not incomplete then buffer = buffer:sub(-(#delimiter + 1)) end
                    break
                end
            else -- closing boundary: disallow nonempty epilogues and malformed endings
                if #buffer > 2 or (buffer ~= '' and buffer ~= '\r' and buffer ~= '\r\n') then
                    return nil, 400, 'invalid_multipart_end'
                end
                break
            end
        end
        if eof then
            if state == 'closed' and (buffer == '' or buffer == '\r\n') then return true end
            return nil, 400, 'incomplete_multipart'
        end
    end
end

function M.check(ngx)
    local file
    local function inspect()
        local headers, header_error = ngx.req.get_headers(100)
        local ct = headers['content-type']
        if type(ct) == 'table' then return nil, 400, 'duplicate_content_type' end
        if header_error then return nil, 400, 'request_headers_truncated' end
        if not ct then return true end
        -- Other media types need application-specific validation; do not scan JSON as MIME.
        if not trim(ct):lower():find('^multipart/') then return true end
        local media, fields = parameters(ct)
        if not media or not fields then return nil, 400, 'invalid_content_type' end
        if media ~= 'multipart/form-data' then return nil, 415, 'unsupported_multipart' end
        local boundary = fields.boundary
        if not boundary or #boundary < 1 or #boundary > 70 or boundary:sub(-1) == ' '
            or boundary:find('[^%w\'()+_,%-%./:=? ]') then
            return nil, 400, 'invalid_boundary'
        end
        local ce = headers['content-encoding']
        if ce and (type(ce) ~= 'string' or trim(ce):lower() ~= 'identity') then
            return nil, 415, 'encoded_multipart_request'
        end
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        local read
        if body then
            local offset = 1
            read = function()
                if offset > #body then return nil end
                local chunk = body:sub(offset, offset + CHUNK - 1)
                offset = offset + #chunk
                return chunk
            end
        else
            local path = ngx.req.get_body_file()
            if not path then return nil, 400, 'missing_multipart_body' end
            file = io.open(path, 'rb')
            if not file then return nil, 500, 'body_file_unavailable' end
            read = function() return file:read(CHUNK) end
        end
        return scan(read, boundary)
    end
    local ran, allowed, status, reason = pcall(inspect)
    if file then file:close() end
    if not ran then return nil, 500, 'upload_guard_internal_error' end
    return allowed, status, reason
end

return M
