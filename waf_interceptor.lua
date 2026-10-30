--[[
ML WAF access-phase handler for OpenResty (access_by_lua_file).

For each proxied request it collects input values from:
  parameters  URI arguments and the request body (form, multipart, JSON, text)
  extended    the URI path, selected headers (User-Agent, Referer) and cookies
Hybrid engine:
  1. regex  every value is first checked against a small table of
            unmistakable SQLi signatures (SIGNATURES below). A match blocks the
            request at once; the ML API is not called at all. This catches
            "good word" attacks, where a payload is padded with benign text
            (e.g. appended to a real User-Agent) to dilute the model's score.
  2. ml     everything else is scored in ONE call to the ML API's /scan/batch
            endpoint (values already scored recently come from a cache).

Extended values use their own threshold and mode (WAF_EXTENDED_THRESHOLD,
WAF_EXTENDED_MODE): the model was trained on parameter values, and ordinary
browser User-Agents score up to ~0.56 with it, so they need a higher bar and
a monitor-first rollout.

Outcomes, recorded in $waf_action (JSON access log):
  skip         nothing to inspect
  allow        scanned, below the thresholds
  block        SQLi detected by a signature or the model, answered 403
  monitor      SQLi detected (or not inspectable) but in monitor mode, allowed
  reject       request could not be fully inspected (too many/too large values), 403
  fail_open    ML API slow/unreachable/erroring, allowed (WAF_FAIL_MODE=open)
  fail_closed  ML API slow/unreachable/erroring, 503 (WAF_FAIL_MODE=closed)

Settings are read from environment variables, which must also be declared
with `env` in nginx.conf (nginx clears the environment for its workers).
]]

local http = require "resty.http"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"
local cjson = require("cjson.safe").new()

-- Deeper JSON documents fail to decode and are then scanned as raw text.
cjson.decode_max_depth(32)

local function env_string(name, default)
    local value = os.getenv(name)
    if value == nil or value == "" then
        return default
    end
    return value
end

local function env_number(name, default)
    return tonumber(os.getenv(name) or "") or default
end

local function env_list(name, default)
    local list = {}
    for item in env_string(name, default):lower():gmatch("[^,%s]+") do
        list[#list + 1] = item
    end
    return list
end

local CONFIG = {
    scan_url           = env_string("WAF_SCAN_URL", "http://ml-api:8000/scan/batch"),
    monitor_only       = env_string("WAF_MODE", "block") == "monitor",
    fail_open          = env_string("WAF_FAIL_MODE", "open") ~= "closed",
    block_threshold    = env_number("WAF_BLOCK_THRESHOLD", 0.5),
    connect_timeout    = env_number("WAF_CONNECT_TIMEOUT_MS", 20),
    send_timeout       = env_number("WAF_SEND_TIMEOUT_MS", 20),
    read_timeout       = env_number("WAF_READ_TIMEOUT_MS", 50),
    -- Path, header and cookie inspection: block | monitor | off.
    extended_mode      = env_string("WAF_EXTENDED_MODE", "monitor"),
    extended_threshold = env_number("WAF_EXTENDED_THRESHOLD", 0.8),
    -- Regex pre-filter: block | monitor | off. Applies to all value sources,
    -- including headers and cookies: signatures are precise enough for that.
    regex_mode         = env_string("WAF_REGEX_MODE", "block"),
    inspect_headers    = env_list("WAF_INSPECT_HEADERS", "user-agent,referer"),
    -- Inspection limits. Requests exceeding them are rejected rather than
    -- partially scanned or truncated: either would let padding hide a payload.
    max_args           = env_number("WAF_MAX_ARGS", 100),
    max_items          = env_number("WAF_MAX_ITEMS", 128),        -- keep <= SQLI_MAX_BATCH_SIZE
    chunk_size         = env_number("WAF_CHUNK_SIZE", 1024),      -- keep <= SQLI_MAX_QUERY_LENGTH
    chunk_overlap      = 64,
    max_header_bytes   = env_number("WAF_MAX_HEADER_BYTES", 4096), -- per header or cookie value
    max_cookies        = env_number("WAF_MAX_COOKIES", 100),
    cache_ttl          = env_number("WAF_CACHE_TTL_S", 300),       -- 0 disables the verdict cache
    alert_url          = env_string("WAF_ALERT_WEBHOOK_URL", nil),
    alert_token        = env_string("WAF_ALERT_WEBHOOK_TOKEN", nil),
    alert_cooldown     = env_number("WAF_ALERT_COOLDOWN_S", 60),
    alert_values       = env_string("WAF_ALERT_INCLUDE_VALUES", "true") ~= "false",
    breaker_seconds    = env_number("WAF_BREAKER_SECONDS", 5),
    -- Per-client fail-open budget (see fail_open_allowed); -1 disables it.
    fail_open_budget   = env_number("WAF_FAIL_OPEN_BUDGET", 5),
    fail_open_window   = env_number("WAF_FAIL_OPEN_WINDOW_S", 10),
}

-- Bodies of these types are binary and not inspected.
local UNINSPECTED_BODY_TYPES = {
    "application/octet-stream", "application/pdf", "application/zip",
    "application/grpc", "image/", "audio/", "video/", "font/",
}

-- Alerts carry at most this many flagged values, each cut to this length.
local ALERT_MAX_VALUES = 5
local ALERT_VALUE_CHARS = 256

local function iso_now()
    return (ngx.utctime():gsub(" ", "T")) .. "Z"
end

---------------------------------------------------------------------------
-- Regex pre-filter: signature table
--
-- Only constructs that essentially never occur in legitimate input. Bare "--"
-- and "/*" are deliberately NOT signatures: "--" is in roughly 1 in 14 JWT
-- cookies (base64url), BEM CSS classes and CLI flags; "/*" in globs such as
-- src/**/*.js. Comment syntax only counts in SQL context (after a quote,
-- between SQL keywords, MySQL /*!...*/).
--
-- Matching is ReDoS-safe: possessive quantifiers (*+ ++) never backtrack, so
-- time stays linear in the input; lua_regex_match_limit (nginx.conf) is the
-- backstop. Patterns run case-insensitively ("i"), JIT-compiled once per
-- worker ("jo").
---------------------------------------------------------------------------

-- signatures:begin
local SIGNATURES = (function()
    local COMMENT = [=[/\*(?:[^*]|\*(?!/))*+\*/]=]          -- /* ... */
    local GAP = [=[(?:\s|]=] .. COMMENT .. [=[)*+]=]         -- optional whitespace or comments
    local SEP = [=[(?:\s|]=] .. COMMENT .. [=[)++]=]         -- required whitespace or comments
    local SEPP = [=[(?:\s|\(|]=] .. COMMENT .. [=[)++]=]     -- ... or "("
    local GAPP = [=[(?:\s|[()]|]=] .. COMMENT .. [=[)*+]=]   -- optional whitespace, comments or brackets
    local KEYWORD = [=[(?:or|and|union|select|from|where|having|order\s++by|group\s++by)]=]

    return {
        { id = "union_select",
          pattern = [=[\bunion]=] .. SEPP .. [=[(?:(?:all|distinct)]=] .. SEPP .. [=[)?select\b]=] },
        { id = "stacked_query",
          pattern = ";" .. GAP .. [=[(?:drop]=] .. SEP .. [=[(?:table|database|schema)\b|truncate]=] .. SEP
              .. [=[table\b|declare]=] .. SEP .. [=[@\w|exec(?:ute)?]=] .. SEP .. [=[(?:master\.|xp_|sp_))]=] },
        { id = "dangerous_procedure",
          pattern = [=[\b(?:xp_cmdshell|xp_regread|xp_dirtree|sp_oacreate|sp_makewebtask)\b]=] },
        { id = "time_delay",
          pattern = [=[\bwaitfor]=] .. SEP .. [=[delay]=] .. GAP .. [=['\d|\bbenchmark\s*+\(\s*+\d++\s*+,]=]
              .. [=[|(?:\b(?:and|or|select|if|then|when)|[(,'"|+])]=] .. GAP .. [=[(?:pg_)?sleep\s*+\(\s*+\d]=] },
        { id = "tautology", -- ' or '1'='1   ') OR ('a'='a   '/**/or/**/1=1
          pattern = [=[['"]]=] .. GAPP .. [=[(?:or|\|\|)(?:]=] .. SEPP .. [=[|(?=['"\d]))['"]?(?<a>\w++)['"]?]=]
              .. GAP .. "=" .. GAPP .. [=[['"]?\k<a>\b]=] },
        { id = "numeric_tautology",
          pattern = [=[\b(?:or|and)]=] .. SEP .. [=[(?<b>\d++)]=] .. GAP .. "=" .. GAP .. [=[\k<b>\b]=] },
        { id = "quote_comment",
          pattern = [=['[\s)]*+(?:--|/\*|#\s*+$)|"[\s)]*+(?:--[\s;]*+$|/\*)]=] },
        { id = "mysql_versioned_comment",
          pattern = [=[/\*!(?:\d{5}|\s*+(?:union|select|and|or|insert|update|delete)\b)]=] },
        { id = "comment_obfuscation",
          pattern = [=[\b]=] .. KEYWORD .. COMMENT .. [=[(?:\w|['"(@])]=] },
        { id = "system_catalog",
          pattern = [=[\b(?:information_schema|sqlite_master|pg_catalog|mysql\.user|sysobjects|syscolumns)\b]=]
              .. [=[|@@(?:version|datadir|hostname|basedir)\b]=] },
        { id = "file_access",
          pattern = [=[\binto]=] .. SEP .. [=[(?:out|dump)file\b|\bload_file\s*+\(]=] },
        { id = "error_based",
          pattern = [=[\b(?:extractvalue|updatexml)\s*+\(|\bexp\s*+\(\s*+~|\bconvert\s*+\(\s*+int\s*+,]=] },
        { id = "char_concat",
          pattern = [=[\bchar\s*+\(\s*+\d++\s*+\)\s*+(?:\|\||\+|,\s*+char\b)]=] },
    }
end)()
-- signatures:end

-- All signatures in one alternation: a benign value (the common case) costs a
-- single scan. Only on a match are the signatures tried one by one to name it.
local SIGNATURES_COMBINED
do
    local parts = {}
    for i, signature in ipairs(SIGNATURES) do
        parts[i] = "(?:" .. signature.pattern .. ")"
    end
    SIGNATURES_COMBINED = table.concat(parts, "|")
end

-- Returns the first matching signature, or nil. A regex error (e.g. the match
-- limit) is logged and treated as "no match": the value then goes to the ML
-- model, so an error never skips inspection.
local function match_signature(value)
    local from, _, err = ngx.re.find(value, SIGNATURES_COMBINED, "joi")
    if not from then
        if err then
            ngx.log(ngx.WARN, "WAF signature check failed, deferring to ML: ", err)
        end
        return nil
    end
    for _, signature in ipairs(SIGNATURES) do
        if ngx.re.find(value, signature.pattern, "joi") then
            return signature
        end
    end
    return nil
end

---------------------------------------------------------------------------
-- Value extraction
---------------------------------------------------------------------------

-- Replace invalid UTF-8 with "?". Invalid bytes (e.g. ?x=%FF) would make the
-- JSON sent to the API undecodable; failing the scan would then trigger
-- fail-open, which is an attacker-controlled bypass.
local function to_valid_utf8(s)
    if not s:find("[\128-\255]") then
        return s
    end
    local out, i, n = {}, 1, #s
    while i <= n do
        local c = s:byte(i)
        local len, lo, hi = 0, 0x80, 0xBF
        if c < 0x80 then len = 1
        elseif c >= 0xC2 and c <= 0xDF then len = 2
        elseif c >= 0xE0 and c <= 0xEF then
            len = 3
            if c == 0xE0 then lo = 0xA0 elseif c == 0xED then hi = 0x9F end
        elseif c >= 0xF0 and c <= 0xF4 then
            len = 4
            if c == 0xF0 then lo = 0x90 elseif c == 0xF4 then hi = 0x8F end
        end

        local valid = len > 0 and i + len - 1 <= n
        if valid and len > 1 then
            local b = s:byte(i + 1)
            valid = b >= lo and b <= hi
            for j = i + 2, i + len - 1 do
                if not valid then break end
                b = s:byte(j)
                valid = b >= 0x80 and b <= 0xBF
            end
        end

        if valid then
            out[#out + 1] = s:sub(i, i + len - 1)
            i = i + len
        else
            out[#out + 1] = "?"
            i = i + 1
        end
    end
    return table.concat(out)
end

-- A batch holds the values to score plus, per value, where it came from
-- (for logs and alerts) and whether it is an extended (path/header/cookie) value.
local function new_batch()
    return { values = {}, labels = {}, extended = {}, seen = {} }
end

local function label(kind, name)
    if type(name) ~= "string" or name == "" then
        return kind
    end
    return kind .. ":" .. to_valid_utf8(name:sub(1, 64))
end

-- Check a value against the signatures, then append it for the ML call,
-- splitting long values into overlapping chunks (the model was trained on
-- short parameter values).
-- Returns true, or false plus a reason:
--   "signature_match"  a signature matched (WAF_REGEX_MODE=block); the value
--                      is not added and collection stops
--   "too_many_items"   the item limit was exceeded
local function add_value(batch, value, source, extended)
    local kind = type(value)
    if kind == "table" then -- repeated keys (?id=1&id=2) or repeated headers
        for _, v in ipairs(value) do
            local ok, why = add_value(batch, v, source, extended)
            if not ok then
                return false, why
            end
        end
        return true
    end
    if kind ~= "string" then
        return true -- valueless flags (?debug) and JSON numbers/booleans/null
    end

    local size, step, start = CONFIG.chunk_size, CONFIG.chunk_size - CONFIG.chunk_overlap, 1
    -- Values this long could never fit the item limit; refuse before scanning.
    if #value > size * CONFIG.max_items then
        return false, "too_many_items"
    end

    -- Pre-flight: the whole value, not chunks, so no signature is split
    -- across a chunk boundary. Values made only of letters, digits and "._~"
    -- can't contain SQL syntax and skip the check.
    if CONFIG.regex_mode ~= "off" and value:find("[^%w%._~]") then
        local signature = match_signature(value)
        if signature then
            if not batch.regex_hit then
                batch.regex_hit = { signature = signature, source = source, value = value }
            end
            if CONFIG.regex_mode == "block" then
                return false, "signature_match"
            end
            -- monitor: record the hit, and let the model score the value too
        end
    end

    repeat
        local chunk = value:sub(start, start + size - 1)
        -- Skip chunks that cannot carry SQL syntax: blank (the API rejects
        -- those), or only letters, digits and "._~" (ids, hex tokens, numbers).
        -- Most path segments and cookie values are like this.
        if chunk:find("[^%w%._~]") and chunk:find("%S") then
            chunk = to_valid_utf8(chunk)
            if not batch.seen[chunk] then
                local n = #batch.values + 1
                if n > CONFIG.max_items then
                    return false, "too_many_items"
                end
                batch.values[n], batch.labels[n], batch.extended[n] = chunk, source, extended == true
                batch.seen[chunk] = true
            end
        end
        start = start + step
    until start + CONFIG.chunk_overlap > #value
    return true
end

local function add_json_strings(batch, node)
    if type(node) ~= "table" then
        return add_value(batch, node, "json", false)
    end
    for _, child in pairs(node) do
        local ok, why = add_json_strings(batch, child)
        if not ok then
            return false, why
        end
    end
    return true
end

-- Text fields of a multipart/form-data body. Web frameworks parse these just
-- like urlencoded fields, so skipping them would be a one-header bypass.
-- File parts (those with a filename) are not inspected.
local function add_multipart_fields(batch, body, raw_content_type)
    local boundary = raw_content_type:match('boundary="([^"]+)"')
        or raw_content_type:match("boundary=([^;%s]+)")
    if not boundary then
        return add_value(batch, body, "body", false)
    end

    local delimiter = "--" .. boundary
    local _, pos = body:find(delimiter, 1, true)
    while pos do
        local next_start, next_end = body:find(delimiter, pos + 1, true)
        if not next_start then
            break
        end
        local part = body:sub(pos + 1, next_start - 1)
        local header_end = part:find("\r\n\r\n", 1, true)
        if header_end then
            local part_headers = part:sub(1, header_end)
            if not part_headers:lower():find("filename", 1, true) then
                local name = part_headers:match('name="([^"]*)"')
                -- Drop the CRLF that precedes the next delimiter.
                local ok, why = add_value(batch, part:sub(header_end + 4, -3), label("multipart", name), false)
                if not ok then
                    return false, why
                end
            end
        end
        pos = next_end
    end
    return true
end

local function add_args(batch, kind, extended, args, err)
    if err == "truncated" then
        return false, "too_many_args"
    end
    for name, value in pairs(args or {}) do
        local ok, why = add_value(batch, value, label(kind, name), extended)
        if not ok then
            return false, why
        end
    end
    return true
end

-- Returns ok, reason. ok=false means the request cannot be fully inspected.
local function collect_body(batch)
    local has_body = (tonumber(ngx.var.http_content_length or "") or 0) > 0
        or ngx.var.http_transfer_encoding ~= nil
    if not has_body then
        return true
    end

    local content_type = (ngx.var.content_type or ""):lower()
    for _, prefix in ipairs(UNINSPECTED_BODY_TYPES) do
        if content_type:sub(1, #prefix) == prefix then
            return true, "body_not_inspected"
        end
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body == nil then
        -- nginx spilled the body to disk: it is larger than client_body_buffer_size.
        if ngx.req.get_body_file() then
            return false, "body_too_large"
        end
        return true
    end

    if content_type:find("application/x-www-form-urlencoded", 1, true) then
        return add_args(batch, "body", false, ngx.req.get_post_args(CONFIG.max_args))
    end

    if content_type:sub(1, 10) == "multipart/" then
        return add_multipart_fields(batch, body, ngx.var.content_type)
    end

    if content_type:find("json", 1, true) then
        local doc = cjson.decode(body)
        if doc ~= nil then
            return add_json_strings(batch, doc)
        end
        -- Malformed JSON may still carry a payload: fall through to raw text.
    end

    return add_value(batch, body, "body", false)
end

---------------------------------------------------------------------------
-- Extended inspection: URI path, headers, cookies
--
-- Size bounds: nginx rejects any request or header line longer than
-- large_client_header_buffers (8 KB, nginx.conf) with 400 before this code
-- runs, so the strings handled here are already capped. On top of that, a
-- header or cookie value above WAF_MAX_HEADER_BYTES makes the request
-- uninspectable (reject in block mode) instead of being truncated or dropped,
-- which would let an attacker pad a payload out of view.
---------------------------------------------------------------------------

local function oversized(value)
    if type(value) == "table" then
        for _, v in ipairs(value) do
            if oversized(v) then
                return true
            end
        end
        return false
    end
    return type(value) == "string" and #value > CONFIG.max_header_bytes
end

local function collect_path(batch)
    -- Use the raw path: nginx's $uri decodes %2F, which would split a payload
    -- such as 1%27%2F**%2FOR... into harmless-looking segments.
    local raw_path = ngx.var.request_uri:match("^[^?#]*")
    local segments = 0
    for segment in raw_path:gmatch("[^/]+") do
        segments = segments + 1
        local ok, why = add_value(batch, ngx.unescape_uri(segment), "path:segment", true)
        if not ok then
            return false, why
        end
    end
    -- Also the whole path: a payload with literal slashes (e.g. /**/ comments)
    -- only reads as SQL in one piece.
    if segments > 1 then
        return add_value(batch, ngx.unescape_uri(raw_path), "path", true)
    end
    return true
end

local function collect_headers(batch)
    -- 0 = no header-count limit: with a limit, 100 padding headers would push
    -- the inspected ones out of the parsed table. Total size is capped by nginx.
    local headers = ngx.req.get_headers(0)
    for _, name in ipairs(CONFIG.inspect_headers) do
        local value = headers[name]
        if value ~= nil then
            if oversized(value) then
                return false, "header_too_large"
            end
            local ok, why = add_value(batch, value, "header:" .. name, true)
            if not ok then
                return false, why
            end
            -- A Referer's query parameters are also scored one by one, the way
            -- our own parameters are, so the surrounding URL can't dilute them.
            if name == "referer" and type(value) == "string" then
                local query = value:match("%?([^#]*)")
                if query then
                    local ok, reason = add_args(batch, "referer-arg", true, ngx.decode_args(query, CONFIG.max_args))
                    if not ok then
                        return false, reason
                    end
                end
            end
        end
    end
    return true
end

local function collect_cookies(batch)
    local header = ngx.var.http_cookie -- all Cookie headers, joined by nginx
    if not header then
        return true
    end
    local count = 0
    for pair in header:gmatch("[^;]+") do
        count = count + 1
        if count > CONFIG.max_cookies then
            return false, "too_many_cookies"
        end
        local name, value = pair:match("^%s*([^=]-)%s*=%s*(.-)%s*$")
        if not name then
            name, value = "", pair
        end
        if #value > CONFIG.max_header_bytes then
            return false, "cookie_too_large"
        end
        -- Many frameworks URL-decode cookie values; scan what the app will see.
        value = ngx.unescape_uri(value:match('^"(.*)"$') or value)
        local ok, why = add_value(batch, value, label("cookie", name), true)
        if not ok then
            return false, why
        end
    end
    return true
end

local function collect_extended(batch)
    for _, collect in ipairs({ collect_path, collect_headers, collect_cookies }) do
        local ok, reason = collect(batch)
        if not ok then
            return false, reason
        end
    end
    return true
end

---------------------------------------------------------------------------
-- ML API call
---------------------------------------------------------------------------

-- Circuit breaker. When the ML API is down (rather than slow), e.g. its
-- container is restarting, DNS lookups and connects can stall for far longer
-- than the read timeout. After such a failure, skip the API for a few seconds
-- so requests fail open immediately. Timeouts and "overloaded" responses do not
-- trip it: an attacker can cause those, and tripping would switch inspection
-- off for everyone.
local function ml_api_down()
    return ngx.shared.waf_state:get("ml_api_down") ~= nil
end

local function trip_breaker(reason)
    if ngx.shared.waf_state:add("ml_api_down", reason, CONFIG.breaker_seconds) then
        ngx.log(ngx.ERR, "WAF circuit breaker open for ", CONFIG.breaker_seconds, "s: ", reason)
    end
end

-- Returns the decoded API response, or nil and an error string.
local function score(values)
    if ml_api_down() then
        return nil, "ml_api_circuit_open"
    end

    local httpc = http.new()
    -- Cosocket I/O: the worker keeps serving other requests while waiting.
    httpc:set_timeouts(CONFIG.connect_timeout, CONFIG.send_timeout, CONFIG.read_timeout)

    local res, err = httpc:request_uri(CONFIG.scan_url, {
        method = "POST",
        body = cjson.encode({ queries = values }),
        headers = {
            ["Content-Type"] = "application/json",
            ["X-WAF-Request-ID"] = ngx.var.request_id,
        },
        keepalive_timeout = 60000, -- reuse connections: a new TCP handshake per request eats the budget
        keepalive_pool = 64,
    })
    if not res then
        if err ~= "timeout" then
            trip_breaker(tostring(err)) -- DNS failure, connection refused, ...
        end
        return nil, "ml_api_" .. tostring(err) -- e.g. ml_api_timeout, ml_api_connection refused
    end
    if res.status ~= 200 then
        local body = cjson.decode(res.body)
        if res.status == 503 and type(body) == "table" and body.error == "model_unavailable" then
            trip_breaker("model_unavailable")
        end
        return nil, "ml_api_status_" .. res.status
    end

    local data = cjson.decode(res.body)
    if type(data) ~= "table" or type(data.probabilities) ~= "table"
        or #data.probabilities ~= #values then
        return nil, "ml_api_bad_response"
    end
    return data
end

local function cache_key(value)
    local sha = resty_sha256:new()
    sha:update(value)
    return resty_string.to_hex(sha:final())
end

-- Score every value, reusing cached probabilities. The model is
-- deterministic, and User-Agents, cookies and common parameters repeat
-- constantly, so most requests send few or no values to the API. That keeps
-- the 50 ms budget and the API's capacity despite the larger inspection surface.
-- Keys are SHA-256 digests, so a crafted value can't collide with a cached
-- benign one.
-- Returns probabilities (nil entries where unknown), ml_request_id, err, number sent.
local function score_batch(values)
    local cache = CONFIG.cache_ttl > 0 and ngx.shared.waf_verdicts or nil
    local probabilities, keys, pending, pending_index = {}, {}, {}, {}
    for i, value in ipairs(values) do
        if cache then
            keys[i] = cache_key(value)
            probabilities[i] = cache:get(keys[i])
        end
        if probabilities[i] == nil then
            pending[#pending + 1] = value
            pending_index[#pending_index + 1] = i
        end
    end
    if #pending == 0 then
        return probabilities, nil, nil, 0
    end

    local result, err = score(pending)
    if not result then
        return probabilities, nil, err, #pending
    end
    for j, i in ipairs(pending_index) do
        local p = tonumber(result.probabilities[j])
        probabilities[i] = p
        if cache and p then
            cache:set(keys[i], p, CONFIG.cache_ttl) -- evicts least-recently-used when full
        end
    end
    return probabilities, result.request_id, nil, #pending
end

---------------------------------------------------------------------------
-- Incident-response webhook
---------------------------------------------------------------------------

-- Runs in a zero-delay timer, i.e. after the current request has been
-- answered, so a slow or dead webhook never delays the client.
local function send_alert(premature, url, token, payload)
    if premature then
        return -- worker is shutting down
    end
    local httpc = http.new()
    httpc:set_timeouts(1000, 1000, 3000)
    local headers = { ["Content-Type"] = "application/json" }
    if token then
        headers["Authorization"] = "Bearer " .. token
    end
    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = payload,
        headers = headers,
        ssl_verify = true,
    })
    if not res then
        ngx.log(ngx.ERR, "WAF alert webhook failed: ", err)
    elseif res.status >= 300 then
        ngx.log(ngx.ERR, "WAF alert webhook returned HTTP ", res.status)
    end
end

local function fire_alert(event)
    if not CONFIG.alert_url then
        return
    end
    -- At most one alert per client IP per cooldown window, so an attack burst
    -- does not flood the automation workflow.
    local alerts = ngx.shared.waf_alerts
    if alerts and not alerts:add("ip:" .. event.ip, true, CONFIG.alert_cooldown) then
        return
    end
    local ok, err = ngx.timer.at(0, send_alert, CONFIG.alert_url, CONFIG.alert_token, cjson.encode(event))
    if not ok then
        ngx.log(ngx.ERR, "WAF could not schedule alert webhook: ", err)
    end
end

---------------------------------------------------------------------------
-- Decision
---------------------------------------------------------------------------

-- Returns a decision table; performs no response I/O itself so it can run
-- under pcall safely.
-- Decision for a signature match: block (or monitor) without calling the ML API.
local function signature_decision(batch, action)
    local hit = batch.regex_hit
    return {
        action = action,
        reason = "sqli_signature",
        engine = "regex",
        signature = hit.signature,
        source = hit.source,
        regex_value = hit.value,
        flagged = {},
        items = #batch.values,
    }
end

local function inspect()
    local batch = new_batch()

    local ok, reason = add_args(batch, "arg", false, ngx.req.get_uri_args(CONFIG.max_args))
    if ok then
        ok, reason = collect_body(batch)
    end
    if not ok and reason ~= "signature_match" then
        return { action = "reject", reason = reason, items = #batch.values }
    end

    if ok and CONFIG.extended_mode ~= "off" then
        local ext_ok, ext_reason = collect_extended(batch)
        if not ext_ok and ext_reason ~= "signature_match" then
            if CONFIG.extended_mode == "block" then
                return { action = "reject", reason = ext_reason, items = #batch.values }
            end
            reason = ext_reason -- monitor: log it, score what was collected
        end
    end

    -- Signature hit in block mode: answer now, skipping the ML call entirely.
    if batch.regex_hit and CONFIG.regex_mode == "block" then
        return signature_decision(batch, CONFIG.monitor_only and "monitor" or "block")
    end

    local values = batch.values
    if #values == 0 then
        if batch.regex_hit then -- WAF_REGEX_MODE=monitor
            return signature_decision(batch, "monitor")
        end
        return { action = "skip", reason = reason }
    end

    ngx.update_time()
    local started = ngx.now()
    local probabilities, ml_request_id, err, sent = score_batch(values)
    ngx.update_time()
    local latency_ms = sent > 0 and (ngx.now() - started) * 1000 or nil

    -- Per-value thresholds. Cached verdicts still count when the API failed,
    -- so a known-bad value is blocked even during an outage.
    local flagged, top, hit_param, hit_extended = {}, nil, false, false
    for i = 1, #values do
        local p = probabilities[i]
        if p then
            local threshold = batch.extended[i] and CONFIG.extended_threshold or CONFIG.block_threshold
            if p >= threshold then
                flagged[#flagged + 1] = i
                if batch.extended[i] then hit_extended = true else hit_param = true end
            end
            if not top or p > probabilities[top] then
                top = i
            end
        end
    end
    if #flagged > 0 then
        table.sort(flagged, function(a, b) return probabilities[a] > probabilities[b] end)
        top = flagged[1]
    end

    local action
    if hit_param then
        action = CONFIG.monitor_only and "monitor" or "block"
    elseif hit_extended then
        action = (CONFIG.extended_mode == "block" and not CONFIG.monitor_only) and "block" or "monitor"
    elseif err then
        action = "fail"
    else
        action = "allow"
    end

    -- WAF_REGEX_MODE=monitor: a signature hit the model did not block is logged.
    if batch.regex_hit and action ~= "block" and action ~= "monitor" then
        local decision = signature_decision(batch, "monitor")
        decision.sent, decision.latency_ms, decision.ml_request_id = sent, latency_ms, ml_request_id
        return decision
    end

    return {
        action = action,
        reason = (#flagged > 0 and "sqli_detected") or err or reason,
        engine = "ml",
        score = top and probabilities[top],
        source = top and batch.labels[top],
        threshold = top and (batch.extended[top] and CONFIG.extended_threshold or CONFIG.block_threshold),
        flagged = flagged,
        batch = batch,
        probabilities = probabilities,
        ml_request_id = ml_request_id,
        items = #values,
        sent = sent,
        latency_ms = latency_ms,
    }
end

local function blocked_values(decision)
    if decision.engine == "regex" then
        local entry = { source = decision.source, signature = decision.signature.id }
        if CONFIG.alert_values then
            entry.value = to_valid_utf8(decision.regex_value:sub(1, ALERT_VALUE_CHARS))
        end
        return { entry }
    end
    local list = {}
    for n = 1, math.min(#decision.flagged, ALERT_MAX_VALUES) do
        local i = decision.flagged[n]
        local entry = {
            source = decision.batch.labels[i],
            probability = decision.probabilities[i],
        }
        if CONFIG.alert_values then
            entry.value = to_valid_utf8(decision.batch.values[i]:sub(1, ALERT_VALUE_CHARS))
        end
        list[n] = entry
    end
    return list
end

local function respond_json(status, body)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(cjson.encode(body))
    return ngx.exit(status)
end

-- Failures a client can cause itself, by sending a burst that overloads the
-- ML API. A single IP's burst of 100 requests made 70-84 of 100 SQLi attempts
-- time out and pass uninspected, even with micro-batching in the API.
local CLIENT_CAUSED_FAILURES = { ml_api_timeout = true, ml_api_status_503 = true }

-- Per-client fail-open budget: each client IP may fail open at most
-- WAF_FAIL_OPEN_BUDGET times per WAF_FAIL_OPEN_WINDOW_S; after that its
-- requests that can't be scored get 503 instead of passing. Outages don't
-- count (circuit breaker open, connection refused): an ML restart still fails
-- open for everyone.
local function fail_open_allowed(reason)
    if CONFIG.fail_open_budget < 0 or not CLIENT_CAUSED_FAILURES[reason] then
        return true
    end
    local count = ngx.shared.waf_state:incr("fo:" .. ngx.var.remote_addr, 1, 0, CONFIG.fail_open_window)
    return count == nil or count <= CONFIG.fail_open_budget
end

local ok, decision = pcall(inspect)
if not ok then
    ngx.log(ngx.ERR, "WAF internal error: ", decision)
    decision = { action = "fail", reason = "waf_internal_error" }
end

if decision.action == "fail" then
    local fail_open = CONFIG.fail_open
    if fail_open and not fail_open_allowed(decision.reason) then
        fail_open = false
        decision.reason = "fail_open_budget_exhausted:" .. decision.reason
    end
    decision.action = fail_open and "fail_open" or "fail_closed"
    ngx.log(ngx.ERR, "WAF could not score request ", ngx.var.request_id, ": ", decision.reason,
        fail_open and " (failing open)" or " (failing closed)")
end
if decision.action == "reject" and CONFIG.monitor_only then
    decision.action = "monitor"
end

-- Every request gets one JSON access-log line with these fields (see nginx.conf).
ngx.var.waf_action = decision.action
ngx.var.waf_reason = decision.reason or ""
ngx.var.waf_score = decision.score and string.format("%.4f", decision.score) or ""
ngx.var.waf_source = decision.source or ""
ngx.var.waf_engine = decision.engine or ""
ngx.var.waf_signature = decision.signature and decision.signature.id or ""
ngx.var.waf_items = tostring(decision.items or 0)
ngx.var.waf_ml_items = tostring(decision.sent or 0)
ngx.var.waf_latency_ms = decision.latency_ms and string.format("%.1f", decision.latency_ms) or ""
ngx.var.waf_ml_request_id = decision.ml_request_id or ""

if decision.reason == "sqli_detected" or decision.reason == "sqli_signature" then
    local signature = decision.signature
    fire_alert({
        event = "sqli_detected",
        action = decision.action,
        source_engine = decision.engine, -- "regex" or "ml"
        -- regex only: which signature matched (probability/threshold are then absent)
        signature = signature and { id = signature.id, pattern = signature.pattern } or nil,
        ts = iso_now(),
        request_id = ngx.var.request_id,
        ml_request_id = decision.ml_request_id,
        ip = ngx.var.remote_addr,
        method = ngx.req.get_method(),
        host = ngx.var.host,
        path = to_valid_utf8(ngx.var.uri:sub(1, ALERT_VALUE_CHARS)),
        probability = decision.score,
        threshold = decision.threshold,
        source = decision.source,
        flagged_count = signature and 1 or #decision.flagged,
        blocked_values = blocked_values(decision),
    })
end

if decision.action == "block" or decision.action == "reject" then
    return respond_json(ngx.HTTP_FORBIDDEN, { error = "forbidden", request_id = ngx.var.request_id })
end
if decision.action == "fail_closed" then
    return respond_json(ngx.HTTP_SERVICE_UNAVAILABLE, { error = "unavailable", request_id = ngx.var.request_id })
end
-- skip / allow / monitor / fail_open: continue to proxy_pass.
