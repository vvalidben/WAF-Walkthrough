--[[
Data for the security dashboard (admin/dashboard.*), served by waf_admin.lua.

Everything comes from the WAF's own hourly access-log files (nginx.conf,
/var/log/waf/access-YYYY-MM-DDTHH.log, kept WAF_LOG_RETENTION_HOURS = 24 h):
  overview()      24 h totals, requests and blocks per hour, top rules and IPs
  feed(limit)     the newest decisions, read from the end of the newest files
  event(id)       one request by request_id, with the value that triggered it
                  and the signature span to highlight
  rules()         every signature with its state and 24 h hit count
  evaluate(text)  dry run of the real signatures and the ML model on one value;
                  nothing is sent to the protected site

The log stores the request URI and User-Agent but not bodies, cookies or other
headers, so the triggering value can only be recovered for parameters in the
URL, the path and the User-Agent (payload_of).
]]

local cjson = require("cjson.safe").new()
local http = require "resty.http"
local waf_rules = require "waf_rules"

local _M = {}

local LOG_FILE = "!/var/log/waf/access-%Y-%m-%dT%H.log" -- os.date format, UTC
local HOURS = 24
local MAX_LINES = 500000     -- overview stops counting past this many lines
local TAIL_BYTES = 512 * 1024
local OVERVIEW_TTL = 5       -- seconds the overview is cached for

-- Decoded arrays keep the array metatable, so an empty list survives the
-- overview cache's round trip as [] rather than {}.
cjson.decode_array_with_array_mt(true)

local BLOCKED = { block = true, reject = true, fail_closed = true }

local function env_number(name, default)
    return tonumber(os.getenv(name) or "") or default
end

local function settings()
    return {
        mode = os.getenv("WAF_MODE") == "monitor" and "monitor" or "block",
        regex_mode = os.getenv("WAF_REGEX_MODE") or "block",
        extended_mode = os.getenv("WAF_EXTENDED_MODE") or "monitor",
        threshold = env_number("WAF_BLOCK_THRESHOLD", 0.5),
        extended_threshold = env_number("WAF_EXTENDED_THRESHOLD", 0.8),
    }
end

local function hour_file(hours_ago)
    return os.date(LOG_FILE, ngx.time() - hours_ago * 3600)
end

local function decode_line(line)
    if line:byte(1) ~= 123 then -- "{"
        return nil
    end
    return cjson.decode(line)
end

-- The value that triggered a decision, from what the log keeps, or nil.
local function payload_of(entry)
    local source = entry.waf_source or ""
    local uri = entry.request_uri or ""
    local query = uri:match("%?(.*)$")
    local name = source:match("^arg:(.+)$")
    if name and query then
        local value = ngx.decode_args(query, 100)[name]
        if type(value) == "table" then
            value = value[1]
        end
        return type(value) == "string" and value or nil
    end
    if source == "arg-name" and query then
        local names = {}
        for key in pairs(ngx.decode_args(query, 100)) do
            if type(key) == "string" and key:find("[^%w_.~-]") then
                names[#names + 1] = key
            end
        end
        return names[1]
    end
    if source == "header:user-agent" then
        return entry.user_agent
    end
    if source == "path" or source == "path:segment" then
        return ngx.unescape_uri(uri:match("^[^?#]*"))
    end
    return nil
end

-- Attack category of a block or monitor entry. Lines logged before
-- waf_category existed get it from the signature id (or "sqli" for the model).
local function category_of(entry)
    if entry.waf_category and entry.waf_category ~= "" then
        return entry.waf_category
    end
    local signature = waf_rules.BY_ID[entry.waf_signature or ""]
    if signature then
        return signature.category
    end
    if entry.waf_engine == "ml" and (entry.waf_action == "block" or entry.waf_action == "monitor") then
        return "sqli"
    end
    return nil
end

-- What the dashboard shows for one log entry.
local function shape(entry)
    local signature = entry.waf_signature ~= "" and entry.waf_signature or nil
    return {
        id = entry.request_id,
        ts = entry.timestamp,
        ip = entry.client_ip,
        method = entry.request_method,
        uri = entry.request_uri,
        path = entry.path,
        host = entry.host,
        ua = entry.user_agent,
        status = entry.status,
        action = entry.waf_action,
        engine = entry.waf_engine ~= "" and entry.waf_engine or nil,
        signature = signature,
        category = category_of(entry),
        score = tonumber(entry.ml_probability),
        source = entry.waf_source ~= "" and entry.waf_source or nil,
        reason = entry.waf_reason ~= "" and entry.waf_reason or nil,
        payload = payload_of(entry),
    }
end

local function top(counts, n)
    local list = {}
    for key, count in pairs(counts) do
        list[#list + 1] = { key = key, count = count }
    end
    table.sort(list, function(a, b) return a.count > b.count or (a.count == b.count and a.key < b.key) end)
    local out = {}
    for i = 1, math.min(n, #list) do
        out[i] = list[i]
    end
    return out
end

local function most(counts)
    local best, n = nil, 0
    for key, count in pairs(counts) do
        if count > n then
            best, n = key, count
        end
    end
    return best
end

local function compute_overview()
    local now = ngx.time()
    local hour_start = now - now % 3600
    local hours, rules, ips = {}, {}, {}
    local totals = { requests = 0, blocked = 0, monitored = 0, fail_open = 0 }
    local lines, truncated = 0, false

    for ago = HOURS - 1, 0, -1 do
        local bucket = { t = hour_start - ago * 3600, total = 0, blocked = 0 }
        hours[#hours + 1] = bucket
        local file = not truncated and io.open(hour_file(ago), "r")
        if file then
            for line in file:lines() do
                lines = lines + 1
                if lines > MAX_LINES then
                    truncated = true
                    break
                end
                local entry = decode_line(line)
                if entry then
                    local action = entry.waf_action or ""
                    totals.requests = totals.requests + 1
                    bucket.total = bucket.total + 1
                    if action == "monitor" then
                        totals.monitored = totals.monitored + 1
                    elseif action == "fail_open" then
                        totals.fail_open = totals.fail_open + 1
                    end
                    if BLOCKED[action] or action == "monitor" then
                        local rule = entry.waf_signature ~= "" and entry.waf_signature
                            or (entry.waf_engine == "ml" and "ml_model") or nil
                        if rule then
                            rules[rule] = (rules[rule] or 0) + 1
                        end
                    end
                    if BLOCKED[action] then
                        totals.blocked = totals.blocked + 1
                        bucket.blocked = bucket.blocked + 1
                        local ip = ips[entry.client_ip]
                        if not ip then
                            ip = { count = 0, categories = {}, rules = {}, last = "" }
                            ips[entry.client_ip] = ip
                        end
                        ip.count = ip.count + 1
                        ip.last = entry.timestamp or ip.last
                        local category = category_of(entry) or "other"
                        ip.categories[category] = (ip.categories[category] or 0) + 1
                        local rule = entry.waf_signature ~= "" and entry.waf_signature or entry.waf_engine
                        if rule and rule ~= "" then
                            ip.rules[rule] = (ip.rules[rule] or 0) + 1
                        end
                    end
                end
            end
            file:close()
        end
    end

    local ip_counts, hostile = {}, 0
    for address, ip in pairs(ips) do
        ip_counts[address] = ip.count
        hostile = hostile + 1
    end
    local top_ips = {}
    for i, item in ipairs(top(ip_counts, 5)) do
        local ip = ips[item.key]
        top_ips[i] = { ip = item.key, blocked = ip.count, category = most(ip.categories),
                       rule = most(ip.rules), last = ip.last }
    end
    local top_rules = {}
    for i, item in ipairs(top(rules, 6)) do
        local signature = waf_rules.BY_ID[item.key]
        top_rules[i] = { id = item.key, hits = item.count,
                         category = signature and signature.category or "sqli" }
    end

    return {
        generated_at = now,
        requests = totals.requests,
        blocked = totals.blocked,
        monitored = totals.monitored,
        fail_open = totals.fail_open,
        hostile_ips = hostile,
        hours = hours,
        top_rules = setmetatable(top_rules, cjson.array_mt),
        top_ips = setmetatable(top_ips, cjson.array_mt),
        rule_hits = rules,
        truncated = truncated,
    }
end

function _M.overview()
    local dict = ngx.shared.waf_config
    local cached = dict:get("dashboard_overview")
    if cached then
        local value = cjson.decode(cached)
        if value then
            return value
        end
    end
    local value = compute_overview()
    dict:set("dashboard_overview", cjson.encode(value), OVERVIEW_TTL)
    return value
end

-- The last TAIL_BYTES of a file as complete lines, oldest first.
local function tail_lines(path)
    local file = io.open(path, "r")
    if not file then
        return {}
    end
    local size = file:seek("end")
    local start = math.max(0, size - TAIL_BYTES)
    file:seek("set", start)
    local data = file:read("*a") or ""
    file:close()
    local lines = {}
    for line in data:gmatch("[^\n]+") do
        lines[#lines + 1] = line
    end
    if start > 0 then
        table.remove(lines, 1) -- cut mid-line
    end
    return lines
end

-- Newest first. "skip" decisions (nothing to inspect, e.g. a plain page or
-- asset load) are left out.
function _M.feed(limit)
    limit = math.max(1, math.min(tonumber(limit) or 60, 200))
    local events = {}
    for ago = 0, 1 do
        local lines = tail_lines(hour_file(ago))
        for i = #lines, 1, -1 do
            local entry = decode_line(lines[i])
            if entry and entry.waf_action ~= "skip" and entry.waf_action ~= "" then
                events[#events + 1] = shape(entry)
                if #events >= limit then
                    return events
                end
            end
        end
    end
    return setmetatable(events, cjson.array_mt)
end

local function spans(value)
    local hits = {}
    for _, hit in ipairs(waf_rules.match_all(value)) do
        local signature = hit.signature
        hits[#hits + 1] = {
            id = signature.id, category = signature.category, pattern = signature.pattern,
            from = hit.from, to = hit.to,
        }
    end
    return setmetatable(hits, cjson.array_mt)
end

function _M.event(id)
    if type(id) ~= "string" or not id:match("^%x+$") then
        return nil
    end
    local needle = '"request_id":"' .. id .. '"'
    local found, ip_count = nil, 0
    for ago = 0, HOURS - 1 do
        local file = io.open(hour_file(ago), "r")
        if file then
            for line in file:lines() do
                if not found and line:find(needle, 1, true) then
                    found = decode_line(line)
                end
            end
            file:close()
        end
        if found then
            break
        end
    end
    if not found then
        return nil
    end
    -- How often this client was blocked in the last 24 h.
    local needle_ip = '"client_ip":"' .. (found.client_ip or "") .. '"'
    for ago = 0, HOURS - 1 do
        local file = io.open(hour_file(ago), "r")
        if file then
            for line in file:lines() do
                if line:find(needle_ip, 1, true) and line:find('"waf_action":"block"', 1, true) then
                    ip_count = ip_count + 1
                end
            end
            file:close()
        end
    end

    local event = shape(found)
    event.ip_blocked_24h = ip_count
    event.hits = event.payload and spans(event.payload) or setmetatable({}, cjson.array_mt)
    event.settings = settings()
    return event
end

function _M.rules()
    local off = waf_rules.disabled_ids()
    local hits = _M.overview().rule_hits or {}
    local list, on = {}, 0
    for _, signature in ipairs(waf_rules.SIGNATURES) do
        local reason = waf_rules.off_reason(signature, off)
        if not reason then
            on = on + 1
        end
        list[#list + 1] = {
            id = signature.id, category = signature.category, pattern = signature.pattern,
            enabled = reason == nil, locked = reason == "env", hits = hits[signature.id] or 0,
        }
    end
    return { rules = list, on = on, total = #list, ml_hits = hits.ml_model or 0, settings = settings() }
end

function _M.status()
    local rules = _M.rules()
    local s = rules.settings
    s.rules_on, s.rules_total = rules.on, rules.total
    return s
end

-- Score one value with the model, as the WAF would (nil when the WAF would
-- skip it: only letters, digits and "._~" can't carry SQL).
local function ml_score(value)
    if not value:find("[^%w%._~]") or not value:find("%S") then
        return nil, "skipped"
    end
    local httpc = http.new()
    httpc:set_timeouts(1000, 1000, 3000)
    local res, err = httpc:request_uri(os.getenv("WAF_SCAN_URL") or "http://ml-api:8000/scan/batch", {
        method = "POST",
        body = cjson.encode({ queries = { value:sub(1, 1024) } }),
        headers = { ["Content-Type"] = "application/json" },
    })
    if not res then
        return nil, err
    end
    local body = cjson.decode(res.body or "")
    if res.status ~= 200 or type(body) ~= "table" or type(body.probabilities) ~= "table" then
        return nil, "ml_api_status_" .. res.status
    end
    return tonumber(body.probabilities[1])
end

-- Dry run: what the WAF would decide for one query-parameter value. The
-- input is the raw (URL-encoded) value; nginx decodes it once, as here.
function _M.evaluate(raw)
    if type(raw) ~= "string" then
        return nil, "payload must be a string"
    end
    if #raw > 8192 then
        return nil, "payload too long (8 KB max)"
    end
    local s = settings()
    local decoded = ngx.unescape_uri((raw:gsub("%+", " ")))
    local hits = s.regex_mode ~= "off" and spans(decoded) or setmetatable({}, cjson.array_mt)
    local score, ml_error = nil, nil
    if #hits == 0 or s.regex_mode ~= "block" then
        score, ml_error = ml_score(decoded)
    end

    local verdict, engine
    if #hits > 0 and s.regex_mode == "block" then
        verdict, engine = "block", "regex"
    elseif score and score >= s.threshold then
        verdict, engine = "block", "ml"
    elseif #hits > 0 then
        verdict, engine = "monitor", "regex" -- WAF_REGEX_MODE=monitor
    else
        verdict, engine = "allow", score and "ml" or nil
    end
    if verdict == "block" and s.mode == "monitor" then
        verdict = "monitor"
    end
    return {
        decoded = decoded, hits = hits, score = score, ml_error = ml_error,
        verdict = verdict, engine = engine, settings = s,
    }
end

-- The JSON codec these tables were built for (its array_mt marks lists).
_M.json = cjson

return _M
