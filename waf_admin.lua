--[[
Admin API for the "protect a site" page (content_by_lua_file, port 8081).

  GET  /api/target        the current target and where it came from
  POST /api/target        {"url": "...", "force": false} check the site answers,
                          then put the WAF in front of it (waf_target.lua)
  POST /api/reset         forget the saved target, fall back to .env
  POST /api/test          one normal request and one SQL injection through the
                          WAF, to show what it allows and blocks

Security dashboard (admin/dashboard.*, data from waf_dashboard.lua):
  GET  /api/status        mode, thresholds, rules switched on
  GET  /api/overview      24 h totals, per hour, top rules and IPs
  GET  /api/feed?limit=   the newest decisions
  GET  /api/event?id=     one request by request_id, with what matched
  GET  /api/rules         every signature, its state and 24 h hits
  POST /api/rules         {"id": "...", "enabled": false} switch one signature
  POST /api/evaluate      {"payload": "..."} dry run of signatures + model
  POST /api/false-positive {"id": "<request_id>"} send the value to the model's
                          training data as safe (needs FEEDBACK_API_KEY)

The port is published on 127.0.0.1 only. On top of that, requests must carry a
localhost Host header (defeats DNS rebinding), and POSTs must be JSON with no
foreign Origin, so a web page open in your browser can't change the target
(a cross-site JSON POST needs a CORS preflight, which this never approves).
]]

local http = require "resty.http"
local target = require "waf_target"
local dashboard = require "waf_dashboard"
local waf_rules = require "waf_rules"
local cjson = dashboard.json

-- The WAF's own listener inside the container (nginx.conf).
local WAF_URL = "http://127.0.0.1:8080"
local TEST_ATTACK = "1' OR '1'='1"

local function reply(status, body)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(cjson.encode(body))
    return ngx.exit(ngx.HTTP_OK)
end

local function allowed_origin()
    local host = (ngx.var.http_host or ""):lower()
    local name = host:match("^([^:]+)")
    if name ~= "127.0.0.1" and name ~= "localhost" then
        return false
    end
    local origin = ngx.var.http_origin
    return origin == nil or origin:lower() == "http://" .. host
end

local function json_body()
    if not (ngx.var.content_type or ""):lower():find("^application/json") then
        return nil
    end
    ngx.req.read_body()
    local body = cjson.decode(ngx.req.get_body_data() or "{}")
    return type(body) == "table" and body or nil
end

-- Does the site answer at all? Any HTTP status counts; only connection,
-- DNS and TLS failures don't.
local function probe(url)
    local httpc = http.new()
    httpc:set_timeouts(3000, 3000, 5000)
    local res, err = httpc:request_uri(url .. "/", {
        method = "GET",
        headers = { ["User-Agent"] = "sqli-waf-admin/1.0" },
        ssl_verify = true,
    })
    if not res then
        return nil, err
    end
    return res.status
end

local function through_waf(query)
    local httpc = http.new()
    httpc:set_timeouts(3000, 3000, 15000)
    local res, err = httpc:request_uri(WAF_URL .. "/?" .. ngx.encode_args(query), {
        headers = { ["User-Agent"] = "sqli-waf-admin/1.0 (self-test)" },
    })
    if not res then
        return { error = err }
    end
    return { status = res.status, request_id = res.headers["X-Request-ID"] }
end

if not allowed_origin() then
    return reply(403, { error = "Open this page at http://127.0.0.1:8081." })
end

local method, uri = ngx.req.get_method(), ngx.var.uri

if method == "GET" and uri == "/api/target" then
    return reply(200, target.current())
end

if method == "GET" then
    if uri == "/api/status" then
        local status = dashboard.status()
        status.target = target.current()
        return reply(200, status)
    elseif uri == "/api/overview" then
        local overview = dashboard.overview()
        overview.rule_hits = nil
        return reply(200, overview)
    elseif uri == "/api/feed" then
        return reply(200, { events = dashboard.feed(ngx.var.arg_limit) })
    elseif uri == "/api/event" then
        local event = dashboard.event(ngx.var.arg_id)
        if not event then
            return reply(404, { error = "No request with that id in the last 24 hours." })
        end
        return reply(200, event)
    elseif uri == "/api/rules" then
        return reply(200, dashboard.rules())
    end
end

if method ~= "POST" then
    return reply(405, { error = "method not allowed" })
end
local body = json_body()
if not body then
    return reply(415, { error = "expected a JSON body" })
end

if uri == "/api/target" then
    local new, notes = target.normalize(body.url)
    if not new then
        return reply(400, { error = notes })
    end
    local status, err = probe(new.url)
    if not status and body.force ~= true then
        return reply(502, { error = "Couldn't reach " .. new.url .. ": " .. tostring(err),
                            can_force = true, target = new })
    end
    local saved, save_err = target.save(new, body.url)
    if not saved then
        notes[#notes + 1] = "Applied, but couldn't be saved (" .. tostring(save_err)
            .. "), so it resets when the WAF restarts."
    end
    ngx.log(ngx.WARN, "WAF admin: now protecting ", new.url,
            " (Host: ", new.host ~= "" and new.host or "visitor's", ")")
    local current = target.current()
    current.notes = setmetatable(notes, cjson.array_mt)  -- [] rather than {} when empty
    current.probe_status = status
    return reply(200, current)
end

if uri == "/api/reset" then
    local ok, err = target.reset()
    if not ok then
        return reply(500, { error = "Couldn't delete the saved target: " .. tostring(err) })
    end
    ngx.log(ngx.WARN, "WAF admin: saved target removed, using .env")
    return reply(200, target.current())
end

if uri == "/api/test" then
    return reply(200, {
        benign = through_waf({ q = "running shoes" }),
        attack = through_waf({ id = TEST_ATTACK }),
        attack_value = TEST_ATTACK,
    })
end

if uri == "/api/rules" then
    if type(body.id) ~= "string" or type(body.enabled) ~= "boolean" then
        return reply(400, { error = 'expected {"id": "<rule id>", "enabled": true|false}' })
    end
    local signature = waf_rules.BY_ID[body.id]
    if not signature then
        return reply(404, { error = "unknown rule" })
    end
    if waf_rules.ENV_DISABLED[signature.category] then
        return reply(409, { error = "The " .. signature.category .. " category is switched off with "
            .. "WAF_DISABLED_CATEGORIES in .env; change it there." })
    end
    local saved, err = waf_rules.set_enabled(body.id, body.enabled)
    ngx.log(ngx.WARN, "WAF admin: rule ", body.id, body.enabled and " switched on" or " switched off")
    local rules = dashboard.rules()
    if not saved then
        rules.warning = "Applied, but couldn't be saved (" .. tostring(err) .. "), so it resets when the WAF restarts."
    end
    return reply(200, rules)
end

if uri == "/api/evaluate" then
    local result, err = dashboard.evaluate(body.payload)
    if not result then
        return reply(400, { error = err })
    end
    return reply(200, result)
end

if uri == "/api/false-positive" then
    local key = os.getenv("FEEDBACK_API_KEY")
    if not key or #key < 16 then
        return reply(501, { error = "Feedback is off. Set FEEDBACK_API_KEY (16+ characters) in .env and run "
            .. "docker compose up -d." })
    end
    local event = dashboard.event(body.id)
    if not event then
        return reply(404, { error = "No request with that id in the last 24 hours." })
    end
    if event.engine ~= "ml" then
        return reply(409, { error = "A signature decided this request; training data can't change that. "
            .. "Switch the rule off on the Rules screen instead." })
    end
    if not event.payload then
        return reply(409, { error = "The value isn't in the log (" .. tostring(event.source)
            .. "), so it can't be sent as feedback." })
    end
    local httpc = http.new()
    httpc:set_timeouts(1000, 1000, 5000)
    local feedback_url = (os.getenv("WAF_SCAN_URL") or "http://ml-api:8000/scan/batch"):gsub("/scan/batch$", "/feedback")
    local res, ferr = httpc:request_uri(feedback_url, {
        method = "POST",
        headers = { ["Content-Type"] = "application/json", ["Authorization"] = "Bearer " .. key },
        body = cjson.encode({ query = event.payload, label = 0, source = event.source,
                              flagged_by = "dashboard", request_id = event.id }),
    })
    if not res then
        return reply(502, { error = "The ML API didn't answer: " .. tostring(ferr) })
    end
    local answer = cjson.decode(res.body or "") or {}
    if res.status ~= 201 and res.status ~= 200 then -- 200: already recorded
        return reply(502, { error = "The ML API refused it (HTTP " .. res.status .. ")." })
    end
    ngx.log(ngx.WARN, "WAF admin: request ", event.id, " flagged as false positive")
    return reply(200, { status = answer.status or "recorded" })
end

return reply(404, { error = "not found" })
