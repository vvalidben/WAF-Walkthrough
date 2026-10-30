--[[
Admin API for the "protect a site" page (content_by_lua_file, port 8081).

  GET  /api/target        the current target and where it came from
  POST /api/target        {"url": "...", "force": false} check the site answers,
                          then put the WAF in front of it (waf_target.lua)
  POST /api/reset         forget the saved target, fall back to .env
  POST /api/test          one normal request and one SQL injection through the
                          WAF, to show what it allows and blocks

The port is published on 127.0.0.1 only. On top of that, requests must carry a
localhost Host header (defeats DNS rebinding), and POSTs must be JSON with no
foreign Origin, so a web page open in your browser can't change the target
(a cross-site JSON POST needs a CORS preflight, which this never approves).
]]

local cjson = require "cjson.safe"
local http = require "resty.http"
local target = require "waf_target"

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

return reply(404, { error = "not found" })
