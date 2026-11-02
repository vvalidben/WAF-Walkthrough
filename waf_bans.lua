--[[
Automatic IP bans, shared by the WAF (waf_interceptor.lua) and the admin
dashboard (waf_admin.lua).

A client IP that gets WAF_BAN_THRESHOLD blocked requests within
WAF_BAN_WINDOW_S seconds is refused outright for WAF_BAN_DURATION_S seconds:
its requests get the same 403 as a block, logged as waf_action "banned",
without inspection or an ML call, so a flood from it costs almost nothing.

Bans and counters live in the waf_bans shared dict, so every worker sees
them at once; they expire by themselves (dict TTL) and are cleared by a
restart. Loopback and WAF_BAN_ALLOWLIST (comma-separated exact IPs) are never
banned. WAF_BAN_THRESHOLD=0 disables automatic bans.

Behind a load balancer, every client has the balancer's IP: set real_ip
in nginx.conf first (README, section 7), or one ban blocks everyone.
]]

local cjson = require "cjson.safe"

local _M = {}

local function env_number(name, default)
    return tonumber(os.getenv(name) or "") or default
end

local THRESHOLD = env_number("WAF_BAN_THRESHOLD", 20)
local WINDOW = env_number("WAF_BAN_WINDOW_S", 600)
local DURATION = env_number("WAF_BAN_DURATION_S", 3600)

local ALLOWLIST = { ["127.0.0.1"] = true, ["::1"] = true }
for ip in (os.getenv("WAF_BAN_ALLOWLIST") or ""):gmatch("[^,%s]+") do
    ALLOWLIST[ip] = true
end

local function dict()
    return ngx.shared.waf_bans
end

function _M.settings()
    return { threshold = THRESHOLD, window = WINDOW, duration = DURATION, enabled = THRESHOLD > 0 }
end

function _M.allowlisted(ip)
    return ALLOWLIST[ip] == true
end

-- The ban record for an IP, or nil.
function _M.banned(ip)
    local value = dict():get("ban:" .. (ip or ""))
    return value and cjson.decode(value) or nil
end

-- Blocked requests counted for an IP in the current window.
function _M.strikes(ip)
    return dict():get("hits:" .. (ip or "")) or 0
end

function _M.ban(ip, info, duration)
    duration = duration or DURATION
    local now = ngx.time()
    local record = {
        ip = ip, since = now, expires = now + duration,
        by = info.by or "auto", blocks = info.blocks, category = info.category,
    }
    local ok, err = dict():set("ban:" .. ip, cjson.encode(record), duration)
    if not ok then
        ngx.log(ngx.ERR, "WAF ban of ", ip, " failed: ", err)
        return nil, err
    end
    ngx.log(ngx.WARN, "WAF ban: ", ip, " for ", duration, " s (", record.by,
            record.blocks and (", " .. record.blocks .. " blocked requests") or "", ")")
    return record
end

-- Count one blocked request. Returns the new ban record when this block
-- crossed the threshold, otherwise nil.
function _M.record_block(ip, category)
    if THRESHOLD <= 0 or not ip or ALLOWLIST[ip] then
        return nil
    end
    -- Fixed window from the first block; the counter expires with it.
    local count = dict():incr("hits:" .. ip, 1, 0, WINDOW)
    if count and count >= THRESHOLD and not dict():get("ban:" .. ip) then
        return _M.ban(ip, { by = "auto", blocks = count, category = category })
    end
    return nil
end

-- Lift a ban and forget the IP's blocked-request count.
function _M.unban(ip)
    local was = dict():get("ban:" .. ip) ~= nil
    dict():delete("ban:" .. ip)
    dict():delete("hits:" .. ip)
    if was then
        ngx.log(ngx.WARN, "WAF ban lifted: ", ip)
    end
    return was
end

-- Active bans, newest first.
function _M.list()
    local now, bans = ngx.time(), {}
    for _, key in ipairs(dict():get_keys(2048)) do
        if key:sub(1, 4) == "ban:" then
            local record = _M.banned(key:sub(5))
            if record then
                record.remaining = math.max(0, record.expires - now)
                bans[#bans + 1] = record
            end
        end
    end
    table.sort(bans, function(a, b) return a.since > b.since end)
    return bans
end

return _M
