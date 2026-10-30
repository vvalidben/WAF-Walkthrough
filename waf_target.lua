--[[
The site the WAF protects (the proxy_pass target), switchable at runtime.

The admin page (waf_admin.lua, port 8081) stores the target in the
waf_config shared dict, so a change applies to the next request in every
worker without a reload, and saves it to TARGET_FILE (the waf_config volume)
so it survives restarts. Without a saved target, WAF_BACKEND_URL and
WAF_BACKEND_HOST from .env apply, and without those the placeholder backend.

The dict holds one value, "<backend url>|<host header>", so a request never
sees the URL of one target with the Host header of another.
]]

local cjson = require "cjson.safe"

local _M = {}

local TARGET_FILE = "/var/lib/waf/target.json"
local DEFAULT_URL = "http://backend_app:8080"

-- Services on the WAF's own networks: proxying public traffic to them would
-- expose them (ml-api sits on an internal-only network on purpose).
local RESERVED = {
    ["ml-api"] = true, openresty = true, loki = true, grafana = true, alloy = true,
    ["127.0.0.11"] = true,
}

-- "This computer" to whoever pastes the URL, but the container itself to
-- nginx; host.docker.internal is the host machine (extra_hosts in compose).
local LOOPBACK = { localhost = true, ["127.0.0.1"] = true, ["0.0.0.0"] = true }

local function env_string(name)
    local value = os.getenv(name)
    if value == nil or value == "" then
        return nil
    end
    return value
end

local function split(packed)
    local url, host = packed:match("^([^|]*)|(.*)$")
    return url, host
end

-- init_by_lua: restore the target saved from the admin page, if any.
function _M.load()
    local file = io.open(TARGET_FILE, "r")
    if not file then
        return
    end
    local saved = cjson.decode(file:read("*a") or "")
    file:close()
    if type(saved) == "table" and type(saved.url) == "string" and type(saved.host) == "string" then
        local dict = ngx.shared.waf_config
        dict:set("target", saved.url .. "|" .. saved.host)
        dict:set("input", saved.input or saved.url)
        dict:set("updated_at", saved.updated_at or "")
    end
end

-- Per request ($backend): the URL nginx proxies to.
function _M.url()
    local packed = ngx.shared.waf_config:get("target")
    if packed then
        return (split(packed))
    end
    return env_string("WAF_BACKEND_URL") or DEFAULT_URL
end

-- Per request ($backend_host): the Host header for the backend, "" to pass
-- the visitor's Host through.
function _M.host()
    local packed = ngx.shared.waf_config:get("target")
    if packed then
        local _, host = split(packed)
        return host
    end
    return env_string("WAF_BACKEND_HOST") or ""
end

-- The target and where it came from, for the admin page.
function _M.current()
    local dict = ngx.shared.waf_config
    local packed = dict:get("target")
    if packed then
        local url, host = split(packed)
        return { url = url, host = host, source = "admin",
                 input = dict:get("input"), updated_at = dict:get("updated_at") }
    end
    local url = env_string("WAF_BACKEND_URL") or DEFAULT_URL
    return { url = url, host = env_string("WAF_BACKEND_HOST") or "",
             source = url == DEFAULT_URL and "default" or "env" }
end

-- Turn whatever was pasted ("example.com", "https://app.vercel.app/login",
-- "localhost:3000") into a target, or nil and a message for the user.
-- Returns the target and a list of notes about what was changed.
function _M.normalize(input)
    if type(input) ~= "string" then
        return nil, "Paste a website address."
    end
    local text = input:gsub("^%s+", ""):gsub("%s+$", "")
    if text == "" then
        return nil, "Paste a website address."
    end
    if #text > 2048 then
        return nil, "That address is too long."
    end

    local had_scheme = text:find("://", 1, true) ~= nil
    if not had_scheme then
        text = "https://" .. text
    end
    local scheme, rest = text:match("^(%a[%w+.-]*)://(.*)$")
    scheme = scheme and scheme:lower()
    if scheme ~= "http" and scheme ~= "https" then
        return nil, "Only http:// and https:// addresses are supported."
    end

    local authority, path = rest:match("^([^/?#]*)(.*)$")
    if authority:find("@", 1, true) then
        return nil, "Addresses with a username or password in them aren't supported."
    end
    local hostname, port = authority:match("^([^:]+):(%d+)$")
    if not hostname then
        if authority:find(":", 1, true) then
            return nil, "That port isn't valid (IPv6 addresses aren't supported)."
        end
        hostname = authority
    end
    hostname = hostname:lower():gsub("%.$", "")
    -- "_" for compose service names like backend_app.
    if hostname == "" or not hostname:match("^[%w][%w._-]*$") then
        return nil, "That doesn't look like a website address."
    end
    if port and (tonumber(port) < 1 or tonumber(port) > 65535) then
        return nil, "That port isn't valid."
    end
    if RESERVED[hostname] then
        return nil, "'" .. hostname .. "' is part of the WAF itself and can't be put behind it."
    end

    local notes = {}
    if LOOPBACK[hostname] then
        if not had_scheme then
            scheme = "http"
        end
        notes[#notes + 1] = "'" .. hostname .. "' inside the WAF container means the container itself, "
            .. "so it was changed to host.docker.internal (this computer)."
        hostname = "host.docker.internal"
    end
    if path ~= "" and path ~= "/" then
        notes[#notes + 1] = "The WAF protects the whole site, so '" .. path .. "' was dropped. "
            .. "Open that page through the WAF instead."
    end

    local hostport = port and (hostname .. ":" .. port) or hostname
    -- Public sites (Vercel, Netlify, any shared host) route by name, so they
    -- need their own hostname as Host; local apps and compose services
    -- keep the visitor's Host.
    local public = hostname:find(".", 1, true) and hostname ~= "host.docker.internal"
        and not hostname:match("^%d+%.%d+%.%d+%.%d+$")
    return { url = scheme .. "://" .. hostport, host = public and hostport or "" }, notes
end

-- Persist and apply a target. Applies even if saving fails (the error is
-- returned so the page can say it won't survive a restart).
function _M.save(target, input)
    local record = { url = target.url, host = target.host, input = input,
                     updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()) }
    local dict = ngx.shared.waf_config
    dict:set("target", record.url .. "|" .. record.host)
    dict:set("input", record.input)
    dict:set("updated_at", record.updated_at)

    -- Write then rename, so a crash can't leave a half-written file.
    local tmp = TARGET_FILE .. ".tmp"
    local file, err = io.open(tmp, "w")
    if not file then
        return nil, err
    end
    file:write(cjson.encode(record))
    file:close()
    local ok, rename_err = os.rename(tmp, TARGET_FILE)
    if not ok then
        return nil, rename_err
    end
    return true
end

-- Forget the saved target and fall back to .env.
function _M.reset()
    local dict = ngx.shared.waf_config
    dict:delete("target")
    dict:delete("input")
    dict:delete("updated_at")
    local ok, err = os.remove(TARGET_FILE)
    if not ok and io.open(TARGET_FILE, "r") then
        return nil, err
    end
    return true
end

return _M
