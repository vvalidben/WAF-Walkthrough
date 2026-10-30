--[[
Regex signatures and which of them are switched on, shared by the WAF
(waf_interceptor.lua) and the admin dashboard (waf_admin.lua).

A signature is off when its category is in WAF_DISABLED_CATEGORIES (fixed at
startup), or when it was switched off on the dashboard's Rules screen. The
dashboard's choices live in the waf_config shared dict, with a version counter
that every worker checks per request, so a toggle applies to the next request
without a reload; they are saved to RULES_FILE (the waf_config volume) so they
survive restarts.
]]

local cjson = require "cjson.safe"

local _M = {}

local RULES_FILE = "/var/lib/waf/rules.json"

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
        -- SQL injection (the ML model covers what these miss)
        { id = "union_select", category = "sqli",
          pattern = [=[\bunion]=] .. SEPP .. [=[(?:(?:all|distinct)]=] .. SEPP .. [=[)?select\b]=] },
        { id = "stacked_query", category = "sqli",
          pattern = ";" .. GAP .. [=[(?:drop]=] .. SEP .. [=[(?:table|database|schema)\b|truncate]=] .. SEP
              .. [=[table\b|declare]=] .. SEP .. [=[@\w|exec(?:ute)?]=] .. SEP .. [=[(?:master\.|xp_|sp_))]=] },
        { id = "dangerous_procedure", category = "sqli",
          pattern = [=[\b(?:xp_cmdshell|xp_regread|xp_dirtree|sp_oacreate|sp_makewebtask)\b]=] },
        { id = "time_delay", category = "sqli",
          pattern = [=[\bwaitfor]=] .. SEP .. [=[delay]=] .. GAP .. [=['\d|\bbenchmark\s*+\(\s*+\d++\s*+,]=]
              .. [=[|(?:\b(?:and|or|select|if|then|when)|[(,'"|+])]=] .. GAP .. [=[(?:pg_)?sleep\s*+\(\s*+\d]=] },
        { id = "tautology", category = "sqli", -- ' or '1'='1   ') OR ('a'='a   '/**/or/**/1=1
          pattern = [=[['"]]=] .. GAPP .. [=[(?:or|\|\|)(?:]=] .. SEPP .. [=[|(?=['"\d]))['"]?(?<a>\w++)['"]?]=]
              .. GAP .. "=" .. GAPP .. [=[['"]?\k<a>\b]=] },
        { id = "numeric_tautology", category = "sqli",
          pattern = [=[\b(?:or|and)]=] .. SEP .. [=[(?<b>\d++)]=] .. GAP .. "=" .. GAP .. [=[\k<b>\b]=] },
        -- Blind extraction with a subquery as the condition. Needs a comparison
        -- after the subquery (or "=(SELECT"), so "and (select one from the
        -- list)" in prose doesn't count.
        { id = "boolean_subquery", category = "sqli", -- 1 AND (SELECT ...)='a'   1 AND 1=(SELECT ...)
          pattern = [=[(?:\b(?:and|or|xor|having|where)\b|&&|\|\|)]=] .. GAP .. [=[\(]=] .. GAP
              .. [=[select\b.{0,250}?\)]=] .. GAP .. [=[(?:[=<>!]|\b(?:like|between|in|is)\b)]=]
              .. [=[|\b(?:and|or|xor|having|where)\b]=] .. GAP .. [=[[\w'"]++]=] .. GAP .. [=[(?:[=<>]|!=)]=]
              .. GAP .. [=[\(]=] .. GAP .. [=[select\b]=] },
        { id = "quote_comment", category = "sqli",
          pattern = [=['[\s)]*+(?:--|/\*|#\s*+$)|"[\s)]*+(?:--[\s;]*+$|/\*)]=] },
        { id = "mysql_versioned_comment", category = "sqli",
          pattern = [=[/\*!(?:\d{5}|\s*+(?:union|select|and|or|insert|update|delete)\b)]=] },
        { id = "comment_obfuscation", category = "sqli",
          pattern = [=[\b]=] .. KEYWORD .. COMMENT .. [=[(?:\w|['"(@])]=] },
        { id = "system_catalog", category = "sqli",
          pattern = [=[\b(?:information_schema|sqlite_master|pg_catalog|mysql\.user|sysobjects|syscolumns)\b]=]
              .. [=[|@@(?:version|datadir|hostname|basedir)\b]=] },
        { id = "file_access", category = "sqli",
          pattern = [=[\binto]=] .. SEP .. [=[(?:out|dump)file\b|\bload_file\s*+\(]=] },
        { id = "error_based", category = "sqli",
          pattern = [=[\b(?:extractvalue|updatexml)\s*+\(|\bexp\s*+\(\s*+~|\bconvert\s*+\(\s*+int\s*+,]=] },
        { id = "char_concat", category = "sqli",
          pattern = [=[\bchar\s*+\(\s*+\d++\s*+\)\s*+(?:\|\||\+|,\s*+char\b)]=] },

        -- Cross-site scripting. Plain formatting tags (<b>, <img src=...>) are
        -- not signatures: rich-text editors send them. Only script-capable
        -- tags, event handlers, script URLs and DOM sinks are.
        { id = "xss_script_tag", category = "xss",
          pattern = [=[<\s*+/?\s*+(?:script|iframe|object|embed|applet|base|frameset)\b]=] },
        { id = "xss_event_handler", category = "xss", -- " onerror=   <svg/onload=
          pattern = [=[(?:^|[\s"'/;<>`])on(?:abort|animation\w++|auxclick|before\w++|blur|canplay\w*+|change]=]
              .. [=[|click|contextmenu|copy|cut|dblclick|drag\w*+|drop|error|focus\w*+|hashchange|input|invalid]=]
              .. [=[|key(?:down|press|up)|load\w*+|message|mouse\w++|page(?:show|hide)|paste|pointer\w++|popstate]=]
              .. [=[|reset|resize|scroll|search|select\w*+|start|submit|toggle|touch\w++|transition\w++|unload]=]
              .. [=[|wheel)\s*+=]=] },
        { id = "xss_script_uri", category = "xss", -- "javascript: the good parts" is not one
          pattern = [=[\b(?:java|vb|live)script\s*+:\s*+(?:[\w$.]++\s*+[(`=]|/[/*]|['"\[(])]=]
              .. [=[|\bdata\s*+:\s*+text/(?:html|javascript)\b]=] },
        { id = "xss_dom_sink", category = "xss",
          pattern = [=[\bdocument\s*+\.\s*+(?:cookie|domain|write(?:ln)?\s*+\()]=]
              .. [=[|\b(?:eval|settimeout|setinterval)\s*+\(\s*+['"`]|\bstring\s*+\.\s*+fromcharcode\s*+\(]=]
              .. [=[|\b(?:alert|prompt|confirm)\s*+(?:\(\s*+(?:\d++|['"`][^'"`]*+['"`]]=]
              .. [=[|(?:document|window)\s*+\.\s*+\w++)?\s*+\)|`[^`]*+`)]=] },

        -- OS command injection: a shell separator followed by a command. Words
        -- that are also English ("cat", "sleep", "ping") only count with a
        -- typical argument; "&id=" in a URL is not "& id".
        { id = "cmd_chain", category = "cmdi",
          pattern = [=[(?:[;&|`]|\$\()\s*+(?:(?:whoami|uname|ifconfig|ipconfig|wget|curl|nc|ncat|netcat|telnet]=]
              .. [=[|bash|zsh|sh|ksh|powershell|pwsh|cmd(?:\.exe)?|busybox|chmod|chown|nslookup|perl|python[23]?]=]
              .. [=[|php|ruby|ls|rm|certutil|bitsadmin|base64|net\s++user)(?=$|[\s;&|<>`'")])]=]
              -- `id` is also a MySQL column name in backticks: not that one
              .. [=[|id(?=$|[\s;&|<>'")])|cat\s++[/~.]|sleep\s++\d|ping\s++-[cn])]=] },
        { id = "cmd_reverse_shell", category = "cmdi",
          pattern = [=[/dev/(?:tcp|udp)/|\b(?:ba|z|k)?sh\s++-[ic]\b|\bmkfifo\b]=]
              .. [=[|\bn(?:c|cat|etcat)\s++[^;&|\n]{0,60}?\s-[a-z]{0,6}?e\s++/]=]
              .. [=[|\bpowershell(?:\.exe)?\s++-(?:e(?:nc(?:odedcommand)?)?|nop|w(?:indowstyle)?\s++hidden)\b]=] },

        -- Path traversal and local/remote file inclusion. One "../" only
        -- counts at the start of a value: "a/../b" is a legitimate relative URL.
        { id = "path_traversal", category = "lfi",
          pattern = [=[^(?:\.|%2e){2}(?:[\\/]|%2f|%5c)|(?:(?:\.|%2e){2}(?:[\\/]|%2f|%5c)){2}]=] },
        { id = "sensitive_file", category = "lfi", -- /.github/ is fine, /.git/ is not
          pattern = [=[/etc/(?:passwd|shadow|group|hosts|issue|sudoers|crontab)\b]=]
              .. [=[|/proc/(?:self|\d++)/(?:environ|cmdline|maps|fd|mem)\b|\b(?:boot|win|system)\.ini\b]=]
              .. [=[|\\windows\\(?:system32|win\.ini)|(?:^|/)\.(?:env|git|svn|hg|htpasswd|htaccess|aws|ssh)(?:/|$|\.\w)]=]
              .. [=[|\bwp-config\.php\b|\bweb\.config\b|\.ds_store\b]=] },
        { id = "file_wrapper", category = "lfi",
          pattern = [=[\b(?:php://(?:filter|input|fd|memory|temp)|phar://|zip://|expect://|glob://|file:///)]=] },

        -- Server-side request forgery: cloud metadata endpoints, unusual URL
        -- schemes and numeric-IP tricks. Plain localhost/private URLs are not
        -- signatures: every Referer of a site served on localhost is one.
        { id = "ssrf_metadata", category = "ssrf",
          pattern = [=[\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b]=]
              .. [=[|\bmetadata\.azure\.com\b|\bfd00:ec2::254\b|/latest/meta-data\b|/computemetadata/v1\b]=] },
        { id = "ssrf_scheme", category = "ssrf",
          pattern = [=[\b(?:gopher|dict|tftp|netdoc|jar)://]=]
              .. [=[|\bhttps?://(?:0x[0-9a-f]++|0[0-7]++|\d{8,10})(?=[.:/]|$)]=] },

        -- Exploits for known-vulnerable components: Log4Shell (also nested
        -- ${${lower:j}ndi:...} forms), Shellshock, Struts/OGNL, Spring4Shell
        -- and Java deserialization (case-sensitive base64/hex magic bytes).
        { id = "log4shell", category = "rce",
          pattern = [=[\$\{\s*+(?:jndi\s*+:|(?:lower|upper|env|sys|date|main|base64|ctx|k8s|docker|spring]=]
              .. [=[|web|java|marker|bundle|sd|event)\s*+:|::-|\$\{)]=] },
        { id = "shellshock", category = "rce",
          pattern = [=[\(\s*+\)\s*+\{\s*+(?::|\w++\s*+\(\s*+\))\s*+;]=] },
        { id = "ognl_injection", category = "rce",
          pattern = [=[#_memberaccess\b|@java\.lang\.(?:runtime|processbuilder|system)\b|\bognl\.ognlcontext\b]=]
              .. [=[|#context\[|\bclass\.module\.classloader\b]=] },
        { id = "java_deserialization", category = "rce",
          pattern = [=[(?-i:(?:^|[^\w+/])rO0AB[A-Za-z0-9+/]{8}|(?:^|\W)aced0005[0-9a-f]{8})]=] },

        -- Server-side template injection: arithmetic probes ({{7*7}}, ${7*7})
        -- and template-engine object access.
        { id = "ssti_probe", category = "ssti",
          pattern = [=[(?:\{\{|\$\{|#\{|<%=?|\{%)\s*+\d++\s*+[*+]\s*+['"]?\d++['"]?\s*+(?:\}\}|\}|%>|%\})]=] },
        { id = "ssti_object_access", category = "ssti",
          pattern = [=[\b__(?:class|mro|subclasses|globals|builtins|bases)__\b]=]
              .. [=[|\{\{[^{}]{0,80}?\b(?:config|self|request|lipsum|cycler|joiner|namespace|url_for]=]
              .. [=[|get_flashed_messages)\s*+[.\[|(]|<#assign\b|\bfreemarker\.template\.utility\b]=] },

        -- XML external entities: an entity declaration or an internal DTD
        -- subset. A plain <!DOCTYPE html ...> is not one.
        { id = "xxe_entity", category = "xxe",
          pattern = [=[<!entity\s++(?:%\s*+)?[\w.-]++\s++(?:system|public)\b|<!doctype\s++[\w:.-]++\s*+(?:\[|system\s)]=] },

        -- NoSQL (MongoDB) operator injection, as a JSON key ({"$ne": null})
        -- or a parameter name (user[$ne]=x); both are checked (check_name).
        { id = "nosql_operator", category = "nosqli",
          pattern = [=[(?:^|\[)\$(?:ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|expr|or|and|nor|not]=]
              .. [=[|elemmatch|function|accumulator|jsonschema)\b]=] },

        -- CRLF injection / HTTP response splitting.
        { id = "crlf_injection", category = "crlf",
          pattern = [=[[\r\n]\s*+(?:set-cookie\s*+:|location\s*+:\s*+(?:https?:)?//|content-type\s*+:\s*+text/html]=]
              .. [=[|http/[12](?:\.\d)?\s++\d{3}\b)]=] },

        -- Attack tools announcing themselves (User-Agent). Name plus version,
        -- so "cell nuclei" in a search box doesn't count.
        { id = "scanner", category = "scanner",
          pattern = [=[\b(?:sqlmap|nikto|nuclei|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|feroxbuster]=]
              .. [=[|masscan|zgrab|havij|w3af|commix|fimap|wfuzz|arachni|whatweb)/\d|\bnmap\s++scripting\s++engine\b]=]
              .. [=[|\bfuzz\s++faster\s++u\s++fool\b|\bwpscan\s++v\d]=] },
    }
end)()
-- signatures:end

_M.SIGNATURES = SIGNATURES

local BY_ID = {}
for _, signature in ipairs(SIGNATURES) do
    BY_ID[signature.id] = signature
end
_M.BY_ID = BY_ID

-- Categories switched off for good with WAF_DISABLED_CATEGORIES (e.g. "xss,cmdi").
local ENV_DISABLED = {}
for category in (os.getenv("WAF_DISABLED_CATEGORIES") or ""):lower():gmatch("[^,%s]+") do
    ENV_DISABLED[category] = true
end
_M.ENV_DISABLED = ENV_DISABLED

local function dict()
    return ngx.shared.waf_config
end

-- Ids switched off on the dashboard, as a set.
function _M.disabled_ids()
    local list = cjson.decode(dict():get("rules_off") or "[]")
    local set = {}
    for _, id in ipairs(type(list) == "table" and list or {}) do
        set[id] = true
    end
    return set
end

-- init_by_lua: restore the dashboard's choices.
function _M.load()
    local ids = {}
    local file = io.open(RULES_FILE, "r")
    if file then
        local saved = cjson.decode(file:read("*a") or "")
        file:close()
        for _, id in ipairs(type(saved) == "table" and type(saved.off) == "table" and saved.off or {}) do
            if BY_ID[id] then
                ids[#ids + 1] = id
            end
        end
    end
    dict():set("rules_off", cjson.encode(setmetatable(ids, cjson.array_mt)))
    dict():set("rules_version", 1)
end

-- Switch one signature on or off from the dashboard. Applies even if saving
-- fails (the error is returned so the page can say it won't survive a restart).
function _M.set_enabled(id, enabled)
    if not BY_ID[id] then
        return nil, "unknown rule"
    end
    local off = _M.disabled_ids()
    off[id] = (not enabled) or nil
    local ids = {}
    for _, signature in ipairs(SIGNATURES) do -- table order, so the file is stable
        if off[signature.id] then
            ids[#ids + 1] = signature.id
        end
    end
    local encoded = cjson.encode(setmetatable(ids, cjson.array_mt))
    dict():set("rules_off", encoded)
    dict():incr("rules_version", 1, 1)

    -- Write then rename, so a crash can't leave a half-written file.
    local tmp = RULES_FILE .. ".tmp"
    local file, err = io.open(tmp, "w")
    if not file then
        return nil, err
    end
    file:write(cjson.encode({ off = setmetatable(ids, cjson.array_mt) }))
    file:close()
    local ok, rename_err = os.rename(tmp, RULES_FILE)
    if not ok then
        return nil, rename_err
    end
    return true
end

-- Why a signature is off: "env" (WAF_DISABLED_CATEGORIES), "dashboard", or nil.
function _M.off_reason(signature, off)
    if ENV_DISABLED[signature.category] then
        return "env"
    end
    if (off or _M.disabled_ids())[signature.id] then
        return "dashboard"
    end
    return nil
end

-- The active signatures and all of them in one alternation: a benign value
-- (the common case) costs a single scan. Rebuilt per worker only when the
-- dashboard changed something.
local cache = {}
function _M.active()
    local version = dict():get("rules_version") or 0
    if cache.version ~= version then
        local off, active, parts = _M.disabled_ids(), {}, {}
        for _, signature in ipairs(SIGNATURES) do
            if not _M.off_reason(signature, off) then
                active[#active + 1] = signature
                parts[#parts + 1] = "(?:" .. signature.pattern .. ")"
            end
        end
        -- (?!) never matches: every signature switched off.
        cache = { version = version, active = active,
                  combined = #parts > 0 and table.concat(parts, "|") or "(?!)" }
    end
    return cache.active, cache.combined
end

-- Returns the first matching active signature, or nil. A regex error (e.g.
-- the match limit) is logged and treated as "no match": in the WAF the value
-- then goes to the ML model, so an error never skips inspection.
function _M.match(value)
    local active, combined = _M.active()
    local from, _, err = ngx.re.find(value, combined, "joi")
    if not from then
        if err then
            ngx.log(ngx.WARN, "WAF signature check failed, deferring to ML: ", err)
        end
        return nil
    end
    for _, signature in ipairs(active) do
        if ngx.re.find(value, signature.pattern, "joi") then
            return signature
        end
    end
    return nil
end

-- Every active signature that matches, with the matched span (1-based,
-- inclusive), for the dashboard.
function _M.match_all(value)
    local active = _M.active()
    local hits = {}
    for _, signature in ipairs(active) do
        local from, to = ngx.re.find(value, signature.pattern, "joi")
        if from then
            hits[#hits + 1] = { signature = signature, from = from, to = to }
        end
    end
    return hits
end

return _M
