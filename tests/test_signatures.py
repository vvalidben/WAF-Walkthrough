"""Regex pre-filter (SIGNATURES in waf_interceptor.lua), run with OpenResty's own PCRE.

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
LUA = (ROOT / "waf_interceptor.lua").read_text(encoding="utf-8")
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
}

BENIGN = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.ab--cd_EF-gh",
    "https://example.com/search?q=or+and&sort=desc&page=2",
    "O'Brien", "Rock 'n' roll", "it's a select few", "union station", "order by price",
    "--verbose", "/* see notes */", "I need sleep (8 hours)", "drop table tennis; exec summary",
    "1=1 is true", "SELECT your size", "Tom & Jerry", "50% off -- today only",
]

# Inputs built to make backtracking regexes blow up; must stay linear.
REDOS = {
    "quote_spaces": "'" + " " * 100_000 + "x",
    "open_comments": "/*" * 50_000,
    "comment_chain": "union" + "/**/" * 30_000 + "x",
    "repeated_tautology": "'or'a'='" * 10_000,
    "spaces_then_eq": "or 1" + " " * 100_000 + "=",
}

needs_docker = pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")


def _signature_block() -> str:
    match = re.search(r"-- signatures:begin\n(.*?)\n-- signatures:end", LUA.replace("\r\n", "\n"), re.S)
    assert match, "signature markers missing from waf_interceptor.lua"
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
