"""End-to-end smoke test of the running stack: client -> OpenResty WAF -> ML API -> backend.

Run after `docker compose up -d openresty` (CI does this with a model trained
on synthetic data):

    python tests/smoke.py --url http://localhost:8080 --compose-logs

Checks that benign traffic reaches the backend, that a signature hit and an
ML-only attack are both blocked, and (with --compose-logs) that the access
log credits each block to the right engine. Standard library only.
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
ML_ATTACK = "7 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77"
BACKEND_TEXT = "backend_app reached"


def request(url: str, method: str = "GET", body: dict | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
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


def engines_by_request_id() -> dict[str, str]:
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "openresty"],
                          capture_output=True, text=True, check=True).stdout
    engines = {}
    for line in logs.splitlines():
        if line.startswith("{"):
            entry = json.loads(line)
            engines[entry["request_id"]] = entry["waf_engine"]
    return engines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--timeout", type=float, default=120, help="Seconds to wait for the stack")
    parser.add_argument("--compose-logs", action="store_true", help="Also check engines in `docker compose logs`")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    wait_until("the WAF", lambda: request(f"{base}/waf/healthz")[0] == 200, args.timeout)
    # The WAF fails open while the model loads, so wait until the ML path blocks.
    wait_until("the ML-only attack to be blocked (model still loading, or the WAF is not blocking)",
               lambda: get(base, ML_ATTACK)[0] == 403, args.timeout)

    failures = []

    def expect(name: str, result: tuple[int, str], status: int) -> dict:
        code, body = result
        ok = code == status and (status != 200 or BACKEND_TEXT in body)
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

    if args.compose_logs:
        time.sleep(1)  # let the access log flush
        engines = engines_by_request_id()
        for name, block, engine in (("regex", regex_block, "regex"), ("ml", ml_block, "ml")):
            got = engines.get(block.get("request_id", ""))
            ok = got == engine
            print(f"{'ok  ' if ok else 'FAIL'} access log credits the {name} block to engine {engine!r} (got {got!r})")
            if not ok:
                failures.append(f"engine {name}")

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nAll smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
