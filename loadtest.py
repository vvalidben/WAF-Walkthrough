"""Load test for the ML WAF: what happens to inspection under concurrency.

Usage (accurate latencies need the load generator inside the Docker network;
from a Windows/macOS host, Docker Desktop's port forwarding adds seconds):

    docker run --rm --network automatedsqliattackdetecter_app -v "$PWD:/w" python:3.14-slim \\
        sh -c "pip install -q httpx && python /w/loadtest.py --target http://openresty:8080/search --unique"

    # from the host, also printing the WAF's own per-second outcomes:
    python loadtest.py --unique --waf-log

Notes:
  * --unique varies the values per request. Without it the WAF's verdict cache
    answers every request after the first, and the ML API is never exercised.
  * --payload attack sends an SQLi variant that no regex signature matches, so
    only the model can catch it: every 200 is an attack that got through.
  * The WAF rate-limits by TCP peer address; spoofed X-Forwarded-For headers
    don't change that (by design), so all requests count as one client.
  * Client-side latency can't tell a timeout from a cache hit or a rate-limit
    429. --waf-log reads the WAF's JSON access log, which records the actual
    outcome of every request (waf_action, waf_reason).
"""

import argparse
import asyncio
import json
import secrets
import statistics
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="http://localhost:8080/search")
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--payload", choices=["benign", "attack"], default="benign")
    parser.add_argument("--unique", action="store_true",
                        help="vary values per request and per run (defeats the verdict cache)")
    parser.add_argument("--waf-log", action="store_true", help="print the WAF's per-second outcomes (needs docker compose)")
    return parser.parse_args()


# Per-run salt: without it, a second run would send the same "unique" values
# and the WAF's verdict cache would answer them without the model.
RUN_SALT = secrets.randbelow(10**6)


def params_for(args: argparse.Namespace, i: int) -> dict[str, str]:
    n = RUN_SALT * 10_000 + i if args.unique else 0
    if args.payload == "attack":
        # Blocked by the model (403, engine=ml) but by no regex signature.
        return {"id": f"1' where {6953 + n}={6953 + n} or 2367=(select count(*) from rdb$fields as t{n})"}
    return {"search": f"normal user input with some length to process {n}", "filter": "active"}


async def send(client: httpx.AsyncClient, semaphore: asyncio.Semaphore, args: argparse.Namespace, i: int):
    async with semaphore:
        started = time.perf_counter()
        try:
            status = (await client.get(args.target, params=params_for(args, i), timeout=5.0)).status_code
        except httpx.RequestError:
            status = 0
        return time.time(), status, (time.perf_counter() - started) * 1000


def print_waf_log(since: str) -> None:
    logs = subprocess.run(
        ["docker", "compose", "logs", "--no-log-prefix", "--since", since, "openresty"],
        capture_output=True, text=True, check=False,
    ).stdout
    rows = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    by_second = defaultdict(list)
    for row in rows:
        by_second[row["timestamp"][11:19]].append(row)
    print(f"\n--- WAF outcomes (JSON access log) ---\n{'second':9} {'n':>5}  {'WAF ms p50':>10}  outcomes")
    for second in sorted(by_second):
        batch = by_second[second]
        server_ms = statistics.median(float(r["request_time"]) * 1000 for r in batch)
        outcomes = Counter(
            f"{r['status']}/{r['waf_action'] or 'rate-limited'}"
            + (f"/{r['waf_reason']}" if r["waf_action"] in ("fail_open", "fail_closed") else "")
            for r in batch
        )
        print(f"{second:9} {len(batch):5}  {server_ms:10.0f}  {dict(outcomes)}")
    print("total:", dict(Counter(f"{r['status']}/{r['waf_action'] or 'rate-limited'}" for r in rows)),
          "| values sent to the model:", sum(int(r["waf_ml_items"] or 0) for r in rows))


async def main() -> None:
    args = parse_args()
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    semaphore = asyncio.Semaphore(args.concurrency)
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)

    t0 = time.time()
    async with httpx.AsyncClient(limits=limits) as client:
        results = await asyncio.gather(*(send(client, semaphore, args, i) for i in range(args.total)))
    elapsed = time.time() - t0
    print(f"{args.total} requests, concurrency {args.concurrency}, payload={args.payload}, unique={args.unique}: "
          f"{elapsed:.2f}s ({args.total / elapsed:.0f} req/s)")

    timeline = defaultdict(list)
    for finished, status, latency in results:
        timeline[int(finished - t0)].append((status, latency))
    print(f"\n{'sec':>3} {'reqs':>5}  {'client p50/p95 ms':>19}  statuses")
    for second in sorted(timeline):
        latencies = sorted(latency for status, latency in timeline[second] if status)
        if latencies:
            p95 = latencies[int(len(latencies) * 0.95)]
            statuses = dict(Counter(status for status, _ in timeline[second]))
            print(f"{second:>3} {len(timeline[second]):>5}  {statistics.median(latencies):8.1f} / {p95:<8.1f}  {statuses}")
    print("statuses:", dict(Counter(status for _, status, _ in results)))
    if args.payload == "attack":
        passed = sum(1 for _, status, _ in results if status == 200)
        print(f"attacks that got through (HTTP 200): {passed} of {args.total}")

    if args.waf_log:
        await asyncio.sleep(1)  # let the last access-log lines flush
        print_waf_log(since)


if __name__ == "__main__":
    asyncio.run(main())
