# SQL Injection Detector

A machine-learning Web Application Firewall, built around SQL injection and extended to the attack categories of the OWASP Top 10. Character n-gram TF-IDF features feed a Random Forest, served by a FastAPI service. An OpenResty (NGINX + Lua) reverse proxy checks every request with a hybrid engine before it reaches your application: high-precision regex signatures first (SQLi, XSS, command injection, path traversal, SSRF, Log4Shell and other known exploits, template injection, XXE, NoSQL injection, CRLF, scanners), then the ML model for any SQLi the signatures don't match. It also rate-limits login brute force and adds security headers. See [OWASP Top 10 coverage](#owasp-top-10-coverage).

```
client --> openresty :8080 ---------------> backend_app (your application)
              |  waf_interceptor.lua
              +--> ml-api :8000 /scan/batch   (internal network only)
```

```
fetch_data.py  -> downloads a public dataset, merges data/feedback/custom_traffic.csv -> data/sqli.csv
train.py       -> trains with fixed parameters                           -> models/sqli_detector.pkl + .onnx
tune.py        -> hyperparameter search                                  -> models/sqli_detector_optimized.pkl + .onnx (+ .json report)
text_preprocessing.py -> preprocessing shared by training and the ONNX-serving API
api.py         -> serves POST /scan, POST /scan/batch and GET /health
Dockerfile, gunicorn.conf.py                          -> ML API container
nginx.conf, waf_interceptor.lua, Dockerfile.openresty -> WAF proxy container
waf_target.lua, waf_admin.lua, admin/                 -> admin page (127.0.0.1:8081): paste a URL to protect that site
waf_dashboard.lua, admin/dashboard.*                  -> security dashboard (127.0.0.1:8081/dashboard): live traffic, threat feed, rules, test console
waf_rules.lua                                         -> the regex signatures, switchable at runtime from the dashboard
waf_bans.lua                                          -> automatic IP bans (20 blocks in 10 min -> 1 h), managed on the dashboard
docker-compose.yml                                    -> WAF + ML API + placeholder backend
loadtest.py                                           -> load test: inspection outcomes under concurrency
monitoring/                                           -> Grafana Alloy, Loki and Grafana config + the "WAF SIEM" dashboard
GeoLite2-City.mmdb                                    -> MaxMind GeoIP database (download it; see section 7)
n8n_sqli_alert.json                                   -> n8n incident-response workflow (import into n8n)
n8n_feedback_loop.json                                -> n8n workflow behind the Slack "Flag as false positive" button
tests/, .github/workflows/ci.yml                      -> test suite and CI (section 8)
```

## 1. Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

`requirements-api.txt` holds the pinned runtime dependencies of the API container: ONNX Runtime, numpy and FastAPI, with **no scikit-learn, SciPy or joblib**. `requirements.txt` adds the training and export tools on top: scikit-learn, pandas, `skl2onnx`, `onnx` and `onnxconverter-common`.

## 2. Get training data

```bash
python fetch_data.py                          # public GitHub dataset (default)
python fetch_data.py --source kaggle          # Kaggle dataset
python fetch_data.py --source github kaggle   # both, combined
```

| Source | Dataset | Notes |
|---|---|---|
| `github` | [Morzeux/HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset) (MIT) | About 19k benign HTTP parameter values and 11k SQLi payloads. Pinned to a commit and verified by SHA-256. XSS, command injection and path traversal rows are dropped rather than labelled safe. |
| `kaggle` | [sajid576/sql-injection-dataset](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset) | About 31k rows. License is listed as *Unknown*, so check it before commercial use. Needs `pip install kaggle`. Public datasets may download anonymously; otherwise set up `~/.kaggle/kaggle.json` or the `KAGGLE_USERNAME` and `KAGGLE_KEY` environment variables. Use `--kaggle-dataset owner/name` for a different dataset. |

Downloads are cached in `data/raw/`; add `--force` to download again. The merged result is written to `data/sqli.csv`.

### Mixing in your own traffic

If `data/feedback/custom_traffic.csv` exists (path set with `--custom`), it is merged in. This is also the file the Slack *Flag as false positive* button appends to (see [Human-in-the-loop feedback](#human-in-the-loop-feedback-slack-button)). It uses the same format as the training CSV; extra columns, such as the feedback audit columns, are ignored:

```csv
query,label
O'Brien,0
"Rock 'n' roll",0
"admin'--",1
```

When the same query appears in both, **your labels override the public dataset**. The public datasets don't look much like real application input: their benign rows are mostly names and addresses, and their attacks are mostly scanner-generated. Benign inputs from your own logs, especially ones containing quotes, SQL keywords or punctuation, are the single most effective way to cut false positives.

`generate_benign_corpus.py` writes a realistic starter set of such rows (short legitimate phrases that mix everyday words with SQL tokens — `C++ and C# tutorials`, `price > 100 and rating >= 4`, `1 or 2 items per customer` — plus reinforcing blind-SQLi attacks). On the public data alone the model blocks those phrases; retrained with this corpus it passes them (0.10–0.35) and still catches attacks. Replace it with your own traffic when you have it.

### Training CSV format

| column  | meaning                         |
|---------|---------------------------------|
| `query` | the raw input text              |
| `label` | `0` = safe, `1` = SQL injection |

- Header names are case-insensitive.
- Values such as `NULL` and `NA` stay as text.
- Rows with an empty query or a label other than 0/1 are dropped with a warning.
- Exact duplicates are dropped, and so are queries that appear with both labels.

## 3. Train

Fast baseline with fixed parameters:

```bash
python train.py --data data/sqli.csv --output models/sqli_detector.pkl
```

Options: `--encoding`, `--test-size 0.2`, `--n-estimators 100`, `--max-features 50000` (0 = unlimited), `--random-state 42`.

Each run writes the scikit-learn pipeline (`.pkl`, for the training tools) and its **ONNX export** (`.onnx`, which the API serves) next to it; see [Serving with ONNX Runtime](#serving-with-onnx-runtime). To export an existing `.pkl` without retraining, run `python train.py --onnx-from models/sqli_detector_optimized.pkl`.

## 4. Tune hyperparameters

```bash
python tune.py                                # randomized search, 20 candidates, 5-fold CV, F1
python tune.py --n-iter 50 --scoring recall   # favour catching attacks over precision
python tune.py --search grid                  # exhaustive search over a smaller grid (32 candidates)
```

The search covers the TF-IDF settings (`ngram_range`, `max_features`, `min_df`, `sublinear_tf`) and the Random Forest settings (`n_estimators`, `max_depth`, `min_samples_leaf`, `max_features`). The spaces are `RANDOM_SPACE` and `GRID_SPACE` in `tune.py`. The search runs on the training split only. The held-out test split is scored once, with the chosen model.

**Latency-aware selection:** the model sits in the WAF's request path, so `tune.py` doesn't simply take the top score. It chooses the fastest-predicting candidate whose CV score is within `--score-tolerance` (default 0.001) of the best. Use `--score-tolerance 0` for pure accuracy. It reports single-request latency for scikit-learn and for the ONNX model as served, and warns if the ONNX latency exceeds 25 ms. `ngram_range` values in the search all start at 1, the only form the ONNX export can convert.

Outputs:
- The best parameters, the top 5 candidates, and a classification report with confusion matrix, printed to the console.
- `models/sqli_detector_optimized.pkl`, the refitted best model.
- `models/sqli_detector_optimized.onnx`, its verified ONNX export, which the API serves.
- `models/sqli_detector_optimized.json`, which records the parameters, CV score, test metrics, scikit-learn version and the ONNX fidelity check.

Runtime grows with candidates × folds. As a reference point, 4 candidates × 3 folds on about 30k rows took about 1 minute, so the default 20 × 5 runs about 8 times as many fits. `--n-jobs` controls parallelism.

## 5. Run the API locally

```bash
SQLI_MODEL_PATH=models/sqli_detector_optimized.onnx uvicorn api:app --port 8000
# PowerShell: $env:SQLI_MODEL_PATH="models/sqli_detector_optimized.onnx"; uvicorn api:app --port 8000
```

```bash
curl -X POST http://localhost:8000/scan \
     -H "Content-Type: application/json" \
     -d "{\"query\": \"' OR 1=1 --\"}"
```

```json
{
  "request_id": "9f1c...",
  "verdict": "malicious",
  "is_malicious": true,
  "confidence": 0.97,
  "sqli_probability": 0.97,
  "threshold": 0.5,
  "scanned_at": "2026-10-29T10:15:02.113Z"
}
```

`confidence` is the model's probability for the verdict it returned. `sqli_probability` is always P(SQLi).

`POST /scan/batch` takes `{"queries": ["value1", "value2", ...]}` (up to `SQLI_MAX_BATCH_SIZE` items). It scores all of them in one model call, which costs little more than scoring one. It returns the same fields with `sqli_probability` set to the maximum, plus `probabilities`, `flagged_indices` and `max_index`. The WAF uses this endpoint.

| Status | When |
|--------|------|
| 200 | Scan completed |
| 422 | Empty, whitespace-only, non-string, oversized, extra-field or malformed JSON input. The offending input is never echoed back. |
| 503 | Model missing, unreadable or exported for different preprocessing, or the request was shed under load (`overloaded`). |

`GET /health` returns 200 when the model is loaded and 503 when it is not.

### Serving with ONNX Runtime

The API runs the model with **ONNX Runtime** (C++ kernels, GIL released) instead of scikit-learn. Measured in the API container, same host and session:

| Single value | scikit-learn | ONNX Runtime |
|---|---|---|
| p50 / p99 / max latency | 11.4 / 22.1 / 66.6 ms | **0.27 / 0.87 / 1.4 ms** |
| Python GC pauses during the run | up to 57.8 ms (24 over 1 ms) | up to 7 ms (2 over 1 ms) |

- **No more pickles:** loading an `.onnx` file can't execute code, unlike a joblib pickle.
- **Smaller image:** without scikit-learn and SciPy it shrank from 518 MB to 411 MB.
- **Under sustained traffic** through the WAF (8 concurrent clients, 285 req/s, 3,000 requests): all 3,000 were scored, with **0 fail-opens** and an ML round-trip of p50 5 / p99 9 / max 20 ms.

**The plain `skl2onnx` conversion is not faithful, so the export fixes and verifies it.** Converted naively, the model scored some attacks up to **0.41 lower** than scikit-learn (6 decisions flipped at 0.5, 438 at 0.8), which would have opened easy evasions. `export_onnx()` in `train.py` corrects five converter issues:

| Issue | Effect | Fix |
|---|---|---|
| scikit-learn's char analyzer collapses whitespace runs; the ONNX graph doesn't | `' AND 1  =  …` scored 0.58 instead of 0.98: padding attacks with spaces evaded it | `text_preprocessing.preprocess()` applies scikit-learn's exact preprocessing in Python before ONNX Runtime |
| `sublinear_tf` exported as log(tf + 1) instead of 1 + log(tf) | every feature shifted; scores off by up to 0.16 | graph rewritten to `Relu(Log(tf) + 1)` |
| `StringNormalizer` (lowercasing) needs the `en_US.UTF-8` locale | the model **failed to load** in the Linux container (it worked on Windows) | node removed; lowercasing happens in `preprocess()` |
| n-grams whose characters aren't single-character features (a frequency tie kept "mü" but dropped "ü") | conversion aborts, or n-grams are silently dropped | missing characters added with IDF weight 0, which leaves every score unchanged |
| `ngram_range` not starting at 1 | ONNX Runtime rejects the graph | export refuses; `tune.py` searches only ranges starting at 1 |

Every export then has to pass a **fidelity gate** before anything is written:
- ONNX Runtime and scikit-learn score the held-out test split plus tricky edge cases (whitespace, Unicode, repetition, padding).
- Any difference above 1e-4 fails the export (`OnnxExportError`) and writes no file. With the fixes the maximum difference is about 1e-6, with no decision flips.
- Removing the sublinear fix makes the gate fail, as tested.
- The model file records its preprocessing ID, class order and versions. The API refuses a model that expects different preprocessing, answering 503, so the WAF fails safely.

Probabilities are rounded to 6 decimals in the API. Random Forest probabilities are multiples of 1/n_trees, so exactly 0.5 or 0.8 is common, and float32 would otherwise return it as 0.79999995, just under the threshold.

**The trade-off:** the ONNX TF-IDF works on a dense matrix, one column per vocabulary entry (50,000), where scikit-learn uses sparse matrices.

| Values per call | scikit-learn | ONNX Runtime (optimized graph) |
|---|---|---|
| 1 | 11.4 ms | 0.27 ms |
| 8 | (not measured) | 2.5 ms |
| 32 | 16.7 ms | 16.7 ms |
| 64 | about 18 ms (estimated) | 30.8 ms |

ONNX is far faster for the small batches that normal traffic produces, but its cost grows by about 0.5 ms per value. So:
- `SQLI_MAX_BATCH_VALUES` defaults to **16**.
- Requests with very many uncached values (dozens of parameters or a large JSON body) cost more than before.
- The graph is already optimized: `ReduceL2`/`Div` instead of the ML-domain `Normalizer`, and a `Relu` sublinear step. That made it 30% faster at batch 32.
- If large requests are common, a smaller vocabulary (`--max-features`) cuts the per-value cost proportionally.

A 100-request burst from one client still outruns the 50 ms budget. Without the per-client budget, 24–62 of 100 attacks got through, against 69–74 with scikit-learn. **The fail-open budget remains the protection there.**

**Concurrency: micro-batching.** Each worker process runs one model call at a time. Each call scores the requests that queued up meanwhile, up to `SQLI_MAX_BATCH_VALUES` values.
- **One call at a time:** running several predictions at once in one process only makes them compete for the CPU.
- **Load shedding:** requests that waited longer than `SQLI_MAX_QUEUE_MS`, or whose client already disconnected, are shed with 503 rather than processed. Without this, requests the WAF had already timed out on piled up into a backlog. In testing that pushed inference times past 20 seconds and made every later call time out.

## 6. Run the WAF stack (Docker)

```bash
python tune.py                      # or train.py; the model must exist in ./models first
# monitoring prerequisites (section 7): GRAFANA_ADMIN_PASSWORD in .env, GeoLite2-City.mmdb downloaded
docker compose up --build -d
docker compose ps                   # all services "healthy" once the model is loaded
curl "http://localhost:8080/search?q=shoes"                      # proxied to backend_app
curl "http://localhost:8080/item?id=1%27%20OR%20%271%27%3D%271"  # 403 {"error":"forbidden",...}
docker compose logs -f openresty    # one JSON line per request with the WAF decision
docker compose logs -f ml-api       # model audit events
docker compose down
```

`backend_app` is a placeholder echo server. `nginx.conf` and `waf_interceptor.lua` are mounted read-only, so after editing them run `docker compose restart openresty`.

### Pointing the WAF at your own site

**Easiest: the admin page.** Open <http://127.0.0.1:8081>, paste your site's address (`my-app.vercel.app`, `https://example.com/any/page`, `localhost:3000`) and click **Protect this site**. The WAF checks that the site answers, then switches to it on the next request, with no restart. **Run test** sends one normal request and one SQL injection through the WAF and shows what was let through and what was blocked.

What the page works out for you:
- Missing `https://` is added, and any path is dropped: the WAF protects the whole site.
- `localhost` / `127.0.0.1` become `host.docker.internal`, because inside the container `localhost` is the container itself.
- Public hostnames are also sent as the `Host` header (what `WAF_BACKEND_HOST` does below). Vercel and Netlify need this to route the request.
- It refuses non-HTTP addresses and the stack's own services (`ml-api`, `grafana`, …), which would otherwise be exposed through the WAF.

The choice is saved on the `waf_config` volume and survives restarts. It overrides `.env` until you click **Go back to the site set in .env**. Target changes are logged to `docker compose logs openresty` ("WAF admin: now protecting …"). The page is published on `127.0.0.1` only (`WAF_ADMIN_PORT`, default 8081), and its API refuses requests with a foreign `Host` or `Origin` header, so a website open in your browser can't change the target. Anyone with a shell on this machine can, so don't publish port 8081 beyond localhost.

### Automatic IP bans

A client that keeps attacking is cut off: `WAF_BAN_THRESHOLD` (20) blocked requests within `WAF_BAN_WINDOW_S` (10 minutes) ban its IP for `WAF_BAN_DURATION_S` (1 hour). A banned IP gets the same 403 as a block, logged as `waf_action: banned`, without inspection or an ML call, so a flood from it costs almost nothing. `waf_bans.lua` keeps bans and per-IP counters in the `waf_bans` shared dict: every worker sees a ban at once, and bans expire by themselves.

- **Manage them on the dashboard.** The Overview lists active bans with an **Unban** button, the sidebar counts them, and a request's detail page offers **Ban this IP** or **Unban**. API: `GET/POST /api/bans`.
- **Never banned:** loopback, plus anything in `WAF_BAN_ALLOWLIST`. The admin page stays reachable from a banned IP, so you can always unban yourself.
- **Counted:** only `block` decisions. Monitor mode, rejects and fail-opens never ban anyone.
- **Not persisted:** a WAF restart clears all bans and counters.
- **Locally, all your test traffic has one IP** (Docker's gateway, e.g. 172.29.0.1). Twenty test attacks within 10 minutes will ban you from your own site; unban yourself on the dashboard. **Behind a load balancer or CDN**, configure `real_ip` (section 7) first, or the balancer's address gets banned and every visitor with it.

### Security dashboard

<http://127.0.0.1:8081/dashboard> (linked from the admin page) shows the WAF's own access log, with no extra services:

| Screen | What it shows |
|---|---|
| Overview | Requests, blocks, monitor detections and hostile IPs over 24 h; requests per hour with the blocked share; top rules and top blocked IPs |
| Threat feed | Every inspected request as it happens (refreshes every 3 s; requests with nothing to inspect are left out), filterable by blocked / monitored |
| Request detail | One request: the value that triggered it with the matched fragment highlighted, every signature it matches, the ML score, the client. Buttons: replay in the console, switch the deciding rule off, or (ML decisions) flag a false positive, which posts the value to `ml-api /feedback` as safe (needs `FEEDBACK_API_KEY`) |
| Rules | All 34 signatures by category with their 24 h hits. Switching one off applies to the next request (a version counter in the `waf_config` shared dict) and is saved to the `waf_config` volume. Categories in `WAF_DISABLED_CATEGORIES` show as locked |
| Test console | A dry run of any value through the real signatures and the ML model. Nothing is sent to the protected site |

- **Data source:** the hourly log files on the `waf_logs` volume (24 h), read by `waf_dashboard.lua`. The overview is cached for 5 seconds. The log keeps the URL and User-Agent but not bodies, cookies or other headers, so for those sources the dashboard names where the value was but can't show it.
- **Security:** it has the admin page's protections (localhost only, foreign `Host`/`Origin` refused). Because it displays attacker-controlled payloads, it renders all data as text nodes and is served with a CSP that forbids inline script (`script-src 'self'`). The design's fonts load from Google Fonts.
- **Signatures moved:** the `SIGNATURES` table now lives in `waf_rules.lua`, which both the WAF and the dashboard use.

**Or set it in `.env`.** Set `WAF_BACKEND_URL` in `.env` instead of editing `nginx.conf`; the default is the placeholder. After changing it, run `docker compose up -d openresty`. This applies whenever no site is saved from the admin page.

| Where your app runs | `.env` |
|---|---|
| Another compose service | `WAF_BACKEND_URL=http://my-app:8080` |
| On the host machine | `WAF_BACKEND_URL=http://host.docker.internal:3000` |
| A remote HTTPS site | `WAF_BACKEND_URL=https://my-app.example.com` plus `WAF_BACKEND_HOST=my-app.example.com` |

For a remote HTTPS backend, `WAF_BACKEND_HOST` is the hostname sent upstream for routing and TLS SNI (many hosts, e.g. Vercel and Netlify, route by it); without it the backend sees the visitor's `Host`. The WAF speaks plain HTTP on port 8080, so visitors reach it as `http://localhost:8080`.

This protects only the traffic that passes through the WAF. To protect a **public** site, the WAF needs its own public server and the site's DNS has to point at it (otherwise visitors bypass the WAF), and you add TLS termination for inbound HTTPS. Start in `WAF_MODE=monitor` so false positives surface before anything is blocked.

### Worked example: a real app behind the WAF

Two deliberately vulnerable or real backends make a clear before/after. Pointed at [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) running on the host (`WAF_BACKEND_URL=http://host.docker.internal:3000`):

```bash
# the classic login bypass, direct vs through the WAF
curl -X POST http://localhost:3000/rest/user/login -H 'Content-Type: application/json' \
  --data-binary '{"email":"'\'' OR 1=1--","password":"x"}'   # 200: returns an admin token
curl -X POST http://localhost:8080/rest/user/login -H 'Content-Type: application/json' \
  --data-binary '{"email":"'\'' OR 1=1--","password":"x"}'   # 403 forbidden (engine regex, signature tautology)
```

Normal browsing is unaffected: the files and API calls a full Juice Shop page load makes all pass (0 false positives). A blind boolean-extraction payload, which matches no signature, is the one caught by the ML engine rather than regex — the case the hybrid design exists for. Every block appears in the Grafana dashboard, split by engine.

### What the WAF inspects

| Source | Handling |
|---|---|
| Query string | Every argument value, including repeated keys (`?id=1&id=2`) |
| `application/x-www-form-urlencoded` body | Every field value |
| `multipart/form-data` body | Every text field. File parts (those with a filename) are not inspected. |
| JSON body | Every string anywhere in the document. Malformed or deeply nested (>32 levels) JSON is scanned as raw text. |
| Other text bodies | The raw body |
| Binary types (`image/*`, `application/octet-stream`, ...) | Not inspected |
| URI path *(extended)* | Each URL-decoded segment, plus the whole path. The raw path is used, because nginx's `$uri` decodes `%2F` and would split a payload into harmless-looking pieces. |
| Headers *(extended)* | The headers in `WAF_INSPECT_HEADERS` (default `user-agent,referer`); other headers are ignored. A Referer's query parameters are also scored one by one. |
| Cookies *(extended)* | Every cookie value, URL-decoded the way PHP and most frameworks decode them |

Values are scored individually, because the model was trained on single parameter values. All values from one request go to `/scan/batch` in a single call. Values made only of letters, digits and `._~` (ids, hex tokens, numbers) can't form SQL syntax, so they are skipped; most path segments and cookies are like this. Bypass hardening:
- Values longer than `WAF_CHUNK_SIZE` are split into overlapping chunks, so padding can't push a payload out of view.
- Invalid UTF-8 is replaced rather than allowed to break the API call, which would otherwise trigger fail-open.
- Requests exceeding `WAF_MAX_ARGS` or `WAF_MAX_ITEMS` are rejected (`reject`) instead of being partly scanned.

**Size limits for headers and cookies:**
- nginx rejects any request or header line over 8 KB (`large_client_header_buffers 4 8k`) with 400 before the WAF runs. That caps the memory inspection can be made to use.
- Within that, a header or cookie value over `WAF_MAX_HEADER_BYTES` (4 KB, the browser per-cookie limit), or more than `WAF_MAX_COOKIES` cookies, makes the request uninspectable. Oversized values are deliberately **not truncated or dropped**: either would let an attacker pad a payload past the cut.

#### Extended inspection: separate threshold, monitor first

The model was trained on parameter values and never saw User-Agents, cookies or paths. Measured on the deployed model:

| Input | Score |
|---|---|
| Chrome on Android / Samsung Internet / Facebook in-app User-Agent | 0.561 / 0.550 / 0.525 |
| Chrome desktop, Edge, Safari User-Agents | 0.40–0.49 |
| Cookie-consent cookie (`{stamp:'...',necessary:true,...}`), JWT, session id | 0.42 / 0.10 / 0.03 |
| SQLi in User-Agent / cookie / path segment / Referer parameter | 0.92 / 0.92–0.95 / 0.96 / 0.96 |
| `/**/`-comment SQLi in path | 0.70 (missed at 0.8) |

At the parameter threshold of 0.5, the WAF would block most Android browsers. Path, header and cookie values therefore use `WAF_EXTENDED_THRESHOLD` (0.8), and `WAF_EXTENDED_MODE` defaults to **`monitor`**: detections are logged and alerted (`waf_action: monitor`) but not blocked. Review a period of real traffic, flag the false positives with the Slack button (or add them to `data/feedback/custom_traffic.csv`) and retrain, then set `WAF_EXTENDED_MODE=block`. In block mode, oversized headers and cookies are rejected too. `WAF_EXTENDED_MODE=off` disables path, header and cookie inspection.

#### Hybrid engine: regex signatures before the model

The model scores each value as one string, so a payload padded with benign text scores low (a "good word" attack). For example, `' OR 1=1--` appended to a real Android Chrome User-Agent scored 0.72, under the 0.8 header threshold. The WAF therefore checks every extracted value (parameters, bodies, path, headers, cookies, Referer parameters) against the `SIGNATURES` table in `waf_rules.lua` *before* the ML call:

- **A match blocks the request immediately.** The value isn't added to the ML batch, and the ML API isn't called at all. The log shows `waf_engine: regex` and `waf_signature: <id>`, and the alert carries `source_engine: "regex"` plus the signature. Signature hits therefore don't depend on the ML API: they are blocked even when it is slow, down, or failing open.
- **No match:** the value goes to the ML batch as before (`waf_engine: ml`).
- **Modes:** `WAF_REGEX_MODE=block` (default), `monitor` (record the hit, let the model decide, log `monitor` if it doesn't block) or `off`. Signatures apply to headers and cookies regardless of `WAF_EXTENDED_MODE`, because they are precise enough to block there.

| Signature | Matches, for example |
|---|---|
| `union_select` | `UNION SELECT`, `union/**/all/**/select`, `UNION(SELECT` |
| `stacked_query` | `; DROP TABLE`, `; TRUNCATE TABLE`, `; DECLARE @x`, `; EXEC xp_…` |
| `dangerous_procedure` | `xp_cmdshell`, `xp_regread`, `xp_dirtree`, `sp_oacreate` |
| `time_delay` | `WAITFOR DELAY '0:0:5'`, `BENCHMARK(5000000,`, `AND SLEEP(5)`, `pg_sleep(` |
| `tautology` | `' OR '1'='1`, `') OR ('a'='a`, `'/**/or/**/1=1` |
| `numeric_tautology` | `OR 1=1`, `AND 2=2` |
| `boolean_subquery` | `AND (SELECT …)='a'`, `AND 1=(SELECT …)` — a subquery used as a condition |
| `blind_extraction` | `ASCII(SUBSTRING((SELECT password …),1,1))`, `LENGTH((SELECT …))` — a subquery read one character at a time |
| `quote_comment` | `admin'--`, `x')/*`, `1'#` at the end of a value |
| `mysql_versioned_comment` | `/*!50000UNION*/`, `/*! SELECT` |
| `comment_obfuscation` | `OR/**/1`, `SELECT/**/password` |
| `system_catalog` | `information_schema`, `sqlite_master`, `pg_catalog`, `@@version` |
| `file_access` | `INTO OUTFILE`, `LOAD_FILE(` |
| `error_based` | `EXTRACTVALUE(`, `UPDATEXML(`, `EXP(~`, `CONVERT(INT,` |
| `char_concat` | `CHAR(75)\|\|CHAR(70)` |

**Bare `--` and `/*` are deliberately not signatures.** In the header-like test data below, `--` occurs in 123 of 2,044 benign values: about 6% of random JWT cookies (base64url can produce `--`), BEM CSS classes such as `card__title--active`, CLI flags and prose. `/*` occurs in globs such as `src/**/*.js`. Comment syntax therefore only counts in SQL context: after a quote (`'--`), between SQL keywords, or as MySQL `/*!`.

**Measured** in OpenResty with the real signature table:

| Data | Values | Signature hits |
|---|---|---|
| Benign User-Agents, 2,000 JWTs, BEM classes, globs, CLI flags, prose with `--` | 2,044 | **0** |
| Benign rows of the training set | 31,626 | 329. Every one is a complete SQL statement that the Kaggle set labels benign (e.g. `SELECT … UNION SELECT …`); 0 hits on anything else. |
| SQLi rows of the training set | 21,838 | 10,511 (48%). The rest is left to the model, as intended for high-precision rules. |
| Good-word attacks (10 payloads appended to 6 real User-Agents) | 60 | **60** |

If your application legitimately accepts SQL text in a parameter (a database console or SQL tutorial), run that route with `WAF_REGEX_MODE=monitor`, or keep it out of the WAF.

**Performance and ReDoS safety.** Inspection makes no network calls; the regex is CPU work in the nginx worker:
- All signatures are combined into one alternation, so a benign value costs one scan. Only on a match are the signatures tried individually to name the one that hit.
- Patterns are JIT-compiled once per worker (`ngx.re.find` with the `jo` flags, plus `i` for case-insensitive matching).
- They use possessive quantifiers (`*+`, `++`), which never backtrack, so matching time is linear in the input.
- Measured: about 3 µs for a User-Agent or JWT, and 27 µs per KB of text. Values over 128 KB are rejected before the check.
- Hostile inputs took at most about 6 ms at 128 KB with no blow-up: unclosed comments, 64K `/*` openers, repeated `' or '`, 128 KB of brackets, and backreference bait.
- `lua_regex_match_limit 100000` in `nginx.conf` is the backstop. If a match ever errors, the value is sent to the model instead of skipping inspection.
- End to end, browser-like traffic (User-Agent, Referer, cookies including a JWT with `--`) ran at p50 12 ms / p95 16 ms per request, the same as before.

**Adding a signature:** add an entry to `SIGNATURES` with an `id` and a `category`, using the `GAP`/`SEP` building blocks for whitespace and comments, and possessive quantifiers only. Test it against benign traffic from your own logs before deploying: a signature blocks without any score or threshold, so one false positive blocks every request that contains it. Then run `docker compose restart openresty`.

#### OWASP Top 10 coverage

The signatures table also covers attacks beyond SQLi. Every signature has a category, which is logged as `waf_category`, sent in alerts, and charted on the dashboard ("Attack types"). The ML model scores SQLi only; the other categories are signatures, so they block immediately without an ML call.

A WAF stops attacks that arrive in requests. It can't fix flaws in your app's own logic, so some Top 10 (2025) categories are only partly or not at all within reach:

| OWASP Top 10:2025 | What this WAF does | Category / where |
|---|---|---|
| A01 Broken Access Control | Path traversal (`../../`, encoded), sensitive-file probes (`/.env`, `/.git/`, `/etc/passwd`, `php://filter`), SSRF to cloud metadata and via `gopher://` or numeric-IP tricks. It can't tell whether user A may see user B's data. | `lfi`, `ssrf` |
| A02 Security Misconfiguration | Adds `X-Content-Type-Options`, `Referrer-Policy` and `X-Frame-Options` when the app doesn't set them, and removes `X-Powered-By`. Blocks XXE (`<!ENTITY ... SYSTEM`, DTD subsets). | `nginx.conf`, `xxe` |
| A03 Software Supply Chain Failures | Virtual patches for well-known exploits of vulnerable components: Log4Shell (including obfuscated `${${lower:j}ndi:`), Shellshock, Struts/OGNL, Spring4Shell, Java deserialization. Not a substitute for updating them. | `rce` |
| A04 Cryptographic Failures | Not addressable by a WAF. | n/a |
| A05 Injection | SQLi (signatures + ML), XSS, OS command injection, server-side template injection, NoSQL operator injection (also in JSON keys and `user[$ne]` parameter names), CRLF / response splitting. | `sqli`, `xss`, `cmdi`, `ssti`, `nosqli`, `crlf` |
| A06 Insecure Design | Not addressable by a WAF. | n/a |
| A07 Authentication Failures | Login brute force: POSTs to login, password, token and OTP paths are limited to 10 per minute per IP (burst 5), then answered 429. | `nginx.conf` (`waf_login`) |
| A08 Software or Data Integrity Failures | Java deserialization payloads only. | `rce` |
| A09 Security Logging and Alerting Failures | Every decision is logged (JSON, Loki, Grafana) and alerted (webhook / n8n). | section 7 |
| A10 Mishandling of Exceptional Conditions | Requests that can't be fully inspected are rejected, and fail-open is budgeted per client (see *Decisions and fail-open*). | existing |

Recon tools announcing themselves in the User-Agent (sqlmap, Nikto, Nmap NSE, ffuf, ...) are blocked too (`scanner`).

**How the new signatures avoid false positives.** Ordinary formatting HTML (`<b>`, `<img src=...>`) isn't flagged; only script-capable tags, event handlers, script URLs and DOM sinks are. "JavaScript: The Good Parts", "Tom & Jerry", `?id=5&sort=price`, relative URLs like `a/../b`, `/.github/`, `{{ name }}` and plain localhost or private-network URLs all pass. English words that are also shell commands (`cat`, `sleep`, `ping`) only count with a typical argument. Measured against the 31,626 benign rows of `data/sqli.csv`, the new categories matched none. `tests/test_signatures.py` holds the attack and look-alike cases, and checks every pattern against backtracking blow-ups.

**If a category misfires on your app**, switch it off with `WAF_DISABLED_CATEGORIES`, e.g. `WAF_DISABLED_CATEGORIES=nosqli` for an API that takes MongoDB-style filters such as `filters[price][$gte]=10` (Strapi), or `cmdi` for a site where users post shell commands. Then run `docker compose up -d openresty`.

#### Verdict cache

User-Agents, cookies and common parameter values repeat across requests, and the model gives the same score for the same input. So the WAF caches each value's probability in `lua_shared_dict waf_verdicts` (keyed by SHA-256, TTL `WAF_CACHE_TTL_S` = 300 s, least-recently-used values evicted first) and sends only unseen values to the API. Without the cache, inspecting User-Agents would put almost every request (static assets included) through the model.

Measured with browser-like traffic (User-Agent, Referer, 3 cookies, unique search parameters): about 6 values per request, of which **18% were sent to the model**. The ML round-trip was **p50 9 ms, p95 13 ms**. A known-bad value is blocked straight from the cache, even while the API is down. After a model update, cached scores persist until their TTL expires; restart OpenResty to clear them immediately.

### Decisions and fail-open

Each request gets exactly one of these outcomes, logged as `waf_action`:

| `waf_action` | Meaning | Response |
|---|---|---|
| `skip` | Nothing to inspect | proxied |
| `allow` | Scored below the threshold | proxied |
| `block` | A value matched a regex signature (`waf_engine: regex`), or a parameter value scored `>= WAF_BLOCK_THRESHOLD`, or (with `WAF_EXTENDED_MODE=block`) a path, header or cookie value scored `>= WAF_EXTENDED_THRESHOLD` (`waf_engine: ml`) | 403 |
| `monitor` | Would have been blocked or rejected, but monitor mode applies (`WAF_MODE=monitor`, or an extended value with `WAF_EXTENDED_MODE=monitor`) | proxied |
| `reject` | Request too large or complex to inspect fully | 403 |
| `banned` | The client IP is banned (see *Automatic IP bans*); not inspected | 403 |
| `fail_open` | ML API timed out (`WAF_READ_TIMEOUT_MS`, default 50 ms), returned 503, was unreachable, or the circuit breaker is open | proxied, error logged |
| `fail_closed` | Same failures, with `WAF_FAIL_MODE=closed` | 503 |

**Circuit breaker:** while the ML container is stopped or restarting, looking up its name can hang until the DNS timeout. When a call fails because the API is down (DNS failure, connection refused, or 503 `model_unavailable`), the WAF skips the API for `WAF_BREAKER_SECONDS` (5 s), and those requests fail open in milliseconds (`waf_reason: ml_api_circuit_open`). In testing, one request per window took 0.5 s and the rest about 8 ms. Timeouts and `overloaded` responses don't trip the breaker, because an attacker can cause those.

The WAF decides from the per-value `probabilities` returned by `/scan/batch` and its own thresholds; the API's `SQLI_THRESHOLD` only labels the API's audit log. Start new deployments in `WAF_MODE=monitor` and review the logs for false positives before switching to `block`.

**Fail-open is a bypass under load.** Anything that makes the ML API slower than the timeout switches inspection off. That includes plain traffic volume, which an attacker can generate on purpose.

The worst case is a **single IP** sending one burst of 100 requests, which the rate limit allows (burst 100). Each request carried a unique SQLi variant that only the model catches. Run from inside the Docker network with `loadtest.py --payload attack --unique`:

| Configuration | Attacks that got through (of 100) |
|---|---|
| One request per model call (before micro-batching) | 84 |
| Micro-batching | 69–74; the API answered, but the burst still exceeded the 50 ms budget |
| Micro-batching + per-client fail-open budget (default) | **5**, the budget; the other 95 got 403 or 503 |

With a 50 ms budget, a client that controls its own burst size can always outrun the model, so capacity alone can't close this. The **per-client fail-open budget** is a policy fix:
- Each client IP may fail open at most `WAF_FAIL_OPEN_BUDGET` (5) times per `WAF_FAIL_OPEN_WINDOW_S` (10 s). Beyond that, its requests that can't be scored get **503** (`waf_reason: fail_open_budget_exhausted:…`) instead of passing.
- Only failures a client can cause itself count: `ml_api_timeout` and `ml_api_status_503` (overloaded).
- ML outages do **not** count (circuit breaker open, DNS failure, connection refused), so an ML restart still fails open for everyone. Tested: with `ml-api` stopped, all 20 requests from one IP failed open.
- **The cost:** a single client firing about 100 simultaneous requests gets 503s for part of that burst instead of silently uninspected 200s. Clients behind one NAT share a budget.
- A distributed attack (many IPs) still gets up to 5 bypasses per IP per window. Fail-open is inherently a trade-off; use `WAF_FAIL_MODE=closed` where you can't accept that.

Throughput with micro-batching: a single client sending 1,000 unique requests at concurrency 100, with the rate limit disabled, was fully scored after the opening burst at up to about 250 req/s. The load generator, not the WAF, was the limit there.

Mitigations included:
- Micro-batching in the API and the per-client fail-open budget (above).
- A fast model (see tuning).
- The verdict cache, which keeps most values away from the model.
- Keep-warm in the API. After a few idle minutes, the first prediction took 60–80 ms instead of about 8 ms (cold caches, model memory paged out), which made it fail open. Each worker now runs a dummy prediction after `SQLI_KEEP_WARM_S` (5 s) of idleness; after a 3-minute idle period, the first predictions took 9–13 ms.
- `WEB_CONCURRENCY=4`.
- Load shedding in the API.
- A per-IP `limit_req` (50 req/s, burst 100, then 429) in `nginx.conf`, which runs before the WAF so one source can't saturate the model.

What you still need to do:
- Size `WEB_CONCURRENCY` for your peak traffic, at roughly 80 req/s per worker with a 50-tree model on the test machine.
- Alert on the rate of `waf_action:"fail_open"`.
- Consider `WAF_FAIL_MODE=closed` for high-value endpoints.
- Load-test with `loadtest.py` (see below) after changing the model, worker count or timeouts.

#### Load testing (`loadtest.py`)

```bash
# accurate latencies: run the load generator inside the Docker network
docker run --rm --network automatedsqliattackdetecter_app -v "$PWD:/w" python:3.14-slim \
  sh -c "pip install -q httpx && python /w/loadtest.py --target http://openresty:8080/search --unique --payload attack"
# from the host, with the WAF's own per-second outcomes
python loadtest.py --unique --waf-log
```

Pitfalls this script avoids:
- **The verdict cache:** without `--unique`, every request after the first is answered from the cache and the model is never exercised. In one run, 1,000 requests sent 6 values to the model.
- **Spoofed `X-Forwarded-For`:** this doesn't bypass the rate limit. It keys on the TCP peer address on purpose, so a header can't evade it.
- **Client-side latency:** it can't tell a timeout from a cache hit or a 429. On Windows/macOS, Docker Desktop's port forwarding added 0.5–6 s per request while the WAF itself answered in 0–3 ms. `--waf-log` reads the WAF's JSON access log, which records each request's actual outcome (`waf_action`, `waf_reason`, e.g. `ml_api_timeout`, `ml_api_circuit_open`).
- **The circuit breaker:** it only opens when the ML API is *down* (`ml_api_circuit_open`). Overload never opens it; overload shows up as `ml_api_timeout` or `ml_api_status_503`.
- Behind a load balancer, key the rate limit on the real client IP; with the default key, every request appears to come from the load balancer.

### Logging

OpenResty writes one JSON line per request (log format `json_waf`) both to stdout (`docker compose logs`) and to hourly files on the `waf_logs` volume (`/var/log/waf/access-YYYY-MM-DDTHH.log`), which Alloy ships to Loki:

```json
{"timestamp":"2026-10-29T21:34:10+00:00","client_ip":"172.23.0.1","status":403,"request_method":"GET",
 "request_uri":"/item?id=1%27%20where%20311%3D311%20or%202367%3D(select%20count(*)%20from%20rdb%24fields%20as%20t3)",
 "user_agent":"curl/8.21.0","waf_engine":"ml","waf_signature":"","ml_probability":"0.7748","waf_action":"block",
 "waf_reason":"sqli_detected","waf_source":"arg:id","request_id":"7e6f80...","host":"localhost","path":"/item",
 "bytes_sent":81,"request_time":0.011,"upstream_time":"","waf_items":"2","waf_ml_items":"1","waf_latency_ms":"10.0",
 "waf_ml_request_id":"c9febaa1..."}
```

`waf_engine` is `regex` when a signature decided the request (`waf_reason: <category>_signature`, e.g. `sqli_signature` or `xss_signature`, `waf_signature` = the signature id, `ml_probability` empty, `waf_ml_items: 0`) and `ml` when the model did (`ml_probability` = the top score). `waf_category` is the attack type of a block or monitor decision (`sqli`, `xss`, `cmdi`, `lfi`, `ssrf`, `rce`, `ssti`, `xxe`, `nosqli`, `crlf`, `scanner`), and empty otherwise. Alerts carry the same `category`; SQLi alerts keep `event: "sqli_detected"`, and the others use `event: "attack_detected"`. Login requests over the brute-force limit are logged with `status: 429` and an empty `waf_action`, because the limit applies before the WAF runs.

**`request_uri` includes the query string**, so attack payloads are visible to analysts, but so is anything applications put in URLs: password-reset tokens, API keys, email addresses. Loki keeps logs for 30 days (`retention_period` in `monitoring/loki-config.yml`), and Grafana is published on localhost only, behind a password; see section 7. Values are JSON-escaped (`escape=json`), so attacker-controlled input can't break out of its field or forge extra log lines.

Local log files: OpenResty can't be told to reopen a rotated file from another container without Docker-socket access, which is root-equivalent. So it writes one file per hour, and an nginx timer deletes files older than `WAF_LOG_RETENTION_HOURS` (24). Tested: a file 30 hours old was deleted at startup, and one 2 hours old was kept.

`waf_source` names where the highest-scoring (or flagged) value came from: `arg:<name>`, `body:<name>`, `multipart:<name>`, `json`, `body`, `path`, `path:segment`, `header:<name>`, `referer-arg:<name>` or `cookie:<name>`. `waf_items` is the number of values inspected, and `waf_ml_items` the number sent to the model (the rest came from the cache). `path` is `request_uri` without the query string. `waf_ml_request_id` links to the ML API's audit event, which holds SHA-256 hashes of the flagged values. Fail-open errors also go to stderr with their cause, for example `ml_api_timeout` or `ml_api_status_503`. Responses carry `X-Request-ID`, which is also forwarded to the backend.

### Incident-response webhook (n8n etc.)

Set `WAF_ALERT_WEBHOOK_URL` (and optionally `WAF_ALERT_WEBHOOK_TOKEN`, sent as `Authorization: Bearer ...`). On each detection (`block` or `monitor`), the WAF POSTs:

```json
{"event":"sqli_detected","action":"block","ts":"2026-10-29T01:12:03Z","request_id":"85ff94ef...","ml_request_id":"54da4a51...",
 "ip":"203.0.113.7","method":"POST","host":"shop.example.com","path":"/login","probability":0.9594,"threshold":0.5,
 "source":"body:pass","flagged_count":2,
 "blocked_values":[{"source":"body:pass","probability":0.9594,"value":"1' OR '1'='1' --"},
                   {"source":"cookie:sid","probability":0.91,"value":"abc' AND SLEEP(5)#"}],
 "source_engine":"ml"}
```

A signature hit sends `"source_engine":"regex"` and the signature that matched. It has no probability, threshold or `ml_request_id`, and `blocked_values` holds the matching value:

```json
{"event":"sqli_detected","action":"block","source_engine":"regex",
 "signature":{"id":"union_select","pattern":"\\bunion(?:\\s|\\(|/\\*…)++(?:(?:all|distinct)…)?select\\b"},
 "ip":"203.0.113.7","method":"GET","host":"shop.example.com","path":"/account","probability":null,"source":"cookie:pref",
 "flagged_count":1,"blocked_values":[{"source":"cookie:pref","signature":"union_select","value":"1' UNION SELECT password FROM users--"}], ...}
```

- The POST is sent from a zero-delay `ngx.timer`, after the client has its 403, so a slow or dead webhook never adds latency.
- Alerts are limited to one per client IP per `WAF_ALERT_COOLDOWN_S` (60 s), so an attack burst doesn't flood the workflow.
- HTTPS certificates are verified.
- `blocked_values` holds up to 5 flagged values, each cut to 256 characters.
- **On a false positive, `blocked_values` is a real user's input, possibly a password.** Set `WAF_ALERT_INCLUDE_VALUES=false` to send only the source and probability.

#### n8n workflow (`n8n_sqli_alert.json`)

Import it via *Workflows → Import from File*. Tested by importing into n8n 2.45.5 (node versions: Webhook 2.2, HTTP Request 4.5, Code 2, If 2.4, Slack 2.7) and receiving live alerts from the WAF.

```
WAF alert webhook ─► AbuseIPDB lookup ─► Build alert ─► High-threat IP? ─┬─ true  ─► Slack: high-threat alert (#security-incidents, @here)
 (POST, header auth)   (GET /api/v2/check,   (merge + escape)  (score >= 50)   └─ false ─► Slack: standard alert (#security-alerts)
                        continues on error)
```

1. **WAF alert webhook**: create a *Header Auth* credential with name `Authorization` and value `Bearer <WAF_ALERT_WEBHOOK_TOKEN>`. Unauthenticated posts get 403. Point the WAF at the production URL, for example `WAF_ALERT_WEBHOOK_URL=https://n8n.example.com/webhook/waf-sqli-alert`.
2. **AbuseIPDB lookup**: replace `YOUR_ABUSEIPDB_API_KEY` with your key, ideally in a Header Auth credential named `Key` rather than in the workflow. The node continues on error, so a bad key, rate limit or outage still produces an alert, marked "lookup failed" and routed to the standard channel.
3. **Build alert** (Code): merges the alert with the AbuseIPDB data (score, reports, ISP, usage type, domain, country, Tor). It escapes `&`, `<`, `>` and backticks in everything from the alert, because the payload is attacker-controlled: unescaped, `<!channel>` in a payload would ping the whole channel, and `<url|text>` would render a disguised link.
4. **High-threat IP?** (If): routes on AbuseIPDB `abuseConfidenceScore >= 50`. A failed lookup scores -1 and goes to the standard channel.
5. **Slack** nodes: select a Slack credential (the bot needs `chat:write`) and check the channel names.

Then publish (activate) the workflow.

**Message format:** the alert is Slack Block Kit inside a coloured attachment: red for blocked, amber for monitor-mode detections. Each flagged value is its own section with a **Flag as false positive** button. The button opens a confirmation dialog and carries the original value, its source and the WAF `request_id` in its `value` (`{"v":1,"q":"<value>","s":"header:user-agent","r":"<request_id>"}`). Slack caps a button value at 2,000 characters and rejects the whole message if one is longer, so such a value gets no button. With the WAF's 256-character alert values, the worst case is 1,703 characters. Both Slack nodes use *Message Type: Blocks* with `blocksUi = {{ $json.slack_high }}` or `{{ $json.slack_standard }}`, built by the Build alert node. A regex alert shows "Detected by: regex signature `<id>` (no ML call)" instead of an ML confidence, and has **no** false-positive button. The button adds the value to the model's training data, which can't change the signature that blocked it; a signature false positive needs the pattern in `SIGNATURES` fixed, and the alert says so.

### Human-in-the-loop feedback (Slack button)

```
Slack button ─► n8n_feedback_loop.json ─────────────────────────────────────────────► ml-api POST /feedback ─► data/feedback/custom_traffic.csv
                 webhook → check timestamp → HMAC (Crypto node) → verify + parse        (bearer token)             (appended under a file lock)
                 └─► message updated via Slack's response_url: button removed, bar turned green, "Flagged as False Positive by @user"
```

**ML API: `POST /feedback`.** Disabled unless `FEEDBACK_API_KEY` (at least 16 characters) is set.

```bash
curl -X POST http://ml-api:8000/feedback -H "Authorization: Bearer $FEEDBACK_API_KEY" -H "Content-Type: application/json" \
     -d '{"query": "Mozilla/5.0 (Linux; Android 10; K) ...", "label": 0, "source": "header:user-agent", "flagged_by": "alice (U0123)", "request_id": "85ff94ef"}'
# 201 {"request_id": "...", "status": "recorded"}   (or "duplicate" if that query+label is already in the file)
```

- The token is compared in constant time and checked before the body is parsed. A wrong or missing token gets 401 and a `feedback_unauthorized` audit event.
- `label` must be the integer 0 or 1. `query` follows the same rules as `/scan`, and NUL characters and invalid UTF-8 are rejected because they would break the training CSV.
- Rows go to `FEEDBACK_CSV_PATH` with the columns `query,label,source,flagged_by,request_id,flagged_at`; training reads only `query` and `label`. An existing file keeps its own header, so a hand-made `query,label` file stays 2-column.
- **Concurrency:** every append takes an exclusive `flock` on a lock file shared by the 4 Gunicorn workers (in the container's `/tmp`), checks for a duplicate, and writes the row with one `O_APPEND` write. In testing, 200 concurrent distinct posts produced exactly 200 well-formed rows, and 50 concurrent identical posts produced 1 recorded and 49 duplicates.
  - The lock coordinates the workers *within one container*. Don't let several `ml-api` replicas write to the same file.
- Writes stop with 503 once the file reaches `FEEDBACK_MAX_BYTES` (50 MB).
- **Container access:** the container gets exactly one writable mount, `./data/feedback`, not the whole `./data` folder, so the API can't alter the main training set. **On Linux**, the directory must be writable by the container user: `mkdir -p data/feedback && sudo chown 10001:10001 data/feedback`.
- **Network access:** `ml-api` joins a new internal network named `sqli_feedback`. Only n8n needs to join it; the WAF's `ml` network stays closed to n8n.

**Enable Interactivity in Slack** (the same Slack app whose bot token posts the alerts):
1. <https://api.slack.com/apps> → your app → **Interactivity & Shortcuts** → turn **Interactivity** on.
2. **Request URL**: the feedback workflow's **production** webhook URL, for example `https://n8n.example.com/webhook/waf-slack-feedback`. Slack calls it from the internet, so n8n must be reachable over public HTTPS (reverse proxy or tunnel). Use the production URL, not the `/webhook-test/` one. **Save Changes**.
3. **Basic Information → App Credentials → Signing Secret**: copy it into a new n8n **Crypto** credential (field *Hmac Secret*) and select that credential on the **Sign with Slack secret** node.
4. No new OAuth scope is needed. Updates go through the `response_url` that Slack includes with each click (valid for 30 minutes, at most 5 updates). The bot still needs `chat:write` to post alerts.

**Set up the feedback workflow** (`n8n_feedback_loop.json`):
1. Import it, then set `YOUR_FEEDBACK_API_KEY` on **Record in training data** to the ML API's `FEEDBACK_API_KEY`. A Header Auth credential is better than leaving the key in the node.
2. Attach n8n to the feedback network. Either run `docker network connect sqli_feedback <n8n-container>`, or add it in n8n's compose file:

```yaml
services:
  n8n:
    networks: [default, sqli_feedback]
networks:
  sqli_feedback:
    external: true
```

3. Optional: put the Slack user IDs allowed to flag false positives in `ALLOWED_USER_IDS` in **Verify & parse click**. Others are rejected; their click fails silently, but the rejection appears in n8n's executions.
4. Publish the workflow, set `FEEDBACK_API_KEY` for `ml-api`, and run `docker compose up -d`.

Why the workflow has 7 nodes rather than 4:
- **Signature check:** Slack can't send a custom auth header, so its HMAC request signature is the only thing stopping anyone who learns the webhook URL from posting fake clicks and writing attack strings into the training data as "safe". The check takes three nodes (timestamp, HMAC, compare), because Code nodes may not `require('crypto')` by default. The signing secret lives in an encrypted n8n credential.
- **Message update:** the alert is updated through Slack's `response_url` with an HTTP Request node, not the Slack node. The Slack node's *update* operation stores the message timestamp as a number, so a timestamp such as `1761700000.123450` loses its trailing zero and the update fails with "message not found".
- **Failure path:** if the ML API is unreachable or rejects the row, the message says so, keeps its colour and keeps the button for a retry.

Tested in n8n 2.45.5 with simulated Slack clicks (correctly signed, real Slack payload shape) and the real ML API:
- **Valid click:** a row was appended and the message was updated green with that value's button removed.
- **Same click again:** reported "already in the training data".
- **Wrong signature:** rejected, nothing written.
- **10-minute-old timestamp:** rejected as a replay.
- **ML API down:** "not recorded" note, button kept.

The real Slack API was not called.

**Retraining with feedback:**

```bash
# review the new rows first: who flagged what (flagged_by, source, request_id)
python fetch_data.py --source github kaggle    # merges data/feedback/custom_traffic.csv; your labels override public ones
python tune.py                                 # or train.py
docker compose restart ml-api openresty        # openresty restart clears the WAF verdict cache
```

If the same value is labelled both 0 and 1 in the file, both rows are dropped at training time; delete the wrong row to resolve it.

#### What feedback does to the model (measured)

Retraining with just 15 flagged browser User-Agents (label 0), tested on User-Agents that were *not* in the feedback:

| | before | after feedback |
|---|---|---|
| Chrome, Android 15 / Pixel 9 | 0.54 | 0.08 |
| Instagram in-app (Android) | 0.61 | 0.25 |
| Edge on Mac, Chrome 138 on Windows, Yandex | 0.41–0.46 | 0.02–0.04 |
| `Mozilla/5.0' OR '1'='1' --` | 0.87 | 0.87 |
| real Android Chrome UA + `' OR 1=1--` | **0.71** | **0.27** |
| real Windows Chrome UA + `'; DROP TABLE users;--` | 0.50 | 0.28 |

Feedback fixes the false positives, but it also teaches the model that browser-shaped strings are safe. An attack appended to a real User-Agent then scores much lower. Adding counter-examples (each flagged value with SQLi payloads appended, labelled 1) only partly restored detection (0.27 → 0.50) and brought false positives back (Instagram 0.72), so it is not built in. The model scores the whole User-Agent as one string, and labelling can't fix that. Before switching `WAF_EXTENDED_MODE=block`, test attacks embedded in realistic headers against your retrained model. For headers, consider a structural check (for example, quotes or `--` in a User-Agent) alongside the model.

**Poisoning risk:** anyone who can click the button can turn a real attack into a "safe" training example, and your labels override the public dataset. That's why there's a confirmation dialog, the `ALLOWED_USER_IDS` allowlist, and the `flagged_by` audit trail, and why you should review new rows before retraining.

### Containers

- **openresty**:
  - Built on the official `openresty/openresty:1.29.2.5-alpine` image, plus `lua-resty-http` 0.17.1, which that image doesn't bundle and which `Dockerfile.openresty` installs with opm in a build stage.
  - Runs as `nobody`, with a read-only root, all capabilities dropped and `no-new-privileges`.
  - Publishes port `${WAF_PORT:-8080}`.
- **ml-api**:
  - Multi-stage `python:3.14-slim` image, running as uid 10001 under Gunicorn with Uvicorn workers.
  - `./models` is mounted read-only.
  - Read-only root and dropped capabilities.
  - `/docs` is disabled.
  - It has **no published port**. It sits on the `ml` network, which is `internal: true` (no internet access) and reachable only by the WAF. To call it directly for debugging, use `docker compose exec ml-api python -c "..."`, or temporarily add `ports: ["127.0.0.1:8000:8000"]`.
- **backend_app**: the placeholder application, reachable only through the WAF.
- The API serves an `.onnx` model, which isn't tied to the training Python or scikit-learn version. After retraining, export (train.py/tune.py do it automatically) and restart `ml-api`.

### Configuration (environment variables)

WAF (`openresty` service). Any new variable must also be declared with `env` in `nginx.conf`.

| Variable | Default | Purpose |
|---|---|---|
| `WAF_MODE` | `block` | `block` or `monitor` (log only) |
| `WAF_FAIL_MODE` | `open` | `open` (proxy when the ML API fails) or `closed` (503) |
| `WAF_BLOCK_THRESHOLD` | `0.5` | Minimum `sqli_probability` to block |
| `WAF_READ_TIMEOUT_MS` | `50` | ML API response timeout. Connect and send timeouts are 20 ms each (`WAF_CONNECT_TIMEOUT_MS`, `WAF_SEND_TIMEOUT_MS`). |
| `WAF_MAX_ARGS` | `100` | Max query or form arguments before `reject` |
| `WAF_MAX_ITEMS` | `128` | Max values (after chunking) before `reject`. Keep ≤ `SQLI_MAX_BATCH_SIZE`. |
| `WAF_CHUNK_SIZE` | `1024` | Chunk length for long values. Keep ≤ `SQLI_MAX_QUERY_LENGTH`. |
| `WAF_ALERT_WEBHOOK_URL` | unset | Incident-response webhook |
| `WAF_ALERT_WEBHOOK_TOKEN` | unset | Bearer token for the webhook |
| `WAF_ALERT_COOLDOWN_S` | `60` | Per-IP alert cooldown |
| `WAF_BREAKER_SECONDS` | `5` | How long to skip an ML API that is down |
| `WAF_REGEX_MODE` | `block` | Regex pre-filter: `block` (skip the ML call and answer 403), `monitor` or `off` |
| `WAF_DISABLED_CATEGORIES` | (none) | Signature categories to switch off, comma-separated: `sqli xss cmdi lfi ssrf rce ssti xxe nosqli crlf scanner` |
| `WAF_BAN_THRESHOLD` | `20` | Blocked requests within the window that ban an IP; `0` disables automatic bans |
| `WAF_BAN_WINDOW_S` | `600` | Window for counting blocked requests per IP |
| `WAF_BAN_DURATION_S` | `3600` | How long a ban lasts |
| `WAF_BAN_ALLOWLIST` | (none) | Comma-separated IPs that are never banned (loopback always is exempt) |
| `WAF_FAIL_OPEN_BUDGET` | `5` | Max fail-opens per client IP per window caused by timeouts or overload; beyond that, 503. `-1` = no limit |
| `WAF_FAIL_OPEN_WINDOW_S` | `10` | Window for `WAF_FAIL_OPEN_BUDGET` |
| `WAF_LOG_RETENTION_HOURS` | `24` | Hourly access-log files kept on the `waf_logs` volume |
| `WAF_EXTENDED_MODE` | `monitor` | Path, header and cookie inspection: `block`, `monitor` or `off` |
| `WAF_EXTENDED_THRESHOLD` | `0.8` | Minimum score for path, header and cookie values |
| `WAF_INSPECT_HEADERS` | `user-agent,referer` | Comma-separated header names to inspect |
| `WAF_MAX_HEADER_BYTES` | `4096` | Max size of an inspected header or cookie value before the request is uninspectable |
| `WAF_MAX_COOKIES` | `100` | Max cookies before the request is uninspectable |
| `WAF_CACHE_TTL_S` | `300` | Verdict cache lifetime; `0` disables the cache |
| `WAF_ALERT_INCLUDE_VALUES` | `true` | Include flagged values in alerts |
| `WAF_PORT` | `8080` | Compose only: host port |
| `WAF_ADMIN_PORT` | `8081` | Compose only: host port of the admin page, bound to `127.0.0.1` |
| `GRAFANA_ADMIN_PASSWORD` | **required** | Grafana `admin` password; compose refuses to start without it. Keep it in `.env`. |
| `GRAFANA_PORT` | `3000` | Compose only: Grafana's port, bound to 127.0.0.1 |

ML API (`ml-api` service):

| Variable | Default | Purpose |
|---|---|---|
| `SQLI_MODEL_PATH` | `models/sqli_detector.onnx` (compose: `/models/$SQLI_MODEL_FILE`) | ONNX model to load |
| `SQLI_MODEL_FILE` | `sqli_detector_optimized.onnx` | Compose only: file name inside `./models` |
| `SQLI_ORT_THREADS` | `1` | ONNX Runtime threads per worker process (more would oversubscribe the CPU across workers) |
| `SQLI_THRESHOLD` | `0.5` | P(SQLi) at or above which input is flagged |
| `SQLI_MAX_QUERY_LENGTH` | `10000` | Max characters per value |
| `SQLI_MAX_BATCH_SIZE` | `128` | Max values per `/scan/batch` call |
| `SQLI_MAX_BATCH_VALUES` | `16` | Max values the micro-batcher scores together in one ONNX Runtime call (cost per value grows with batch size) |
| `SQLI_MAX_QUEUE_MS` | `250` (compose: `40`) | Shed requests that waited longer than this for the model |
| `SQLI_KEEP_WARM_S` | `5` | Dummy prediction after this many idle seconds, so the next real one is fast; `0` disables it |
| `FEEDBACK_API_KEY` | unset (disabled) | Bearer token for `POST /feedback`, at least 16 characters |
| `FEEDBACK_CSV_PATH` | `data/feedback/custom_traffic.csv` (compose: `/feedback/custom_traffic.csv`) | CSV that feedback rows are appended to |
| `FEEDBACK_LOCK_PATH` | `<temp dir>/sqli_feedback.lock` | Lock file shared by the worker processes |
| `FEEDBACK_MAX_BYTES` | `52428800` | Stop accepting feedback once the CSV reaches this size |
| `SQLI_LOG_PREVIEW` | `false` | Include the first 120 chars of *malicious* inputs in logs |
| `SQLI_ENABLE_DOCS` | `true` (container: `false`) | Serve `/docs` and `/openapi.json` |
| `WEB_CONCURRENCY` | `2` (compose: `4`) | Gunicorn worker processes. Each holds a copy of the model and scores one request at a time. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxy IPs trusted for `X-Forwarded-For` |

## 7. Monitoring and SIEM dashboard (Grafana, Loki, Alloy)

```
openresty --(json_waf, hourly files)--> waf_logs volume --(read-only)--> alloy --(GeoIP lookup)--> loki <-- grafana (127.0.0.1:3000)
```

- **Grafana Alloy** (`monitoring/alloy-config.alloy`) tails the access log, parses the JSON, looks up `client_ip` in MaxMind GeoLite2, and pushes to Loki. Alloy replaces Promtail, which reached **end of life on 2 March 2026** with no further fixes. The pipeline is the same: parse JSON, set the timestamp, GeoIP, labels.
- **Loki** (`monitoring/loki-config.yml`) is a single binary with filesystem storage and 30-day retention. It has no published port.
- **Grafana** (`monitoring/grafana/`) has the Loki datasource and a **WAF SIEM** dashboard provisioned automatically (folder *WAF*). It is published on `127.0.0.1` only.
- **Isolation:** all three sit on their own `monitoring` network, with no route to the application or the model.
- **Hardening:** all containers run with a read-only root, all capabilities dropped and `no-new-privileges`. Alloy runs as its unprivileged image user (it would otherwise run as root).

### Setup

1. **GeoLite2 City database** (free, MaxMind account required). Sign up at <https://www.maxmind.com/en/geolite2/signup>, then create a license key under *Account → Manage License Keys* and download:

   ```bash
   curl -fL -u "ACCOUNT_ID:LICENSE_KEY" -o GeoLite2-City.tar.gz \
     "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
   tar -xzf GeoLite2-City.tar.gz          # creates GeoLite2-City_YYYYMMDD/
   cp GeoLite2-City_*/GeoLite2-City.mmdb ./GeoLite2-City.mmdb
   ```

   - **Keep it updated:** the GeoLite2 licence requires using a current database. MaxMind's [`geoipupdate`](https://github.com/maxmind/geoipupdate) (also as a container) automates that; run `docker compose restart alloy` after each update.
   - **Attribution:** "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com."
   - **If the file is missing:** Docker Desktop creates an empty *directory* named `GeoLite2-City.mmdb` and Alloy fails with `invalid stage config no such device`. Delete the directory, download the file, then run `docker compose up -d alloy`.
2. **Grafana password:** copy `.env.example` to `.env` (git-ignored) and set `GRAFANA_ADMIN_PASSWORD` to a long random string. Compose refuses to start without it. Set `GRAFANA_PORT` there if 3000 is taken.
3. Run `docker compose up -d` and open <http://127.0.0.1:3000>. Log in as `admin`, then open *Dashboards → WAF → WAF SIEM*.

**Behind a load balancer or CDN**, `client_ip` (`$remote_addr`) is the balancer's address. GeoIP, the Top-IP panel, the rate limit, the fail-open budget and alerts would all see one "client". Tell nginx which proxies to trust, in the `server` block of `nginx.conf`:

```nginx
set_real_ip_from 10.0.0.0/8;          # your load balancer's addresses only
real_ip_header   X-Forwarded-For;
real_ip_recursive on;
```

Never trust `X-Forwarded-For` from arbitrary clients; it's trivially spoofed.

### Labels vs. structured metadata

Every distinct combination of Loki *labels* is a separate stream, and Loki allows 5,000 streams per tenant by default. So only low-cardinality fields are labels. Per-IP, per-city and per-coordinate fields are **structured metadata**: filterable and groupable in LogQL exactly like labels (`sum by (client_ip)`, `| geoip_city_name="London"`), but they don't create streams. Making latitude, longitude or client IP labels would create a stream per location or IP, and Loki would start rejecting logs.

| Labels (stream selectors) | Structured metadata |
|---|---|
| `job` (`waf`), `status`, `waf_action`, `waf_engine`, `waf_category`, `geoip_country_name` | `client_ip`, `waf_signature`, `geoip_city_name`, `geoip_country_code`, `geoip_location_latitude`, `geoip_location_longitude` |

Anything else in the line (`request_uri`, `user_agent`, `ml_probability`, …) is available with `| json` at query time.

### Dashboard queries (LogQL)

The **WAF SIEM** dashboard already contains these panels. To build them yourself, paste the queries into a panel on the Loki datasource.

"Blocks" means `waf_action="block"`: a 403 from a signature or the model. Plain `status="403"` also counts `reject` (requests too large to inspect), which has no engine. To include header and cookie detections in monitor mode, use `waf_action=~"block|monitor"`.

**a. Traffic vs. blocks:** *Time series*, query type *Range*, legend `HTTP {{status}}`, unit *requests/sec*:

```logql
sum by (status) (rate({job="waf", status=~"200|403"} [$__auto]))
```

**b. WAF engine efficacy:** *Pie chart*, query type *Instant*, legend `{{waf_engine}}`, *Value options → Show: All values*:

```logql
sum by (waf_engine) (count_over_time({job="waf", waf_action="block"} [$__range]))
```

**c. Top 10 attacking IPs:** *Bar gauge* (horizontal), query type *Instant*, *Show: All values*, transformation *Sort by* `Value #A` (descending), field *Display name* `${__data.fields.client_ip}`:

```logql
topk(10, sum by (client_ip) (count_over_time({job="waf", waf_action="block"} [$__range])))
```

**d. GeoMap:** *Geomap*, query type *Instant*. Add the transformation *Convert field type* to change `geoip_location_latitude` and `geoip_location_longitude` to *Number*. Then add a *Markers* layer with *Location mode: Coords* on those two fields and *Size* from `Value #A`:

```logql
sum by (geoip_location_latitude, geoip_location_longitude, geoip_city_name, geoip_country_name) (
  count_over_time({job="waf", waf_action="block"} | geoip_location_latitude != "" [$__range])
)
```

Grafana turns a Loki *instant* query into **one table**: a `Value #A` column plus a column per label. That's why panels b–d need *Show: All values*, and why the GeoMap needs no reduce step.

More useful queries:

```logql
{job="waf", waf_engine="regex"} | waf_signature="union_select"                              # hits of one signature
sum by (waf_signature) (count_over_time({job="waf", waf_engine="regex"} [$__range]))       # signature leaderboard
sum by (waf_category) (count_over_time({job="waf", waf_action="block", waf_category=~".+"} [$__range]))  # attack types
sum(rate({job="waf", waf_action="fail_open"} [5m]))                                        # fail-opens: alert on this
{job="waf", waf_action="block"} | json | ml_probability != "" and ml_probability < 0.6     # borderline ML blocks
```

**Tested** with MaxMind's official test database (known test IPs), real WAF traffic and synthetic block lines from five test locations:
- **Grafana query API:** every query above returned the expected values.
- **Rendered dashboard:** all five panels display correctly (traffic chart, engine donut, map markers sized by count, IP bars, log lines). It was checked with a headless browser, because three of the panels were broken until the "one table" behaviour above was handled.
- Loki holds only the intended labels, and the hourly cleanup works.

**Grafana plugins:** Grafana 13 auto-updates its bundled plugins, including the Loki datasource, at startup. With a read-only root filesystem, that update unregistered the bundled Loki plugin and then failed to replace it, leaving Grafana with no Loki datasource. Runtime plugin downloads are therefore disabled (`GF_PLUGINS_PREINSTALL_DISABLED`, `GF_PLUGINS_PREINSTALL_AUTO_UPDATE`). Update plugins by moving to a newer Grafana image.

**Editing the dashboard:** it's provisioned read-only from `monitoring/grafana/dashboards/waf-siem.json`. Edit that file and run `docker compose restart grafana`; file-change detection doesn't work reliably through Docker Desktop bind mounts. Or use *Save as* in Grafana to make your own copy.

## 8. Tests and CI

```bash
pip install -r requirements-dev.txt
pytest                      # about 10 s
```

The tests don't need the datasets or a trained model: `tests/synthetic_data.py` generates a small labelled set, and the session trains and exports a 20-tree model from it. That model only has to separate obvious cases; it says nothing about the production model's accuracy.

| File | What it checks |
|---|---|
| `test_preprocessing.py` | `preprocess()` produces exactly scikit-learn's char-analyzer n-grams (whitespace runs, Unicode, case) |
| `test_train.py` | Dataset cleaning; the ONNX export matches scikit-learn with 0 decision flips; the **fidelity gate rejects an export without the sublinear-TF fix** and writes no file; `ngram_range` not starting at 1 is refused |
| `test_api.py` | `/scan` and `/scan/batch` against scikit-learn's scores; input validation without reflecting input; 503 for a missing model or one exported with other preprocessing; `/feedback` auth, de-duplication, CSV integrity and concurrent appends; micro-batching keeps results aligned and sheds requests that waited too long |
| `test_n8n_workflows.py` | Runs the workflows' Code nodes with Node.js (`tests/n8n_code_node.js` stands in for n8n): attacker text is escaped in Slack, a genuine signed click round-trips the exact flagged value, and forged clicks are rejected (wrong secret, tampered body, stale timestamp, truncated signature, foreign `response_url`) |
| `test_signatures.py` | The `SIGNATURES` block cut from `waf_rules.lua`, run by `resty` in the OpenResty image: 91 attacks hit the expected signature, 62 benign look-alikes (user agents, JWTs, URLs, names like O'Brien) hit none, and 14 adversarial inputs up to 100 KB finish in under 250 ms |

`test_n8n_workflows.py` skips without Node.js and `test_signatures.py` without Docker.

**End-to-end smoke test:** `tests/smoke.py` drives a running stack: benign traffic reaches the backend, and a signature hit, an ML-only attack and an attack in a JSON body are all blocked. With `--compose-logs` it also checks that the access log credits each block to the right engine.

```bash
docker compose up -d openresty
python tests/smoke.py --url http://localhost:8080 --compose-logs
```

**CI** (`.github/workflows/ci.yml`, on every push to `main` and every pull request):
1. **test:** `pytest` on Python 3.14, including the Node.js and Docker tests.
2. **smoke:** trains a model on synthetic data with `train.py` (so the ONNX fidelity gate runs on every build), builds the images, starts WAF + ML API + backend with `docker compose up --wait`, and runs `tests/smoke.py`.

## Security notes

- **Defense in depth:** this is a detection layer, not a fix. Parameterised queries remain the actual defense against SQLi.
- **Model file:** the API loads only ONNX models, which can't execute code when loaded. The training tools still read and write joblib pickles (`.pkl`, where loading can run arbitrary code), so only load pickles you trained yourself. The read-only mount stops the container from tampering with the model, but protecting the host directory is up to you.
- **Exposure:** only the WAF should be reachable from outside. The ML API has no authentication and sits on an internal network. Put TLS termination in front of OpenResty, or add it to `nginx.conf`.
- **Logs are sensitive:** they hold client IPs (personal data in many jurisdictions), User-Agents and full request URIs with attack payloads and whatever else apps put in URLs. Grafana is localhost-only behind a required password, and Loki keeps 30 days. Put SSO and TLS in front of Grafana before sharing it, and match the retention to your data-protection rules.
- **Evaluation:** test-set scores on the public datasets are near 100% because those test sets are easy. In hand tests, simple attacks such as `1; DROP TABLE users` were missed and benign text such as `1 or 2 items` was flagged, depending on the training data. Before relying on the model, check it against inputs from your own application, run in `monitor` mode first, and retrain with confirmed false positives and new attacks.
