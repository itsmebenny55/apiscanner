# APISCAN Audit Tool Modernization Guide

This guide documents the modernized audit tools introduced alongside the legacy
scanners. The goal was to move the core auditors from a **`requests` +
`ThreadPoolExecutor`** design to a **bleeding-edge async stack** without breaking
the existing `apiscan.py` integration.

| Legacy tool            | Modernized tool                    | OWASP API |
|------------------------|------------------------------------|-----------|
| `ssrf_audit.py`        | `improved_ssrf_audit.py`           | API7 SSRF |
| `bola_audit.py`        | `improved_bola_audit.py`           | API1 BOLA/IDOR |
| `broken_auth_audit.py` | `improved_broken_auth_audit.py`    | API2 Broken Auth |
| —                      | `improved_common.py` (shared core) | — |

All modern plumbing lives in **`improved_common.py`** so the three auditors share
one implementation of the async client, LLM fuzzing, browser probing, graph
correlation, fingerprinting, streaming and logging.

---

## 1. What changed (the seven priorities)

### 1. `requests` + threading → `httpx` + `asyncio`
`AsyncHTTPClient` (in `improved_common.py`) wraps `httpx.AsyncClient` with:

- a shared `asyncio.Semaphore(concurrency)` — replaces the thread pool;
- an async `RateLimiter` (requests-per-second pacing via a monotonic gap);
- automatic retries with linear backoff;
- per-request timing (for blind-SSRF latency analysis);
- optional HTTP/2 (falls back to HTTP/1.1 when `h2` is not installed);
- `from_requests_session()` to inherit headers/cookies/verify/proxies from the
  `requests.Session` that `apiscan.py` already builds.

Each auditor now fans out probes with `asyncio.gather(...)` instead of
submitting to a `ThreadPoolExecutor`. Concurrency is bounded once, at the client,
so every probe across every endpoint shares the same connection and rate budget.

### 2. Playwright for browser-based detection
`PlaywrightProbe` lazily launches headless Chromium. The auditors call it when a
response looks like a WAF/JS challenge (HTTP 403/429/503 or a "Just a moment…"
interstitial). The browser executes JavaScript and clears interstitials, then the
rendered response is analyzed like any other. When Playwright is not installed the
probe reports `available = False` and the scan stays on `httpx`.

### 3. LLM-based payload generation (Claude)
`LLMPayloadGenerator` uses `anthropic.AsyncAnthropic` to expand the static seed
payloads with context-aware ones:

- SSRF: extra bypass/encoding payloads for the detected server;
- BOLA: additional object-id candidates (adjacent ids, roles, sentinels);
- Broken Auth: additional default/weak credential pairs.

It is **off by default** (`use_llm=False`). It activates only when `use_llm=True`
**and** the `anthropic` package is installed **and** `ANTHROPIC_API_KEY` (or
`LLM_API_KEY`) is set. Any failure (no key, rate limit, network) transparently
falls back to the static seed payloads, so scans never depend on the LLM. Results
are cached per (category, context) to avoid repeat calls.

### 4. Graph-based vulnerability correlation (networkx)
`VulnerabilityGraph` builds a typed `networkx.DiGraph` of
`endpoint → finding ← param / payload`. `correlate()` surfaces **systemic** issues
that per-finding views miss:

- parameters vulnerable across multiple endpoints (`systemic_params`);
- payload families that repeatedly succeed (`systemic_payloads`);
- hotspot endpoints ranked by finding count;
- severity rollups.

`export_graphml()` writes the graph for external analysis (Gephi, etc.). Without
`networkx` it falls back to equivalent dict-based aggregation.

### 5. Passive fingerprinting ↔ active scanning balance
`PassiveFingerprinter` reads the **baseline** response headers/body first and
detects server tech, WAF vendor, cloud provider and JS challenges **without
sending any attack traffic**. `recommend()` then tunes the active phase:

- auto-enable the browser probe when a JS/WAF challenge is detected;
- throttle RPS behind an aggressive WAF to avoid blocks.

Every auditor runs one passive fingerprint before its active probes.

### 6. WebSocket support (real-time API testing)
`WebSocketProbe` (using the `websockets` package) connects, sends messages and
collects responses. `improved_broken_auth_audit.py` uses it to test whether
common WebSocket endpoints (`/ws`, `/websocket`, `/socket`, `/api/ws`) accept
**unauthenticated** connections. It handles both new (`additional_headers`) and
old (`extra_headers`) `websockets` APIs and degrades gracefully when the package
is missing.

### 7. Modern error handling and logging (structlog)
`get_logger()` returns a `structlog` logger with ISO timestamps and level-aware
console rendering. When `structlog` is absent it returns a shim over stdlib
`logging` that accepts the same `log.info("event", key=value)` keyword API, so
call sites are identical either way. Third-party transport loggers (`httpx`,
`httpcore`, …) are quieted to `WARNING`.

Results also **stream** to JSONL via `ResultStreamer` (one finding per line,
flushed immediately, deduped) so a long scan produces durable partial output even
if interrupted — and `ResponseCache` avoids re-probing identical requests.

---

## 2. Architecture

```
                 improved_common.py  (shared async foundation)
   ┌───────────────────────────────────────────────────────────────┐
   │ ScanConfig (pydantic)   AsyncHTTPClient (httpx+asyncio)         │
   │ RateLimiter             LLMPayloadGenerator (Claude)           │
   │ PassiveFingerprinter    PlaywrightProbe (headless Chromium)    │
   │ WebSocketProbe          VulnerabilityGraph (networkx)          │
   │ ResultStreamer          ResponseCache      get_logger(structlog)│
   │ run_async() sync↔async bridge                                   │
   └───────────────────────────────────────────────────────────────┘
            ▲                     ▲                      ▲
            │                     │                      │
 improved_ssrf_audit.py  improved_bola_audit.py  improved_broken_auth_audit.py
   AsyncSSRFAuditor        AsyncBOLAAuditor         AsyncAuthAuditor
```

Every heavy dependency (`playwright`, `networkx`, `structlog`, `websockets`,
`anthropic`, `h2`) is imported lazily and guarded. The toolkit **imports and runs
with only `httpx` + `pydantic`** installed; each extra package simply lights up
its feature. Check what is active:

```bash
python improved_common.py            # logs the capability map
```

---

## 3. Usage

### As a library (async — preferred)

```python
import asyncio
from improved_common import ScanConfig
from improved_ssrf_audit import AsyncSSRFAuditor

cfg = ScanConfig(concurrency=30, rps=20, use_llm=True, browser_auto=True)
auditor = AsyncSSRFAuditor(base_url="https://api.example.com", config=cfg)
eps = AsyncSSRFAuditor.endpoints_from_swagger("openapi.json", default_base="https://api.example.com")

findings = asyncio.run(auditor.test_endpoints_async(eps))
print(auditor.correlation())
auditor.save_report("ssrf.html", fmt="html")
```

### As a library (sync — drop-in for legacy call sites)

Each auditor exposes the **same synchronous method names** as its legacy
counterpart, wrapping the async core with `run_async()`:

```python
findings = auditor.test_endpoints(eps)                 # SSRF
results  = bola.run(spec)                               # BOLA
issues   = auth.test_authentication_mechanisms(spec_eps)  # Broken Auth
```

Because the class names are also aliased (`SSRFAuditor = AsyncSSRFAuditor`, etc.)
and the constructors accept the legacy positional/keyword forms, migrating
`apiscan.py` is a one-line import swap per tool, e.g.:

```python
# from ssrf_audit import SSRFAuditor
from improved_ssrf_audit import SSRFAuditor
```

### As a CLI

```bash
python improved_ssrf_audit.py        --url https://api.example.com --swagger openapi.json --use-llm --use-browser
python improved_bola_audit.py        --url https://api.example.com --swagger openapi.json --use-llm
python improved_broken_auth_audit.py --url https://api.example.com --swagger openapi.json --use-llm
```

---

## 4. Configuration (`ScanConfig`)

Validated with pydantic; construct directly or from `**kwargs`.

| Field | Default | Purpose |
|---|---|---|
| `concurrency` | 20 | Max in-flight requests (semaphore size) |
| `rps` | 15.0 | Requests-per-second cap |
| `timeout` | 15.0 | Per-request timeout (s) |
| `retries` / `retry_backoff` | 2 / 0.5 | Retry policy |
| `verify_tls` | False | TLS verification |
| `http2` | True | Try HTTP/2 (needs `h2`) |
| `blind_threshold` | 4.0 | Latency (s) for blind-SSRF detection |
| `use_browser` / `browser_auto` | False / True | Playwright: forced / auto-on-WAF |
| `use_llm` / `llm_model` | False / `claude-sonnet-4-5` | Claude fuzzing |
| `stream_results` / `cache_responses` | True / True | JSONL streaming, response cache |
| `output_dir` | `scan_output` | Where JSONL streams are written |

Legacy env knobs still work for SSRF: `APISCAN_SSRF_MAX_PARAMS`,
`APISCAN_SSRF_MAX_PAYLOADS`, `APISCAN_SSRF_MAX_ENCODINGS`.

---

## 5. Implementation patterns (reusable)

**Bounded async fan-out.** Bound concurrency once at the client with a semaphore
plus a rate limiter, then fan out freely with `asyncio.gather`. Probes never need
to know the global limit.

**Graceful optional dependencies.** Guard every heavy import
(`try/except ImportError`), expose an `available`/`enabled` flag, and provide a
working fallback path. The feature is a bonus, never a hard requirement — this
mirrors the repo's existing `sslyze` guard.

**One uniform response object.** `ProbeResponse` normalizes httpx, Playwright and
cache results into the same shape, so analysis code is source-agnostic and can
record `detected_via` (`httpx` / `browser` / `cache`).

**Sync/async bridge for legacy call sites.** `run_async()` runs a coroutine with
`asyncio.run`, or in a worker-thread loop if already inside a running loop. This
lets synchronous `apiscan.py` keep calling the auditors unchanged.

**Passive before active.** Fingerprint the baseline response first; let the result
decide browser usage and throttling before any attack payload is sent.

**Stream + dedupe.** Emit findings to JSONL as discovered, keyed for dedupe, so
long scans are crash-resilient and produce incremental output.

---

## 6. Install

```bash
pip install -r requirements.txt
# Browser detection (one-time, downloads Chromium):
python -m playwright install chromium
# LLM fuzzing:
export ANTHROPIC_API_KEY=sk-ant-...
```

Minimum to run (everything else degrades gracefully): `httpx`, `pydantic`.

---

## 7. Backward compatibility & migration notes

- **Report parity.** All three tools emit findings through the existing
  `report_utils.ReportGenerator`, so HTML/Markdown output matches the rest of
  APISCAN. `improved_bola_audit.py` reuses `TestResult` + `classify_risk` from
  `bola_audit.py` for identical severity scoring.
- **`save_report(path, fmt=...)` fix.** `ReportGenerator.save()` only writes HTML
  and takes no `fmt` argument. The improved `save_report()` handles this: HTML via
  `.save(path)`, Markdown via `generate_markdown()`. (The legacy `save_report`
  passes `fmt=` to `.save()`, which raises — worth fixing in the legacy tools too.)
- **Non-destructive.** The legacy `ssrf_audit.py` / `bola_audit.py` /
  `broken_auth_audit.py` are untouched; the modern tools are additive and can be
  adopted per-tool.
