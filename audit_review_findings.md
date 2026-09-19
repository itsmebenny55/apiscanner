# APISCAN Audit Tools — State-of-the-Art Technology Gap Review

Date: 2026-09-19
Scope: `/Volumes/My Shared Files/Projects/apiscanner`
Reviewer target files: `stealth_audit.py`, `ssrf_audit.py`, `bola_audit.py`,
`broken_auth_audit.py`, `authorization_audit.py`, `misconfiguration_audit.py`,
`inventory_audit.py`, `business_flow_audit.py`, `resource_consumption_audit.py`,
`broken_object_property_audit.py`, `safe_consumption_audit.py`

---

## 0. Executive summary

The audit suite is a mature, breadth-first OWASP API Top-10 (2023) scanner, but it is
architecturally anchored to **synchronous `requests` + small `ThreadPoolExecutor`
pools**. The genuinely modern capabilities the repo has recently grown
(curl_cffi JA3/JA4 impersonation, httpx HTTP/2, an adaptive-learning engine, LLM
clients, camoufox browser automation) are **only partially wired — or not wired at
all — into the eleven OWASP auditors**.

Highest-leverage gaps, in order:

1. **No `asyncio` anywhere in the audit path.** Every auditor blocks on `requests`,
   parallelized (when at all) by thread pools capped at 2–10 workers. This is the
   dominant throughput bottleneck and forces coverage-reducing payload caps.
2. **HTTP-client fragmentation.** `requests` (all), `httpx`/HTTP-2 (only
   `safe_consumption_audit.py`), `curl_cffi` via the shared `StealthSession`, and raw
   `socket`+`ssl` (`broken_auth_audit.py`) coexist with no unified client.
3. **`adaptive_learning_engine.py` is dead code** — not imported by any auditor or by
   `apiscan.py`. No LLM is used inside any detection loop.
4. **No browser automation / managed-challenge handling in the audit path.** SPA / JS
   endpoint discovery and Cloudflare Turnstile targets cannot be audited.
5. **Depth gaps vs. bleeding-edge** in JWT, GraphQL, and modern transports
   (gRPC / WebSocket / SSE), even though breadth coverage of the Top-10 is good.

---

## 1. Current tech stack

Source: `requirements.txt`, `pyproject.toml`, `setup.py`.

| Area | Library / version | Assessment |
|---|---|---|
| HTTP (sync) | `requests>=2.31.0`, `urllib3>=2.2.0` | Current, but sync-only. |
| TLS/HTTP2 impersonation | `curl_cffi>=0.5.0` | Modern; **but see §3 — only reaches auditors indirectly.** `0.5.0` floor is old (curl_cffi is at 0.7+ with newer impersonation profiles). |
| Async HTTP | `httpx>=0.27.0` | Present but used **only** in `safe_consumption_audit.py` (sync `httpx.Client`, not `AsyncClient`). |
| SOCKS | `PySocks>=1.7.1` | Fine (VN egress lanes). |
| Auth | `requests_ntlm`, `requests-oauthlib`, `oauthlib`, `PyJWT>=2.8.0` | Fine. |
| TLS analysis | `sslyze>=6.2.0` | Modern; **but `broken_auth_audit.py` hand-rolls raw `socket`/`ssl` instead of using it.** |
| AI | `openai>=1.0,<2.0`, `anthropic>=0.67.0` | Current SDKs, used only for report/doc generation, not detection. |
| Config/validation | `pydantic>=2.0`, `pydantic-settings>=2.0` | Modern. |
| Retry | `tenacity>=8.2.0` | Present; auditors mostly use `urllib3 Retry` or hand-rolled loops instead. |

Weaknesses:
- **All dependencies are `>=` floors with no lockfile** (no `requirements.lock`,
  `poetry.lock`, or hashes). Non-reproducible builds.
- **Minimum Python is 3.8** (`setup.py:145` → `required = (3, 8)`). Python 3.8 reached
  end-of-life 2024-10; 3.9 is next. This blocks use of `match`, `asyncio.TaskGroup`
  (3.11), `tomllib`, and modern typing.
- **`datetime.utcnow()` used pervasively** (e.g. `ssrf_audit.py:632`,
  `broken_auth_audit.py:74`, `broken_object_property_audit.py:197`) — deprecated in
  3.12; should be `datetime.now(timezone.utc)`.

---

## 2. Architecture: threading vs. async, requests vs. modern HTTP

**No `async def` / `await` / `aiohttp` exists in any of the eleven audit files.**
Concurrency is thread-pool or fully serial:

| Tool | Concurrency model | HTTP client | Notes |
|---|---|---|---|
| `ssrf_audit.py` | `ThreadPoolExecutor`, cap **10** (`SSRFConfig.max_concurrency`) | `requests` | Hand-rolled token bucket `_pace()` (`:288`); `verify=False` default. |
| `bola_audit.py` | `concurrent.futures`, default **2 workers** (`APISCAN_BOLA_WORKERS`, `:176`) | `requests` | JSON-shape fingerprinting; very low default parallelism. |
| `broken_auth_audit.py` | **Fully serial** (no pool) | `requests` + raw `socket`/`ssl` | TLS/cipher/JWT checks run sequentially. |
| `authorization_audit.py` | **Fully serial** | `requests` | Role matrix anonymous/user/admin. |
| `misconfiguration_audit.py` | `ThreadPoolExecutor` (`:16`) | `requests` | Largest tool (1222 lines). |
| `inventory_audit.py` | `ThreadPoolExecutor` (`:12`) | `requests` | Path-list probing (API9). |
| `business_flow_audit.py` | `ThreadPoolExecutor`, concurrency **4** (`:94`) | `requests` | `threading.Lock` for issue list. |
| `resource_consumption_audit.py` | `concurrent.futures` | `requests` + `HTTPAdapter`/`urllib3 Retry` (`:91`) | Retry on 429/5xx. |
| `broken_object_property_audit.py` | **Fully serial** | `requests` | No concurrency at all. |
| `safe_consumption_audit.py` | `concurrent.futures` | `requests` **and optional `httpx` HTTP/2** (`HttpxSessionWrapper`, `:336`) | Most modern tool. `APISCAN_HTTP2` env toggle. |
| `stealth_audit.py` | n/a | `requests` | **Dead code — see §7.** |

Key architectural problems:

- **Blocking I/O dominates.** For an I/O-bound scanner hitting hundreds of endpoints,
  `asyncio` + a single async client would give an order-of-magnitude more in-flight
  requests than the current 2–10 threads, without the per-thread memory/GIL context
  cost. `ssrf_audit.py` explicitly documents the pain at
  `ssrf_audit.py:403-408`:

  ```python
  # Limit SSRF probes to avoid combinatorial explosion:
  # 397 endpoints × 11 params × 30 payloads × 5 encodings = 655K+ requests.
  # Smart limiting: max 3 params, 4 payloads/param, 2 encodings.
  ```

  i.e. coverage is being **thrown away** to compensate for a slow transport. An async
  client with a bounded semaphore keeps coverage while controlling load.

- **No shared base auditor / HTTP layer.** Each tool re-implements the same helpers:
  `_headers_to_list`, `_safe_body`, `_log_issue`/`_record_issue`, `_canonical_path`,
  the ANSI `_tw()` writer (identical block in `ssrf_audit.py:256` and
  `business_flow_audit.py:121`), and its own rate limiter. `crawl_common.py` exists but
  the auditors do not import it. This blocks a single-point async/HTTP-2/stealth
  upgrade — every fix must be applied 11 times.

- **HTTP/2 is invisible to 10 of 11 tools.** Only `safe_consumption_audit.py` can send
  HTTP/2 (`safe_consumption_audit.py:355`, sync `httpx.Client(http2=...)`). Everything
  else is HTTP/1.1 via `requests`, so HTTP/2-specific findings (except the passive
  ALPN/Rapid-Reset check in `broken_auth_audit.py:439-490`) are unreachable.

---

## 3. Gaps vs. bleeding-edge

### 3.1 asyncio
Absent. Recommended target: an async core (`httpx.AsyncClient` or `aiohttp`) with a
shared `asyncio.Semaphore` rate/concurrency governor, replacing the per-tool
`ThreadPoolExecutor` + `_pace()` pattern. On 3.11+ use `asyncio.TaskGroup` for
structured cancellation.

### 3.2 curl_cffi TLS (JA3/JA4) impersonation — partially wired, fragile
Good news: `apiscan.py:104,1417-1430` wraps the auth session via
`enhance_with_stealth()` / `enhance_session_with_full_stealth()`, and
`stealth_session.py:74` defines `class StealthSession(CurlCffiSession)` with sticky
browser JA3/JA4 + HTTP/2. `--full-stealth` defaults to **True** (`apiscan.py:1858`),
so auditors normally inherit a curl_cffi-backed session.

Gaps:
- **Compatibility risk.** All auditors are written against `requests.Session` — they
  call `.request()/.get()/.post()`, `.cookies.get_dict()`, `.headers`,
  `resp.request.headers`, `resp.cookies.get_dict()`. `StealthSession(CurlCffiSession)`
  must emulate that full surface or auditors silently degrade. This coupling is
  undocumented and untested per-auditor.
- **Fallback loses fingerprint.** When `configure_authentication` fails,
  `apiscan.py:1414-1415` falls back to a plain `requests.Session()`; if stealth is off
  the TLS fingerprint reverts to Python's default (trivially bot-detectable).
- **`curl_cffi>=0.5.0` floor is stale** — newer impersonation profiles (recent Chrome/
  Firefox/Safari) require 0.7+. `stealth_session.py:65` still hard-defaults to
  `chrome124`.

### 3.3 Playwright / camoufox (browser automation) — not in audit path
`camoufox` appears only in the **dead** `stealth_audit.py:153` docstring;
`enhanced_camoufox.py` is a VN-crawler asset, not used by auditors. Consequence:
- No JS-rendered / SPA API endpoint discovery (XHR/fetch harvesting).
- No way to audit targets behind managed challenges (Turnstile) that require a real
  browser context.
Recommended: an optional Playwright-driven discovery mode that captures live XHR/fetch
calls and feeds them as endpoints into the existing auditors.

### 3.4 LLM integration — dead / report-only
- `ai_client.py`, `llmsetup.py` drive **report and documentation** generation only.
- **`adaptive_learning_engine.py` is imported by nothing** (`grep` across `apiscan.py`
  and all `*_audit.py` returns zero hits). A learning/feedback capability exists but is
  orphaned.
Bleeding-edge opportunities, none implemented:
- LLM-guided payload mutation (context-aware SSRF/BOLA/mass-assignment payloads from the
  observed schema and responses).
- LLM response triage for **false-positive suppression** (the tools currently rely on
  brittle substring lists, e.g. `ssrf_audit.py:561-573` indicator list).
- Business-logic inference in `business_flow_audit.py` (LLM proposes flow sequences
  from the OpenAPI spec instead of regex keyword matching, `business_flow_audit.py:83`).

### 3.5 Advanced WAF evasion — split from the audit path
Modern evasion (`curl_cffi_session.py`, `waf_bypass_tvpl.py`, `cloudflare_bypass.py`,
`stealth_advanced.py`) targets the VN crawlers. Inside the auditors, evasion is limited
to header randomization + delays (behavioral) inherited from the session, plus
`safe_consumption_audit.py`'s `RATE_LIMIT_BYPASS_HEADERS` (`:427`,
`X-Forwarded-For` etc.). No per-request TLS variation, no adaptive challenge handling
in the OWASP auditors themselves.

---

## 4. Detection capability vs. OWASP API Top 10 (2023)

Breadth mapping is complete:

| API risk | Tool | Depth assessment |
|---|---|---|
| API1 BOLA | `bola_audit.py` | ID-substitution + JSON-shape diffing. **Gap:** UUID/GUID enumeration strategy, systematic cross-tenant object matrices. |
| API2 Broken Auth | `broken_auth_audit.py` | JWT `alg:none`/`exp`/signature (`:256-269`); weak creds; TLS/cipher; **modern**: quantum-resistance (`:514`), HTTP/2 Rapid Reset CVE-2023-44487 (`:407`). **Gap:** JWT algorithm confusion (RS256→HS256 with public key as HMAC key), `kid` path-traversal/SQLi, `jku`/`x5u` header injection, JWKS spoofing, weak-secret brute force. |
| API3 BOPLA | `broken_object_property_audit.py` | Mass-assignment / excessive-exposure, `active_mode` gated. **Gap:** fully serial; limited write-property fuzzing. |
| API4 Resource Consumption | `resource_consumption_audit.py` | Deep-nested JSON (`:114`), batch sizes, size/time thresholds, `urllib3 Retry`. **Gap:** no HTTP/2 stream-flood, no GraphQL query-cost. |
| API5 BFLA | `authorization_audit.py` | Role matrix (anon/user/admin). **Gap:** serial; needs multi-token automation. |
| API6 Unrestricted Business Flows | `business_flow_audit.py` | Coupon reuse, price/qty tampering, sequential rate. **Gap:** regex-based flow detection; no true multi-step stateful race beyond coupon loop. |
| API7 SSRF | `ssrf_audit.py` | Cloud-metadata (AWS/GCP/Alibaba/Tencent), gopher/dict/ldap, DNS-rebind, blind-latency. **Gap:** no OAST/collaborator callback verification (payloads reference `burpcollaborator.net` at `:121` but there is no listener to confirm out-of-band hits — blind detection is latency-only). |
| API8 Misconfiguration | `misconfiguration_audit.py` | Largest coverage incl. GraphQL introspection probe (`:1188`), CORS, headers. |
| API9 Improper Inventory | `inventory_audit.py` | Path/version probing, `/graphql`, debug endpoints. |
| API10 Unsafe Consumption | `safe_consumption_audit.py` | Most modern: HTTP/2, GraphQL introspection query (`:625`), NoSQL, advanced SSRF, JWT, business-logic payloads. |

Cross-cutting detection gaps:
- **GraphQL** is only *introspection detection*. No dedicated auditor for batching/alias
  DoS, field-suggestion leakage, or depth/complexity abuse.
- **No gRPC, WebSocket, SSE, or GraphQL-subscription auditing** — modern API surfaces
  are unaddressed.
- **False-positive control is substring-based** and duplicated per tool (e.g.
  `ssrf_audit.py:561`, `resource_consumption_audit.py:68` `_FP_BODY_PATTERNS`). No
  shared, testable classifier.

---

## 5. Performance bottlenecks (concrete)

1. **Serial tools:** `broken_auth_audit.py`, `authorization_audit.py`,
   `broken_object_property_audit.py` run every request one-at-a-time. On large specs
   these dominate wall-clock time.
2. **Tiny thread pools:** `bola_audit.py` defaults to **2** workers
   (`bola_audit.py:176`); `business_flow_audit.py` to **4** (`:94`); `ssrf` caps at
   **10** (`ssrf_audit.py:177`). Even the parallel tools under-utilize an I/O-bound
   workload.
3. **Coverage sacrificed for speed:** SSRF caps params/payloads/encodings
   (`ssrf_audit.py:406-408`) purely to survive the slow sync transport.
4. **Serial per-endpoint baseline sampling:** `ssrf_audit.py:332-352`
   (`baseline_samples`) issues extra blocking round-trips before probing each endpoint.
5. **Monolith:** `safe_consumption_audit.py` is 4673 lines / 202 KB in one file — slow
   to import, hard to test, hard to parallelize incrementally.
6. **Duplicated hot helpers** (ANSI writers, header/body normalizers) instantiate
   per-tool rather than sharing a compiled/cached implementation.

---

## 6. Concrete improvement areas (prioritized)

**P0 — transport modernization**
- Introduce a shared `BaseAuditor` + async HTTP core (`httpx.AsyncClient`, HTTP/2 on)
  with a single `asyncio.Semaphore` governor and adaptive 429 backoff. Migrate serial
  tools (`broken_auth`, `authorization`, `broken_object_property`) first.
- Collapse the duplicated helpers (`_headers_to_list`, `_safe_body`, `_tw`,
  `_log_issue`) into that base and route them through `crawl_common.py`.

**P0 — stealth session contract**
- Define and unit-test the `requests.Session` API surface that
  `StealthSession(CurlCffiSession)` must satisfy, so auditors don't silently degrade.
  Bump `curl_cffi>=0.7` and refresh default impersonation profile off `chrome124`
  (`stealth_session.py:65`).

**P1 — detection depth**
- JWT: add algorithm confusion, `kid`/`jku`/`x5u` injection, JWKS spoofing, weak-secret
  brute force to `broken_auth_audit.py`.
- SSRF: add a real OAST/collaborator listener to confirm out-of-band callbacks
  (`ssrf_audit.py` currently ships collaborator payloads with no verification channel).
- Add a dedicated GraphQL auditor (batching/alias DoS, depth/complexity, field
  suggestion) and stubs for gRPC/WebSocket.

**P1 — intelligence**
- Wire `adaptive_learning_engine.py` into the scan loop or delete it.
- Add optional LLM response-triage for false-positive suppression and schema-aware
  payload mutation (SDKs already in `requirements.txt`).

**P2 — discovery & platform**
- Optional Playwright/camoufox discovery mode to harvest live XHR/fetch endpoints from
  SPAs and reach managed-challenge targets.
- Add a Turnstile/managed-challenge handler (today only reCAPTCHA exists, and only in
  dead code — see §7).

**P2 — hygiene**
- Pin dependencies (lockfile + hashes); raise minimum Python to 3.10+ and adopt
  `asyncio.TaskGroup`.
- Replace `datetime.utcnow()` with `datetime.now(timezone.utc)` suite-wide.
- Split `safe_consumption_audit.py` into a package.

---

## 7. `stealth_audit.py` — dead code, self-documented

`stealth_audit.py:1-19` states the module is **"ASPIRATIONAL / CURRENTLY UNUSED"** and
imported by nothing in the default scan path. Two hard limitations it declares:
1. `CapSolverHandler` solves only Google reCAPTCHA v2/v3
   (`stealth_audit.py:51,101`), but the Vietnamese-gov targets are fronted by
   **Cloudflare Turnstile / managed challenges**, which this cannot solve.
2. `AuditSession.get()` detects a reCAPTCHA sitekey and fetches a token but
   **never resubmits the form** (`stealth_audit.py:244-247`), so even the reCAPTCHA
   path is incomplete.

Recommendation: either delete it or replace it with a real Turnstile/managed-challenge
handler wired into the audit session. Do not present it as a working CAPTCHA bypass.
