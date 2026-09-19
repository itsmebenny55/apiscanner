# APISCAN Async CAPTCHA Solver Guide

This guide documents the modernized CAPTCHA tooling that replaces the two legacy
solvers. It follows the same design as the async audit stack (see
`modernization_guide.md`): a shared `httpx` + `asyncio` foundation
(`improved_common.py`), structured logging, graceful optional dependencies, and
drop-in sync shims for legacy call sites.

| Legacy tool             | Modernized tool                     | Role |
|-------------------------|-------------------------------------|------|
| `captcha_solver.py`     | `improved_captcha_solver.py`        | Multi-service async solving core (Turnstile / reCAPTCHA / hCaptcha / image) |
| `gdt_captcha_solver.py` | `improved_gdt_captcha_solver.py`    | Page-level workflow: detect → harvest/solve → inject, for VN gov forms |

> **Scope / intended use.** APISCAN is an authorized-testing tool. These solvers
> exist to let the operator complete CAPTCHA-gated forms on targets they are
> permitted to test and to reach **public** government data (procurement, legal
> gazette, tax lookup) for transparency and research. Respect each site's terms
> and applicable law, keep the rate limits low, and route procurement traffic
> through the correct VN egress lane. The tooling never fabricates tokens: a
> failed solve returns `success=False`, not a fake value (the legacy
> "placeholder test token" behaviour is gone).

---

## 1. Why this rewrite (the eight priorities)

### 1. Playwright browser flow for Turnstile + reCAPTCHA v2/v3/Enterprise
`BrowserCaptchaHarvester` (in `improved_gdt_captcha_solver.py`) launches stealth
headless Chromium and **harvests a real token** by rendering the page:

- **Turnstile** (managed mode) and **reCAPTCHA v3** typically mint a token
  automatically once the page runs in a genuine browser context; the harvester
  reads it out of the hidden field (`cf-turnstile-response` /
  `g-recaptcha-response`). For v3/Enterprise it actively calls
  `grecaptcha.execute(sitekey, {action})` to mint the token.
- **reCAPTCHA v2 checkbox** usually needs an interactive solve; the browser leg
  falls through and the commercial service takes over (by design, not a bug).

`pyppeteer` is listed as an alternative driver in `requirements.txt`; Playwright
is the primary/default.

### 2. Cloudflare Turnstile support (the critical gap)
Turnstile was **entirely missing** from the legacy solvers, yet it is the
dominant challenge on Cloudflare-fronted VN government sites. It is now a
first-class type across the whole stack: detection, browser harvesting, and
commercial solving (`AntiTurnstileTaskProxyLess` on CapSolver,
`TurnstileTaskProxyless` on 2Captcha and Anti-Captcha). Turnstile is checked
**first** during detection, including the bare "Just a moment…" managed
interstitial.

### 3. Commercial fallback: CapSolver / 2Captcha / Anti-Captcha
`AsyncServiceSolver` drives all three through the one modern
`createTask` → poll `getTaskResult` JSON envelope they now share. A single
descriptor table (`_SERVICE_SPECS`) maps each CAPTCHA type to each provider's
task-type string, so adding a provider is a table entry, not a new class.

### 4. Claude Vision for image CAPTCHAs
`VisionCaptchaSolver` transcribes simple alphanumeric image challenges with
Claude Vision (reuses `ANTHROPIC_API_KEY` and the `anthropic` async client).
Intended for straightforward text-in-image CAPTCHAs (as several VN forms use)
and the operator's own custom challenges — not for defeating interactive or
behavioural CAPTCHAs, which go through a real browser or a commercial service.
Disabled automatically when the package or key is absent.

### 5. Async architecture with httpx
Both modules are `asyncio`-native and reuse `AsyncHTTPClient` from
`improved_common.py` for all HTTP (shared pacing/retry plumbing). Polling loops
are non-blocking (`asyncio.sleep`); blocking local OCR runs in a worker thread
(`asyncio.to_thread`) so it never stalls the event loop. Both expose async
context managers and `aclose()`.

### 6. Logging / result streaming (improved_common patterns)
Every component logs through `get_logger()` — `structlog` with an ISO timestamp
when installed, else a stdlib shim with the identical `log.info("event", k=v)`
keyword API. Third-party transport loggers stay quiet. Results are a single
uniform `CaptchaResult` dataclass (`success`, `solution`/`token`, `service`,
`elapsed`, `attempts`, `from_cache`, `error`).

### 7. WebSocket / real-time challenge handling
Real-time challenges are handled by driving the live page in the browser (the
Playwright context keeps the widget's WebSocket/session to
`challenges.cloudflare.com` alive until the token is issued). For lower-level
WebSocket probing, `improved_common.WebSocketProbe` is available and shares the
same config surface.

### 8. Smart retry with exponential backoff
`_backoff_delay(attempt, base, cap)` gives `base·2ⁿ` capped at
`retry_backoff_max` (e.g. 1, 2, 4, 8, 16, 30 s). Each service is retried up to
`retries` times before the chain falls to the next service; the accumulated
per-service errors are returned on total failure.

---

## 2. Fallback chains

The chain is **type-aware** (cheap/free legs first, paid last, graceful fail):

```
Image CAPTCHA:   Claude Vision  →  local OCR (amazoncaptcha→EasyOCR→Tesseract)
                                →  commercial ImageToText  →  fail

Token CAPTCHA:   stealth browser harvest  →  commercial service  →  fail
(Turnstile /     (managed Turnstile & v3 usually succeed here;
 reCAPTCHA /       v2 checkbox / hCaptcha typically need the paid leg)
 hCaptcha)
```

Every leg is optional. With no browser and no API keys, token solving reports a
clear failure; image solving still tries Vision/OCR if those are installed.

---

## 3. Usage

### Solve a specific token CAPTCHA (async, library)

```python
import asyncio
from improved_captcha_solver import create_solver, CaptchaConfig, CaptchaService

async def main():
    cfg = CaptchaConfig(primary=CaptchaService.CAPSOLVER, v3_min_score=0.7)
    async with create_solver(cfg) as solver:
        r = await solver.solve_turnstile(
            "https://portal.example.gov.vn/login", "0x4AAAAAAA...")
        if r.success:
            print("token:", r.token, "via", r.service, f"{r.elapsed:.1f}s")

asyncio.run(main())
```

### Page workflow: detect → solve → inject (async)

```python
import asyncio, httpx
from improved_gdt_captcha_solver import AsyncGDTCaptchaSolver
from improved_captcha_solver import CaptchaType

async def main():
    async with httpx.AsyncClient(verify=False) as c:
        html = (await c.get("https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp")).text
    async with AsyncGDTCaptchaSolver(use_browser=True) as solver:
        sol = await solver.solve_from_html(html, "https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp")
        if sol and sol["success"]:
            html = solver.inject_token(html, sol["token"], CaptchaType(sol["type"]))

asyncio.run(main())
```

### Sync shim (drop-in for the legacy `get_captcha_solution`)

```python
from improved_gdt_captcha_solver import AsyncGDTCaptchaSolver
sol = AsyncGDTCaptchaSolver().get_captcha_solution(html, page_url)  # runs the async chain
```

### CLI

```bash
# Capability / status
python improved_captcha_solver.py --status

# Solve one challenge
python improved_captcha_solver.py --type turnstile --url https://site.gov.vn --sitekey 0x4AA...
python improved_captcha_solver.py --type image --image captcha.png

# Full page workflow (fetch, detect, solve)
python improved_gdt_captcha_solver.py --url https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp
python improved_gdt_captcha_solver.py --html-file saved_form.html --no-browser
```

---

## 4. Supported CAPTCHA types

| Type | Detected via | Browser harvest | Commercial task |
|------|--------------|-----------------|-----------------|
| Cloudflare **Turnstile** | `cf-turnstile`, `challenges.cloudflare.com/turnstile`, `_cf_chl_opt`, "Just a moment…" | ✅ managed mode | `AntiTurnstileTaskProxyLess` / `TurnstileTaskProxyless` |
| **reCAPTCHA v2** | `g-recaptcha` + `data-sitekey`, `render(` | ⚠️ interactive → API | `ReCaptchaV2TaskProxyLess` / `RecaptchaV2TaskProxyless` |
| **reCAPTCHA v3** | `execute(` / `api.js?render=` | ✅ via `execute()` | `ReCaptchaV3TaskProxyLess` / `RecaptchaV3TaskProxyless` |
| **reCAPTCHA Enterprise** | `grecaptcha.enterprise`, `enterprise.js` | ✅ if `execute()` action | `…EnterpriseTask…` |
| **hCaptcha** | `hcaptcha` + `data-sitekey` | ⚠️ interactive → API | `HCaptchaTaskProxyLess` / `HCaptchaTaskProxyless` |
| **Image / text** | `<img …captcha…>`, `captcha_image`, `verifycaptcha` | n/a | Vision / local OCR / `ImageToTextTask` |

---

## 5. Configuration (`CaptchaConfig`)

Validated with pydantic; construct directly or via `create_solver(**kwargs)`.

| Field | Default | Purpose |
|---|---|---|
| `primary` | `capsolver` | Service tried first; others are fallbacks |
| `capsolver_key` / `twocaptcha_key` / `anticaptcha_key` | env | API keys (see below) |
| `timeout` | 20.0 | Per-request timeout (s) |
| `poll_interval` / `poll_timeout` | 3.0 / 180.0 | Task-result poll cadence / ceiling (s) |
| `retries` / `retry_backoff` / `retry_backoff_max` | 2 / 1.0 / 30.0 | Exponential-backoff retry policy |
| `v3_min_score` | 0.7 | reCAPTCHA v3 minimum score |
| `use_vision` / `vision_model` | True / `claude-sonnet-4-5` | Claude Vision image solving |
| `cache_enabled` / `cache_ttl` / `image_cache_ttl` | True / 110 / 3600 | TTL result cache (s) |

### API keys (environment)

```bash
export CAPSOLVER_API_KEY=cap-...
export TWOCAPTCHA_API_KEY=...        # or 2CAPTCHA_API_KEY
export ANTICAPTCHA_API_KEY=...
export ANTHROPIC_API_KEY=sk-ant-...  # enables Claude Vision image solving
```

Any single service is sufficient; all are optional. Keys are read from the
environment / `.env` — never hard-coded.

---

## 6. Result caching

Solved results are cached in-process with a TTL (`_TTLCache`):

- **Tokens are single-use and short-lived.** The token cache TTL defaults to
  110 s, so its real value is deduping bursts of identical solve requests (e.g.
  a retried scan step) within a token's validity window — not long-term reuse.
  Do not reuse a consumed token; request a fresh solve for each submission.
- **Image answers** are keyed by the SHA-256 of the image bytes and cached
  longer (default 1 h): an identical image reliably has the same answer.

Only successful results are cached; a cache hit sets `from_cache=True`.

---

## 7. Performance (rough, environment-dependent)

These are ballpark figures for planning, not guarantees — real numbers depend on
the target, the chosen provider, network path (VN egress adds latency), and
account balance/queue. Measure with `CaptchaResult.elapsed` on your own runs.

| Path | Typical solve time | Notes |
|------|--------------------|-------|
| Browser harvest (managed Turnstile / v3) | ~2–8 s | Free; no third-party account |
| Commercial Turnstile | ~5–20 s | Depends on provider queue |
| Commercial reCAPTCHA v2 | ~15–45 s | Human-in-the-loop providers are slower |
| Claude Vision (image) | ~1–4 s | Simple alphanumeric images only |
| Local OCR (image) | ~0.3–3 s | Accuracy varies wildly by image quality |

Success rates are **not** advertised here because they swing with the specific
challenge configuration and provider; the fallback chain exists precisely so one
leg's miss is covered by the next. Track your own success/`error` counts from
the streamed `CaptchaResult`s.

---

## 8. Error handling

- Every solver returns a `CaptchaResult`; check `.success` before using
  `.token`/`.solution`. On failure, `.error` carries the concatenated
  per-service reasons.
- Optional deps degrade silently: no Playwright → browser leg skipped; no OCR
  engines → those skipped; no API keys → commercial leg skipped; no
  `anthropic`/key → Vision skipped. `solver.get_status()` reports what is live.
- Transport errors and provider `errorId`s are caught and logged, never raised
  to the caller; the chain advances to the next leg.
- Interactive v2/hCaptcha with no API key configured is the common
  "unsolvable" case — the result says so explicitly rather than returning a fake
  token.

---

## 9. Install

```bash
pip install -r requirements.txt
# Browser harvesting (one-time, downloads Chromium):
python -m playwright install chromium
# Local OCR (optional): Tesseract binary for pytesseract
brew install tesseract          # macOS
# Verify what's active:
python improved_captcha_solver.py --status
```

Minimum to solve token CAPTCHAs via a commercial service: `httpx` + one API key.
Minimum to harvest managed Turnstile/v3 for free: `playwright` (+ `chromium`).
