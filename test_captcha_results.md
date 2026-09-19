# CAPTCHA Solver Test Results

Date: 2026-09-19
Scope: `improved_captcha_solver.py`, `improved_gdt_captcha_solver.py`
Environment: Python 3.14.7 (darwin), pydantic 2.13.5, httpx 0.28.1, anthropic present, **playwright NOT installed** (degradation path exercised for real)

## Summary

| File | Syntax | Import | Async patterns | Unit tests |
|------|--------|--------|----------------|------------|
| `improved_captcha_solver.py` | PASS | PASS | 12 `async def`, 21 `await` | 27 tests, all PASS |
| `improved_gdt_captcha_solver.py` | PASS | PASS | 16 `async def`, 38 `await` | 21 tests, all PASS |
| **Total** | | | | **48 tests, 48 passed, 0 failed** |

New test files created:
- `test_improved_captcha_solver.py`
- `test_improved_gdt_captcha_solver.py`

## 1. Syntax validation

```
python3 -m py_compile improved_captcha_solver.py       -> OK
python3 -m py_compile improved_gdt_captcha_solver.py   -> OK
```

## 2. Import validation

```
python3 -c "import improved_captcha_solver; ..."       -> OK
python3 -c "import improved_gdt_captcha_solver; ..."   -> OK
```
Both modules import cleanly with only the base stack (pydantic + httpx + anthropic)
present. Every heavy/optional dependency (Playwright, enhanced_camoufox,
amazoncaptcha/easyocr/pytesseract, PIL) is lazily imported behind try/except and its
absence does not break import.

## 3. Async patterns

Both modules are genuinely async (asyncio + httpx), not sync code wrapped in async
signatures:
- `improved_captcha_solver.py`: async `AsyncServiceSolver.solve` (createTask ->
  poll getTaskResult with `asyncio.sleep` backoff), async `VisionCaptchaSolver.solve_image`,
  async `UnifiedAsyncCaptchaSolver` facade with `__aenter__/__aexit__/aclose`.
- `improved_gdt_captcha_solver.py`: async `BrowserCaptchaHarvester` (Playwright
  async API), `LocalImageOCR.solve` runs blocking OCR via `asyncio.to_thread`,
  async `AsyncGDTCaptchaSolver` workflow with async context management and a
  synchronous `get_captcha_solution` shim over `run_async`.

## 4. Test execution

Command (per brief):
```
python3 -m pytest test_improved_captcha*.py -v
```
Note: the glob `test_improved_captcha*.py` matches only the first file; the GDT tests
are named `test_improved_gdt_captcha_solver.py`. Run both explicitly:
```
python3 -m pytest test_improved_captcha_solver.py test_improved_gdt_captcha_solver.py -v
```

Result: **48 passed in ~0.4s** (fully offline; no network, no browser).

Tests were run in an isolated venv because the system Python is PEP-668
externally-managed and has no `pytest`. To reproduce:
```
python3 -m venv /tmp/captcha-testvenv
/tmp/captcha-testvenv/bin/pip install pytest pytest-asyncio pydantic httpx anthropic
cd "/Volumes/My Shared Files/Projects/apiscanner"
/tmp/captcha-testvenv/bin/python -m pytest \
    test_improved_captcha_solver.py test_improved_gdt_captcha_solver.py -v
```
The project's `pyproject.toml` already registers the pytest config; no extra
`--asyncio-mode` flag is needed (pytest-asyncio defaults to strict mode and every
async test carries an explicit `@pytest.mark.asyncio` marker, compatible with the
project's `--strict-markers`).

### Coverage by focus area

**Turnstile detection (key focus) — VERIFIED**
- `cf-turnstile` widget class + `data-sitekey` extraction (keys starting `0x`).
- `challenges.cloudflare.com/turnstile` script tag.
- Cloudflare managed interstitial ("Just a moment..." / `_cf_chl_opt`).
- Turnstile is checked **before** reCAPTCHA in `CaptchaDetector.detect`, confirmed by
  a mixed-signal page resolving to Turnstile.
- Turnstile task built with the correct per-provider task name
  (`AntiTurnstileTaskProxyLess` for CapSolver vs `TurnstileTaskProxyless` for
  2Captcha) and carries `action`/`cdata`/`chlPageData`.

**Vision API integration (key focus) — VERIFIED correct**
- Prompt-based image transcription via `AsyncAnthropic.messages.create` with the
  correct message shape (base64 image block + text block, `max_tokens`, model from
  `ANTHROPIC_MODEL`).
- Degrades gracefully: disabled when `ANTHROPIC_API_KEY`/`LLM_API_KEY` is absent or
  when `use_vision=False`; `solve_image` returns a clean failure ("vision disabled")
  instead of raising.

**Browser automation graceful degradation (key focus) — VERIFIED**
- With Playwright genuinely not installed, `BrowserCaptchaHarvester.start()` returns
  `False` and sets `available=False` (no exception).
- `harvest()` on an unavailable harvester returns a failed `CaptchaResult`
  ("browser unavailable"); the GDT workflow then falls through to the commercial leg.

**Commercial API adapters (key focus) — VERIFIED correct**
- Unified `createTask`/`getTaskResult` envelope for CapSolver / 2Captcha /
  Anti-Captcha driven from one descriptor table.
- Task construction verified for Turnstile, reCAPTCHA v2 (+ invisible), v3 (action +
  minScore), Enterprise (+ enterprisePayload), hCaptcha, and image (body/numeric/case).
- Solution extraction tries `gRecaptchaResponse` / `token` / `text` in order.

**Fallback chains — VERIFIED**
- Commercial: primary service first, then remaining services; a failing primary
  (createTask errorId) falls through to the next service which succeeds.
- Image chain in `AsyncGDTCaptchaSolver`: Claude Vision -> local OCR -> commercial
  ImageToText, confirmed by mocked legs (OCR-hit path and OCR-miss->commercial path).
- Token chain: browser harvest -> commercial service (browser disabled -> commercial).

**Result caching — VERIFIED**
- Successful solve is cached; an identical second call returns `from_cache=True` with
  the same solution and issues **no** further HTTP calls.
- `_TTLCache` honours TTL expiry (evicts on read after expiry) and `clear()`.

**Error handling — VERIFIED**
- `createTask` `errorId` surfaces the provider `errorDescription`.
- Missing `taskId` returns a clean failure.
- Poll loop returns "poll timeout" when the task never reaches `status: ready`.
- No configured service -> failure result rather than an exception.
- pydantic config validation rejects out-of-range values (`v3_min_score`, `timeout`).

**Token injection — VERIFIED**
- Replaces an existing `g-recaptcha-response` textarea in place (no duplication).
- Appends a hidden `cf-turnstile-response` input when the field is absent.

## Graceful degradation confirmation

Confirmed the modules load and run useful subsets with missing optional deps:
- No Playwright: browser harvesting disabled, workflow continues to commercial/OCR.
- No `anthropic` key: Vision disabled, image chain continues to OCR/commercial.
- No OCR engines (amazoncaptcha/easyocr/pytesseract): `LocalImageOCR.solve` returns
  `None` (each engine skipped) with no crash.
- No commercial API keys: solver logs `captcha_no_services` and returns failure
  results rather than raising.

## Known limitations

- Tests are **offline by design**: the commercial `createTask`/`getTaskResult`
  round trip, the Playwright harvest, and the Anthropic Vision call are mocked or
  exercised only on their degradation paths. No live third-party solve was performed
  (no API keys, and doing so would incur cost / hit real services).
- Playwright is not installed in this environment, so the *success* path of
  `BrowserCaptchaHarvester` (real token harvest, `enhanced_camoufox` stealth
  fingerprint wiring, reCAPTCHA v3 `execute()` injection) is validated only by code
  review, not execution. Recommend an integration test with
  `playwright install chromium` before relying on the browser leg in production.
- Local OCR accuracy (amazoncaptcha/EasyOCR/Tesseract preprocessing) is not
  measured — only its graceful-skip behaviour when engines are missing.
- The system Python is PEP-668 managed; running the suite requires a venv or
  `--break-system-packages`. The project's canonical suite lives in `testing/`;
  these two files sit at the repo root next to the modules under test.

## Production readiness

Both modules are **structurally sound and safe to import/run**: clean syntax, clean
imports, correct async design, and robust graceful degradation across every optional
dependency. The commercial-adapter request/response shapes, Turnstile detection, the
Vision message shape, and the fallback/caching/error logic are all correct as
verified by 48 passing unit tests.

Before production use, complete the gaps above with **live/integration testing**:
(1) at least one real solve per commercial provider to confirm current task-type
names and error codes; (2) a Playwright-installed run to validate real token harvest
and stealth wiring; (3) an OCR-accuracy check against representative GDT/VN gov
captcha images. Until then, treat the browser-harvest and commercial-solve success
paths as verified-by-review, not verified-by-execution.
