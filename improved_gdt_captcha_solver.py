#!/usr/bin/env python3
########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                          #
#                                                       #
# improved_gdt_captcha_solver.py                        #
# Modernized page-level CAPTCHA workflow.               #
#                                                       #
# Async rewrite of gdt_captcha_solver.py:               #
#   detect + extract (reCAPTCHA v2/v3/Enterprise,       #
#       hCaptcha, Turnstile, image)                     #
#   Playwright browser harvest with stealth flags       #
#       (fingerprint + JS overrides from               #
#        enhanced_camoufox)                             #
#   fallback chain: vision/OCR -> browser -> commercial #
#       service -> fail gracefully                       #
#   token injection into the target form                #
#   async httpx + structlog + result caching            #
#                                                       #
# For authorized auditing / lawful access to public     #
# government forms only.                                 #
########################################################
"""Page-level async CAPTCHA workflow for VN government forms.

``gdt_captcha_solver.py`` (the legacy version) detects a CAPTCHA in a page's
HTML, extracts the sitekey and either OCRs an image challenge locally or returns
a placeholder "test token" for reCAPTCHA/hCaptcha. It has **no Turnstile
support** - the critical gap, because Vietnamese government portals increasingly
sit behind Cloudflare Turnstile rather than reCAPTCHA.

This module keeps the same detect -> extract -> solve -> inject shape but:

* adds **Turnstile** detection, browser harvesting and commercial solving;
* adds reCAPTCHA **Enterprise** detection;
* drives a **stealth Playwright** browser (fingerprint headers + navigator
  overrides from :mod:`enhanced_camoufox`) to harvest tokens for real, instead
  of returning fake placeholder tokens;
* runs a graceful **fallback chain** per CAPTCHA type:
    - image  : Claude Vision -> local OCR -> commercial ImageToText -> fail
    - token  : stealth browser harvest -> commercial service -> fail
* is fully async (httpx via :mod:`improved_common`) and reuses the commercial
  solving + caching from :mod:`improved_captcha_solver`.

Every heavy dependency (Playwright, enhanced_camoufox, OCR engines) is optional
and guarded; the module imports and runs with only the base stack installed.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from improved_common import get_logger, run_async
from improved_captcha_solver import (
    CaptchaConfig,
    CaptchaResult,
    CaptchaType,
    UnifiedAsyncCaptchaSolver,
)

# Optional stealth fingerprint source (enhanced_camoufox pulls in cloudflare_bypass
# + vn_egress_monitor at import; guard so this module still loads without them).
try:  # pragma: no cover - optional
    from enhanced_camoufox import EnhancedCamoufoxSession
    from cloudflare_bypass import BrowserProfile

    _HAVE_CAMOUFOX = True
except Exception:  # pragma: no cover
    EnhancedCamoufoxSession = None  # type: ignore
    BrowserProfile = None  # type: ignore
    _HAVE_CAMOUFOX = False


# Chromium launch flags that reduce automation fingerprints. Mirrors the intent
# of enhanced_camoufox (which spoofs headers/navigator) at the browser level.
_STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-infobars",
    "--disable-extensions",
    "--disable-features=IsolateOrigins,site-per-process",
    "--window-size=1920,1080",
]

# Fields the various widgets write their token into.
_TOKEN_FIELDS = {
    CaptchaType.RECAPTCHA_V2: "g-recaptcha-response",
    CaptchaType.RECAPTCHA_V3: "g-recaptcha-response",
    CaptchaType.RECAPTCHA_ENTERPRISE: "g-recaptcha-response",
    CaptchaType.HCAPTCHA: "h-captcha-response",
    CaptchaType.TURNSTILE: "cf-turnstile-response",
}


# --------------------------------------------------------------------------- #
# Detection + extraction
# --------------------------------------------------------------------------- #
@dataclass
class CaptchaChallenge:
    """A CAPTCHA found in a page, with everything needed to solve it."""

    captcha_type: CaptchaType
    sitekey: Optional[str] = None
    action: Optional[str] = None            # reCAPTCHA v3 / Turnstile action
    image_url: Optional[str] = None         # image CAPTCHA
    is_enterprise: bool = False
    is_invisible: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


class CaptchaDetector:
    """Detect the CAPTCHA type and extract its parameters from page HTML."""

    def __init__(self, logger: Any = None):
        self.log = logger or get_logger("apiscan.captcha.detect")

    def detect(self, html: str, page_url: str = "") -> Optional[CaptchaChallenge]:
        low = (html or "").lower()

        # --- Cloudflare Turnstile (check FIRST - the critical VN gov case) --- #
        if ("challenges.cloudflare.com/turnstile" in low
                or "cf-turnstile" in low
                or 'data-sitekey' in low and 'turnstile' in low):
            sitekey = self._extract_turnstile_sitekey(html)
            action = self._first_match(html, [r'data-action=["\']([^"\']+)["\']'])
            self.log.info("captcha_detected", type="turnstile", sitekey=(sitekey or "")[:20])
            return CaptchaChallenge(CaptchaType.TURNSTILE, sitekey=sitekey, action=action)

        # A bare Cloudflare interstitial ("Just a moment...") is a managed
        # challenge - still Turnstile under the hood, solved by rendering.
        if ("just a moment" in low and "cloudflare" in low) or "_cf_chl_opt" in low:
            self.log.info("captcha_detected", type="turnstile", note="cf managed interstitial")
            return CaptchaChallenge(CaptchaType.TURNSTILE, sitekey=self._extract_turnstile_sitekey(html))

        # --- reCAPTCHA (enterprise / v2 / v3) --- #
        if "recaptcha" in low:
            enterprise = "grecaptcha.enterprise" in low or "enterprise.js" in low
            sitekey = self._extract_recaptcha_sitekey(html)
            # An execute() call (either namespace) with no render() is v3-style:
            # the token is minted programmatically and carries an action.
            has_execute = re.search(r'grecaptcha\.(?:enterprise\.)?execute\(', html, re.IGNORECASE) is not None
            has_render = re.search(r'grecaptcha\.(?:enterprise\.)?render\(', html, re.IGNORECASE) is not None
            if (has_execute or "/recaptcha/api.js?render=" in low) and not has_render:
                action = self._first_match(html, [
                    r'grecaptcha\.(?:enterprise\.)?execute\([^,]+,\s*\{\s*action\s*:\s*["\']([^"\']+)["\']',
                    r'action["\']?\s*:\s*["\']([^"\']+)["\']',
                ])
                ctype = CaptchaType.RECAPTCHA_ENTERPRISE if enterprise else CaptchaType.RECAPTCHA_V3
                self.log.info("captcha_detected", type=ctype.value, sitekey=(sitekey or "")[:20])
                return CaptchaChallenge(ctype, sitekey=sitekey, action=action, is_enterprise=enterprise)
            invisible = "data-size=\"invisible\"" in low or "'invisible'" in low
            ctype = CaptchaType.RECAPTCHA_ENTERPRISE if enterprise else CaptchaType.RECAPTCHA_V2
            self.log.info("captcha_detected", type=ctype.value, sitekey=(sitekey or "")[:20])
            return CaptchaChallenge(ctype, sitekey=sitekey, is_enterprise=enterprise, is_invisible=invisible)

        # --- hCaptcha --- #
        if "hcaptcha" in low:
            sitekey = self._first_match(html, [r'data-sitekey=["\']([^"\']+)["\']'])
            self.log.info("captcha_detected", type="hcaptcha", sitekey=(sitekey or "")[:20])
            return CaptchaChallenge(CaptchaType.HCAPTCHA, sitekey=sitekey)

        # --- image CAPTCHA --- #
        img = self._extract_image_url(html, page_url)
        if img:
            self.log.info("captcha_detected", type="image", url=img[:60])
            return CaptchaChallenge(CaptchaType.IMAGE, image_url=img)

        return None

    # -- extractors ---------------------------------------------------------- #
    @staticmethod
    def _first_match(html: str, patterns: List[str]) -> Optional[str]:
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _extract_turnstile_sitekey(self, html: str) -> Optional[str]:
        return self._first_match(html, [
            r'class=["\'][^"\']*cf-turnstile[^"\']*["\'][^>]*data-sitekey=["\']([^"\']+)["\']',
            r'data-sitekey=["\']([^"\']+)["\'][^>]*class=["\'][^"\']*cf-turnstile',
            r'turnstile\.render\([^,]+,\s*\{[^}]*sitekey["\']?\s*:\s*["\']([^"\']+)["\']',
            r'data-sitekey=["\'](0x[^"\']+)["\']',  # Turnstile keys start with 0x
        ])

    def _extract_recaptcha_sitekey(self, html: str) -> Optional[str]:
        return self._first_match(html, [
            r'data-sitekey=["\']([^"\']+)["\']',
            r'grecaptcha\.(?:enterprise\.)?render\([^,]+,\s*\{[^}]*sitekey["\']?\s*:\s*["\']([^"\']+)["\']',
            r'grecaptcha\.(?:enterprise\.)?execute\(["\']([^"\']+)["\']',
            r'sitekey["\']?\s*:\s*["\']([^"\']+)["\']',
            r'/recaptcha/api\.js\?render=([^"\'&]+)',
        ])

    def _extract_image_url(self, html: str, page_url: str) -> Optional[str]:
        m = re.search(
            r'<img[^>]+(?:id|class|src)=["\'][^"\']*captcha[^"\']*["\'][^>]*>',
            html, re.IGNORECASE,
        )
        if not m:
            if "captcha_image" not in html.lower() and "verifycaptcha" not in html.lower():
                return None
            m2 = re.search(r'src=["\']([^"\']*captcha[^"\']*)["\']', html, re.IGNORECASE)
            if not m2:
                return None
            src = m2.group(1)
        else:
            src_m = re.search(r'src=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
            if not src_m:
                return None
            src = src_m.group(1)

        if src.startswith(("http://", "https://")):
            return src
        if page_url:
            from urllib.parse import urljoin

            return urljoin(page_url, src)
        return src


# --------------------------------------------------------------------------- #
# Stealth browser harvester (Playwright)
# --------------------------------------------------------------------------- #
class BrowserCaptchaHarvester:
    """Render a page in a stealth headless browser and harvest the token.

    This is the honest "use a real browser" path: for managed Turnstile and
    reCAPTCHA v3 the widget issues a token on its own once the page runs in a
    genuine browser context; we read it out of the hidden field. Interactive v2
    checkbox challenges usually need a real solve and will fall through to the
    commercial service - that is expected, not a bug.
    """

    def __init__(self, config: CaptchaConfig, *, headless: bool = True, logger: Any = None):
        self.config = config
        self.headless = headless
        self.log = logger or get_logger("apiscan.captcha.browser")
        self._pw = None
        self._browser = None
        self.available = False
        # Stealth fingerprint (headers + navigator overrides) if available.
        self._fp = None
        if _HAVE_CAMOUFOX:
            try:
                self._fp = EnhancedCamoufoxSession(BrowserProfile.CHROME_LATEST, auto_detect_vn=False)
            except Exception as e:  # pragma: no cover
                self.log.info("camoufox_unavailable", error=str(e))

    async def start(self) -> bool:
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception:
            self.log.info("playwright_unavailable")
            self.available = False
            return False
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=self.headless, args=_STEALTH_ARGS)
            self.available = True
            return True
        except Exception as e:  # pragma: no cover
            self.log.warning("playwright_launch_failed", error=str(e))
            self.available = False
            return False

    async def _new_context(self):
        kwargs: Dict[str, Any] = {
            "ignore_https_errors": True,
            "viewport": {"width": 1920, "height": 1080},
            "locale": "vi-VN",
        }
        headers: Dict[str, str] = {}
        if self._fp is not None:
            try:
                headers = self._fp.get_headers()
                kwargs["user_agent"] = headers.get("User-Agent")
                kwargs["timezone_id"] = self._fp.fingerprint.get("timezone", "Asia/Ho_Chi_Minh")
            except Exception:
                pass
        ctx = await self._browser.new_context(**{k: v for k, v in kwargs.items() if v is not None})
        # Extra HTTP headers (drop UA - set via context) + navigator overrides.
        if headers:
            hdr = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
            try:
                await ctx.set_extra_http_headers(hdr)
            except Exception:
                pass
        if self._fp is not None:
            try:
                await ctx.add_init_script(self._fp.get_javascript_overrides())
            except Exception:
                pass
        else:
            # Minimal webdriver hide even without camoufox.
            await ctx.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
            )
        return ctx

    async def harvest(self, challenge: CaptchaChallenge, page_url: str) -> CaptchaResult:
        """Render ``page_url`` and read the token for ``challenge`` type."""
        started = time.perf_counter()
        if not self.available or self._browser is None:
            return CaptchaResult(False, challenge.captcha_type.value, service="browser", error="browser unavailable")

        field = _TOKEN_FIELDS.get(challenge.captcha_type)
        if not field:
            return CaptchaResult(False, challenge.captcha_type.value, service="browser", error="type not token-based")

        ctx = None
        try:
            ctx = await self._new_context()
            page = await ctx.new_page()
            await page.goto(page_url, wait_until="domcontentloaded", timeout=int(self.config.timeout * 1000))

            # reCAPTCHA v3 (and v3-style Enterprise): actively execute to mint a
            # token rather than waiting for a user gesture.
            v3_style = challenge.captcha_type == CaptchaType.RECAPTCHA_V3 or (
                challenge.captcha_type == CaptchaType.RECAPTCHA_ENTERPRISE and challenge.action
            )
            if v3_style and challenge.sitekey:
                token = await self._execute_recaptcha_v3(page, challenge)
                if token:
                    return CaptchaResult(
                        True, challenge.captcha_type.value, solution=token, service="browser",
                        elapsed=time.perf_counter() - started,
                    )

            token = await self._poll_field(page, field)
            if token:
                self.log.info("captcha_browser_harvested", type=challenge.captcha_type.value)
                return CaptchaResult(
                    True, challenge.captcha_type.value, solution=token, service="browser",
                    elapsed=time.perf_counter() - started,
                )
            return CaptchaResult(
                False, challenge.captcha_type.value, service="browser",
                error="token not issued in browser (challenge likely interactive)",
                elapsed=time.perf_counter() - started,
            )
        except Exception as e:
            return CaptchaResult(False, challenge.captcha_type.value, service="browser", error=str(e))
        finally:
            if ctx is not None:
                try:
                    await ctx.close()
                except Exception:
                    pass

    async def _poll_field(self, page: Any, field: str) -> Optional[str]:
        """Poll a hidden token field until it has a value or we time out."""
        deadline = time.monotonic() + self.config.poll_timeout
        selector = f'[name="{field}"]'
        while time.monotonic() < deadline:
            try:
                val = await page.eval_on_selector(selector, "el => el && el.value")
            except Exception:
                val = None
            if val:
                return val
            await page.wait_for_timeout(int(self.config.poll_interval * 1000))
        return None

    async def _execute_recaptcha_v3(self, page: Any, challenge: CaptchaChallenge) -> Optional[str]:
        action = challenge.action or "verify"
        ns = "grecaptcha.enterprise" if challenge.is_enterprise else "grecaptcha"
        js = f"""
        () => new Promise((resolve) => {{
            try {{
                {ns}.ready(() => {{
                    {ns}.execute("{challenge.sitekey}", {{action: "{action}"}})
                        .then(t => resolve(t)).catch(() => resolve(null));
                }});
            }} catch (e) {{ resolve(null); }}
        }})
        """
        try:
            return await page.evaluate(js)
        except Exception:
            return None

    async def close(self) -> None:
        try:
            if self._browser is not None:
                await self._browser.close()
            if self._pw is not None:
                await self._pw.stop()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Local image OCR (reused / async-wrapped from the legacy solver)
# --------------------------------------------------------------------------- #
class LocalImageOCR:
    """Local OCR chain: amazoncaptcha -> EasyOCR -> Tesseract.

    Preprocessing mirrors the legacy ``gdt_captcha_solver`` (upscale, contrast,
    sharpen, threshold). All engines are optional; each missing one is skipped.
    Blocking OCR runs in a worker thread so it never stalls the event loop.
    """

    def __init__(self, logger: Any = None):
        self.log = logger or get_logger("apiscan.captcha.ocr")

    async def solve(self, image_bytes: bytes) -> Optional[str]:
        return await asyncio.to_thread(self._solve_sync, image_bytes)

    def _solve_sync(self, image_bytes: bytes) -> Optional[str]:
        for method in (self._amazoncaptcha, self._easyocr, self._tesseract):
            try:
                sol = method(image_bytes)
            except Exception as e:  # pragma: no cover
                self.log.info("ocr_method_error", method=method.__name__, error=str(e))
                sol = None
            if sol and len(sol) >= 3:
                self.log.info("captcha_ocr_solved", method=method.__name__, chars=len(sol))
                return sol
        return None

    def _amazoncaptcha(self, image_bytes: bytes) -> Optional[str]:
        from amazoncaptcha import AmazonCaptcha  # type: ignore
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(image_bytes)
            tmp = f.name
        try:
            sol = AmazonCaptcha(tmp).solve()
            return sol if sol and sol != "Not solved" else None
        finally:
            Path(tmp).unlink(missing_ok=True)

    def _preprocess(self, image_bytes: bytes, grayscale: bool):
        from io import BytesIO
        from PIL import Image, ImageEnhance, ImageFilter  # type: ignore

        img = Image.open(BytesIO(image_bytes))
        if img.mode == "RGBA":
            img = img.convert("RGB")
        if img.size[0] < 200:
            img = img.resize((img.size[0] * 3, img.size[1] * 3), Image.Resampling.LANCZOS)
        if grayscale:
            img = img.convert("L")
        img = ImageEnhance.Contrast(img).enhance(3 if grayscale else 2)
        img = ImageEnhance.Brightness(img).enhance(1.2)
        img = img.filter(ImageFilter.SHARPEN)
        return img

    def _easyocr(self, image_bytes: bytes) -> Optional[str]:
        import easyocr  # type: ignore

        reader = easyocr.Reader(["en"], gpu=False)
        img = self._preprocess(image_bytes, grayscale=False)
        results = reader.readtext(img, detail=0)
        if results:
            text = "".join(results).strip().replace(" ", "")
            return text or None
        return None

    def _tesseract(self, image_bytes: bytes) -> Optional[str]:
        import pytesseract  # type: ignore
        from PIL import ImageFilter  # type: ignore

        img = self._preprocess(image_bytes, grayscale=True)
        img = img.point(lambda x: 0 if x < 150 else 255, "1")
        img = img.filter(ImageFilter.MedianFilter(size=3))
        cfg = "--psm 8 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        text = pytesseract.image_to_string(img, config=cfg).strip().replace(" ", "").replace("\n", "")
        return text or None


# --------------------------------------------------------------------------- #
# Main async workflow
# --------------------------------------------------------------------------- #
class AsyncGDTCaptchaSolver:
    """Detect -> solve (fallback chain) -> inject, for VN government forms."""

    def __init__(
        self,
        config: Optional[CaptchaConfig] = None,
        *,
        session_headers: Optional[Dict[str, str]] = None,
        use_browser: bool = True,
        browser_headless: bool = True,
        logger: Any = None,
    ):
        self.config = config or CaptchaConfig()
        self.log = logger or get_logger("apiscan.captcha.gdt")
        self.detector = CaptchaDetector(logger=self.log)
        self.solver = UnifiedAsyncCaptchaSolver(self.config, logger=self.log)
        self.ocr = LocalImageOCR(logger=self.log)
        self.use_browser = use_browser
        self._harvester = BrowserCaptchaHarvester(self.config, headless=browser_headless, logger=self.log) if use_browser else None
        self._browser_started = False
        self._session_headers = session_headers or {}

    # -- fetch helper -------------------------------------------------------- #
    async def _fetch_image(self, url: str) -> Optional[bytes]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.config.timeout, follow_redirects=True) as c:
                r = await c.get(url, headers=self._session_headers)
                if r.status_code == 200 and r.content:
                    return r.content
        except Exception as e:
            self.log.warning("captcha_image_fetch_failed", url=url[:60], error=str(e))
        return None

    async def _ensure_browser(self) -> bool:
        if self._harvester is None:
            return False
        if not self._browser_started:
            self._browser_started = await self._harvester.start()
        return self._harvester.available

    # -- solve one challenge with the fallback chain ------------------------- #
    async def solve_challenge(self, challenge: CaptchaChallenge, page_url: str) -> CaptchaResult:
        ctype = challenge.captcha_type

        # ----- image CAPTCHA: vision -> local OCR -> commercial ------------- #
        if ctype == CaptchaType.IMAGE:
            if not challenge.image_url:
                return CaptchaResult(False, ctype.value, error="no image URL")
            img = await self._fetch_image(challenge.image_url)
            if not img:
                return CaptchaResult(False, ctype.value, error="image fetch failed")

            # vision + commercial are both handled by solve_image (vision first);
            # slot local OCR in between by trying OCR before the paid fallback.
            if self.solver.vision.enabled:
                v = await self.solver.vision.solve_image(img)
                if v.success:
                    return v
            ocr = await self.ocr.solve(img)
            if ocr:
                return CaptchaResult(True, ctype.value, solution=ocr, service="local-ocr")
            return await self.solver.solve_image(img)  # commercial ImageToText

        # ----- token CAPTCHAs: browser harvest -> commercial --------------- #
        if not challenge.sitekey and ctype != CaptchaType.TURNSTILE:
            return CaptchaResult(False, ctype.value, error="no sitekey extracted")

        # 1) stealth browser harvest (free; best for managed Turnstile / v3)
        if self.use_browser and await self._ensure_browser():
            harvested = await self._harvester.harvest(challenge, page_url)
            if harvested.success:
                return harvested
            self.log.info("captcha_browser_fallthrough", type=ctype.value, reason=harvested.error)

        # 2) commercial service
        if not challenge.sitekey:
            return CaptchaResult(False, ctype.value, error="browser harvest failed and no sitekey for API fallback")

        if ctype == CaptchaType.TURNSTILE:
            return await self.solver.solve_turnstile(page_url, challenge.sitekey, action=challenge.action)
        if ctype == CaptchaType.RECAPTCHA_V3:
            return await self.solver.solve_recaptcha_v3(page_url, challenge.sitekey, action=challenge.action or "verify")
        if ctype in (CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_ENTERPRISE):
            return await self.solver.solve_recaptcha_v2(
                page_url, challenge.sitekey,
                enterprise=(ctype == CaptchaType.RECAPTCHA_ENTERPRISE),
                is_invisible=challenge.is_invisible,
            )
        if ctype == CaptchaType.HCAPTCHA:
            return await self.solver.solve_hcaptcha(page_url, challenge.sitekey)
        return CaptchaResult(False, ctype.value, error="unsupported type")

    # -- top-level: from raw HTML ------------------------------------------- #
    async def solve_from_html(self, html: str, page_url: str) -> Optional[Dict[str, Any]]:
        challenge = self.detector.detect(html, page_url)
        if challenge is None:
            self.log.info("captcha_none_detected")
            return None
        result = await self.solve_challenge(challenge, page_url)
        field = _TOKEN_FIELDS.get(challenge.captcha_type, "captcha")
        return {
            "type": challenge.captcha_type.value,
            "sitekey": challenge.sitekey,
            "field_name": field,
            "token": result.solution,
            "success": result.success,
            "service": result.service,
            "elapsed": round(result.elapsed, 2),
            "from_cache": result.from_cache,
            "error": result.error,
        }

    # -- token injection ----------------------------------------------------- #
    @staticmethod
    def inject_token(html: str, token: str, captcha_type: CaptchaType) -> str:
        field = _TOKEN_FIELDS.get(captcha_type, "g-recaptcha-response")
        # Replace an existing response textarea/input, else append a hidden input.
        pat = re.compile(
            rf'<(?:textarea|input)[^>]*name=["\']{re.escape(field)}["\'][^>]*>(?:</textarea>)?',
            re.IGNORECASE,
        )
        replacement = f'<input type="hidden" name="{field}" value="{token}">'
        if pat.search(html):
            return pat.sub(replacement, html)
        return html + replacement

    # -- lifecycle ----------------------------------------------------------- #
    async def aclose(self) -> None:
        if self._harvester is not None:
            await self._harvester.close()
        await self.solver.aclose()

    async def __aenter__(self) -> "AsyncGDTCaptchaSolver":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # -- sync compatibility shim (mirrors legacy get_captcha_solution) ------- #
    def get_captcha_solution(self, html: str, page_url: str, method: str = "auto") -> Optional[Dict[str, Any]]:
        """Synchronous wrapper for legacy call sites (``method`` is ignored;
        the async chain always runs vision/OCR/browser/commercial as available)."""
        async def _run() -> Optional[Dict[str, Any]]:
            try:
                return await self.solve_from_html(html, page_url)
            finally:
                await self.aclose()

        return run_async(_run())


__all__ = [
    "CaptchaChallenge",
    "CaptchaDetector",
    "BrowserCaptchaHarvester",
    "LocalImageOCR",
    "AsyncGDTCaptchaSolver",
]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _main() -> int:
    import argparse
    import json

    p = argparse.ArgumentParser(description="APISCAN page-level CAPTCHA workflow (VN gov forms)")
    p.add_argument("--url", default="https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp", help="Page URL to fetch + solve")
    p.add_argument("--html-file", help="Solve from a local HTML file instead of fetching")
    p.add_argument("--no-browser", action="store_true", help="Disable Playwright harvesting")
    p.add_argument("--headful", action="store_true", help="Run the browser non-headless")
    args = p.parse_args()

    async def _run() -> int:
        if args.html_file:
            from pathlib import Path
            html = Path(args.html_file).read_text(encoding="utf-8", errors="replace")
        else:
            async with httpx.AsyncClient(verify=False, timeout=20, follow_redirects=True) as c:
                r = await c.get(args.url)
                html = r.text
        async with AsyncGDTCaptchaSolver(
            use_browser=not args.no_browser, browser_headless=not args.headful,
        ) as solver:
            result = await solver.solve_from_html(html, args.url)
        if result is None:
            print("No CAPTCHA detected.")
            return 0
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("success") else 1

    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(_main())
