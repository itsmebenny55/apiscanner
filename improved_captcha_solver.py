#!/usr/bin/env python3
########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                          #
#                                                       #
# improved_captcha_solver.py                            #
# Modernized async CAPTCHA solver.                      #
#                                                       #
# Async rewrite of captcha_solver.py:                   #
#   httpx.AsyncClient + asyncio  (was requests, sync)   #
#   Cloudflare Turnstile support (was missing)          #
#   reCAPTCHA v2 / v3 / Enterprise + hCaptcha           #
#   Commercial fallback chain: CapSolver / 2Captcha /   #
#       Anti-Captcha (unified createTask/getTaskResult) #
#   Claude Vision image-CAPTCHA recognition             #
#   TTL result cache (avoid re-solving identical work)  #
#   Exponential-backoff retry + structured logging      #
#                                                       #
# For authorized security auditing and lawful access to #
# public data only. Every heavy dependency is imported  #
# lazily and degrades gracefully.                       #
########################################################
"""Async multi-service CAPTCHA solver for APISCAN.

This is the modern replacement for :mod:`captcha_solver` (the synchronous
``UnifiedCaptchaSolver`` built on ``requests``). It keeps the same idea - one
facade over several commercial solving services with automatic fallback - but:

* is fully ``asyncio`` / ``httpx`` based (reuses :class:`AsyncHTTPClient`);
* adds **Cloudflare Turnstile** solving (the critical gap: many VN government
  sites sit behind Cloudflare, not reCAPTCHA);
* adds **reCAPTCHA Enterprise** and unifies v2/v3/hCaptcha across all providers
  through the modern ``createTask`` / ``getTaskResult`` JSON API that CapSolver,
  2Captcha and Anti-Captcha now share;
* adds a **Claude Vision** solver for simple image/text CAPTCHAs;
* caches results with a short TTL (tokens are single-use / short-lived, image
  answers are keyed by image hash);
* retries with exponential backoff and logs through ``improved_common``.

The higher-level page workflow (detect type, extract sitekey, drive a real
browser to harvest a token, inject it into a form) lives in
:mod:`improved_gdt_captcha_solver`, which composes this module for the
commercial-fallback leg of its chain.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from improved_common import AsyncHTTPClient, ScanConfig, get_logger

# Optional: Anthropic client for vision-based image CAPTCHA transcription.
try:  # pragma: no cover - optional
    from anthropic import AsyncAnthropic  # type: ignore

    _HAVE_ANTHROPIC = True
except Exception:  # pragma: no cover
    AsyncAnthropic = None  # type: ignore
    _HAVE_ANTHROPIC = False


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class CaptchaType(str, Enum):
    """CAPTCHA challenge families this solver understands."""

    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    RECAPTCHA_ENTERPRISE = "recaptcha_enterprise"
    HCAPTCHA = "hcaptcha"
    TURNSTILE = "turnstile"
    IMAGE = "image"


class CaptchaService(str, Enum):
    """Supported commercial solving services."""

    CAPSOLVER = "capsolver"
    TWOCAPTCHA = "2captcha"
    ANTICAPTCHA = "anticaptcha"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
class CaptchaConfig(BaseModel):
    """Validated configuration for the async solver.

    API keys default to the documented environment variables so nothing secret
    is ever hard-coded:  ``CAPSOLVER_API_KEY``, ``TWOCAPTCHA_API_KEY`` /
    ``2CAPTCHA_API_KEY``, ``ANTICAPTCHA_API_KEY``.
    """

    # transport / pacing
    timeout: float = Field(default=20.0, gt=0)
    poll_interval: float = Field(default=3.0, gt=0, description="Seconds between task-result polls.")
    poll_timeout: float = Field(default=180.0, gt=0, description="Max seconds to wait for a solution.")
    retries: int = Field(default=2, ge=0, le=10)
    retry_backoff: float = Field(default=1.0, ge=0, description="Base seconds for exponential backoff.")
    retry_backoff_max: float = Field(default=30.0, gt=0)

    # service selection
    primary: CaptchaService = Field(default=CaptchaService.CAPSOLVER)
    capsolver_key: Optional[str] = Field(default_factory=lambda: os.getenv("CAPSOLVER_API_KEY"))
    twocaptcha_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("TWOCAPTCHA_API_KEY") or os.getenv("2CAPTCHA_API_KEY")
    )
    anticaptcha_key: Optional[str] = Field(default_factory=lambda: os.getenv("ANTICAPTCHA_API_KEY"))

    # reCAPTCHA v3
    v3_min_score: float = Field(default=0.7, ge=0.0, le=1.0)

    # vision (Claude) image CAPTCHA
    use_vision: bool = Field(default=True, description="Try Claude Vision for image CAPTCHAs.")
    vision_model: str = Field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"))

    # caching
    cache_enabled: bool = Field(default=True)
    cache_ttl: float = Field(default=110.0, gt=0, description="Token cache TTL (s); tokens are short-lived.")
    image_cache_ttl: float = Field(default=3600.0, gt=0, description="Image-answer cache TTL (s).")

    model_config = {"extra": "ignore"}


# --------------------------------------------------------------------------- #
# Result object
# --------------------------------------------------------------------------- #
@dataclass
class CaptchaResult:
    """Uniform result across every solver leg and CAPTCHA type."""

    success: bool
    captcha_type: Optional[str] = None
    # A token (reCAPTCHA/hCaptcha/Turnstile) or plain text (image CAPTCHA).
    solution: Optional[str] = None
    service: Optional[str] = None          # capsolver | 2captcha | anticaptcha | claude-vision | cache
    elapsed: float = 0.0
    attempts: int = 0
    from_cache: bool = False
    error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def token(self) -> Optional[str]:
        """Alias - solvers that return web tokens read ``.token``."""
        return self.solution


# --------------------------------------------------------------------------- #
# TTL cache
# --------------------------------------------------------------------------- #
class _TTLCache:
    """Tiny in-memory TTL cache. Not shared across processes.

    CAPTCHA tokens are single-use and expire quickly, so caching is best-effort
    and deliberately short-lived; its main value is deduping bursts of identical
    solve requests (e.g. retries of one scan step) and reusing image-CAPTCHA
    answers keyed by the image bytes.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, CaptchaResult]] = {}

    def get(self, key: str) -> Optional[CaptchaResult]:
        item = self._store.get(key)
        if not item:
            return None
        expires, result = item
        if time.monotonic() >= expires:
            self._store.pop(key, None)
            return None
        return result

    def put(self, key: str, result: CaptchaResult, ttl: float) -> None:
        self._store[key] = (time.monotonic() + ttl, result)

    def clear(self) -> None:
        self._store.clear()


def _backoff_delay(attempt: int, base: float, cap: float) -> float:
    """Exponential backoff (attempt is 0-based)."""
    return min(cap, base * (2 ** attempt))


# --------------------------------------------------------------------------- #
# Commercial service adapter (unified createTask / getTaskResult)
# --------------------------------------------------------------------------- #
# CapSolver, 2Captcha and Anti-Captcha all expose a modern JSON API with the
# same request/response envelope. Only the base URL and the per-type task names
# differ, so one adapter drives all three via a small descriptor table.
_SERVICE_SPECS: Dict[CaptchaService, Dict[str, Any]] = {
    CaptchaService.CAPSOLVER: {
        "base_url": "https://api.capsolver.com",
        "task_types": {
            CaptchaType.RECAPTCHA_V2: "ReCaptchaV2TaskProxyLess",
            CaptchaType.RECAPTCHA_V3: "ReCaptchaV3TaskProxyLess",
            CaptchaType.RECAPTCHA_ENTERPRISE: "ReCaptchaV2EnterpriseTaskProxyLess",
            CaptchaType.HCAPTCHA: "HCaptchaTaskProxyLess",
            CaptchaType.TURNSTILE: "AntiTurnstileTaskProxyLess",
            CaptchaType.IMAGE: "ImageToTextTask",
        },
    },
    CaptchaService.TWOCAPTCHA: {
        "base_url": "https://api.2captcha.com",
        "task_types": {
            CaptchaType.RECAPTCHA_V2: "RecaptchaV2TaskProxyless",
            CaptchaType.RECAPTCHA_V3: "RecaptchaV3TaskProxyless",
            CaptchaType.RECAPTCHA_ENTERPRISE: "RecaptchaV2EnterpriseTaskProxyless",
            CaptchaType.HCAPTCHA: "HCaptchaTaskProxyless",
            CaptchaType.TURNSTILE: "TurnstileTaskProxyless",
            CaptchaType.IMAGE: "ImageToTextTask",
        },
    },
    CaptchaService.ANTICAPTCHA: {
        "base_url": "https://api.anti-captcha.com",
        "task_types": {
            CaptchaType.RECAPTCHA_V2: "RecaptchaV2TaskProxyless",
            CaptchaType.RECAPTCHA_V3: "RecaptchaV3TaskProxyless",
            CaptchaType.RECAPTCHA_ENTERPRISE: "RecaptchaV2EnterpriseTaskProxyless",
            CaptchaType.HCAPTCHA: "HCaptchaTaskProxyless",
            CaptchaType.TURNSTILE: "TurnstileTaskProxyless",
            CaptchaType.IMAGE: "ImageToTextTask",
        },
    },
}

# Solution payloads use different key names per provider / type; try each.
_SOLUTION_KEYS = ("gRecaptchaResponse", "token", "text")


class AsyncServiceSolver:
    """One commercial solving service, driven asynchronously.

    Uses :class:`AsyncHTTPClient` from ``improved_common`` for HTTP (shared
    retry/pacing plumbing) and implements the ``createTask`` -> poll
    ``getTaskResult`` loop with exponential backoff.
    """

    def __init__(self, service: CaptchaService, api_key: str, config: CaptchaConfig, http: AsyncHTTPClient, logger: Any = None):
        self.service = service
        self.api_key = api_key
        self.config = config
        self.http = http
        self.log = logger or get_logger(f"apiscan.captcha.{service.value}")
        spec = _SERVICE_SPECS[service]
        self.base_url = spec["base_url"]
        self.task_types = spec["task_types"]

    # -- task construction --------------------------------------------------- #
    def _build_task(self, captcha_type: CaptchaType, **kw: Any) -> Optional[Dict[str, Any]]:
        ttype = self.task_types.get(captcha_type)
        if not ttype:
            return None
        task: Dict[str, Any] = {"type": ttype}

        if captcha_type in (CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_ENTERPRISE):
            task["websiteURL"] = kw["website_url"]
            task["websiteKey"] = kw["sitekey"]
            if kw.get("enterprise_payload"):
                task["enterprisePayload"] = kw["enterprise_payload"]
            if kw.get("is_invisible"):
                task["isInvisible"] = True
        elif captcha_type == CaptchaType.RECAPTCHA_V3:
            task["websiteURL"] = kw["website_url"]
            task["websiteKey"] = kw["sitekey"]
            task["pageAction"] = kw.get("action", "verify")
            task["minScore"] = kw.get("min_score", self.config.v3_min_score)
        elif captcha_type == CaptchaType.HCAPTCHA:
            task["websiteURL"] = kw["website_url"]
            task["websiteKey"] = kw["sitekey"]
        elif captcha_type == CaptchaType.TURNSTILE:
            task["websiteURL"] = kw["website_url"]
            task["websiteKey"] = kw["sitekey"]
            # Cloudflare "action" / "cData" / "chlPageData" when the widget sets them.
            if kw.get("action"):
                task["action"] = kw["action"]
            if kw.get("cdata"):
                task["cdata"] = kw["cdata"]
            if kw.get("chl_page_data"):
                task["chlPageData"] = kw["chl_page_data"]
        elif captcha_type == CaptchaType.IMAGE:
            task["body"] = kw["image_b64"]
            if kw.get("case_sensitive") is not None:
                task["case"] = bool(kw["case_sensitive"])
            if kw.get("numeric") is not None:
                task["numeric"] = int(kw["numeric"])
        else:
            return None
        return task

    @staticmethod
    def _extract_solution(solution: Dict[str, Any]) -> Optional[str]:
        for key in _SOLUTION_KEYS:
            val = solution.get(key)
            if val:
                return val
        return None

    # -- create + poll ------------------------------------------------------- #
    async def solve(self, captcha_type: CaptchaType, **kw: Any) -> CaptchaResult:
        started = time.perf_counter()
        task = self._build_task(captcha_type, **kw)
        if task is None:
            return CaptchaResult(
                success=False, captcha_type=captcha_type.value, service=self.service.value,
                error=f"{self.service.value} does not support {captcha_type.value}",
            )

        create_payload = {"clientKey": self.api_key, "task": task}
        resp = await self.http.request("POST", f"{self.base_url}/createTask", json_body=create_payload)
        if not resp.ok:
            return CaptchaResult(False, captcha_type.value, service=self.service.value, error=f"createTask transport: {resp.error}")

        try:
            data = _loads(resp.text)
        except Exception as e:
            return CaptchaResult(False, captcha_type.value, service=self.service.value, error=f"createTask parse: {e}")

        if data.get("errorId"):
            err = data.get("errorDescription") or data.get("errorCode") or "unknown createTask error"
            self.log.warning("captcha_create_error", service=self.service.value, error=err)
            return CaptchaResult(False, captcha_type.value, service=self.service.value, error=str(err))

        task_id = data.get("taskId")
        if not task_id:
            return CaptchaResult(False, captcha_type.value, service=self.service.value, error="no taskId returned")

        self.log.info("captcha_task_created", service=self.service.value, type=captcha_type.value, task_id=task_id)

        deadline = time.monotonic() + self.config.poll_timeout
        result_payload = {"clientKey": self.api_key, "taskId": task_id}
        while time.monotonic() < deadline:
            await asyncio.sleep(self.config.poll_interval)
            r = await self.http.request("POST", f"{self.base_url}/getTaskResult", json_body=result_payload)
            if not r.ok:
                continue
            try:
                rd = _loads(r.text)
            except Exception:
                continue
            if rd.get("errorId"):
                err = rd.get("errorDescription") or rd.get("errorCode") or "unknown getTaskResult error"
                return CaptchaResult(False, captcha_type.value, service=self.service.value, error=str(err))
            if rd.get("status") == "ready":
                token = self._extract_solution(rd.get("solution") or {})
                if not token:
                    return CaptchaResult(False, captcha_type.value, service=self.service.value, error="ready but no solution field")
                self.log.info("captcha_solved", service=self.service.value, type=captcha_type.value)
                return CaptchaResult(
                    success=True, captcha_type=captcha_type.value, solution=token,
                    service=self.service.value, elapsed=time.perf_counter() - started,
                    extra={"task_id": task_id},
                )
            # status == "processing" -> keep polling
        return CaptchaResult(False, captcha_type.value, service=self.service.value, error="poll timeout")


# --------------------------------------------------------------------------- #
# Claude Vision image-CAPTCHA solver
# --------------------------------------------------------------------------- #
class VisionCaptchaSolver:
    """Transcribe simple image/text CAPTCHAs with Claude Vision.

    Intended for straightforward alphanumeric image challenges (the kind several
    VN government forms use) and for the operator's own custom challenges - not
    as a way to defeat interactive/behavioural CAPTCHAs. For protected
    third-party token CAPTCHAs (reCAPTCHA/hCaptcha/Turnstile), use a real
    browser (see improved_gdt_captcha_solver) or a commercial service. Disabled
    automatically when the ``anthropic`` package or ``ANTHROPIC_API_KEY`` is
    absent.
    """

    _PROMPT = (
        "This image is a text CAPTCHA from a form the operator is authorized to "
        "submit. Reply with ONLY the exact characters shown, no spaces, no "
        "explanation. If you cannot read them confidently, reply exactly: UNKNOWN"
    )

    def __init__(self, config: CaptchaConfig, logger: Any = None):
        self.config = config
        self.log = logger or get_logger("apiscan.captcha.vision")
        self._client = None
        api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("LLM_API_KEY")
        self.enabled = bool(config.use_vision and _HAVE_ANTHROPIC and api_key)
        if self.enabled:
            try:
                self._client = AsyncAnthropic(api_key=api_key)
            except Exception as e:  # pragma: no cover
                self.log.warning("vision_init_failed", error=str(e))
                self.enabled = False

    async def solve_image(self, image_bytes: bytes, media_type: str = "image/png") -> CaptchaResult:
        started = time.perf_counter()
        if not self.enabled or self._client is None:
            return CaptchaResult(False, CaptchaType.IMAGE.value, service="claude-vision", error="vision disabled")
        b64 = base64.b64encode(image_bytes).decode()
        try:
            msg = await self._client.messages.create(
                model=self.config.vision_model,
                max_tokens=64,
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
                        {"type": "text", "text": self._PROMPT},
                    ],
                }],
            )
            text = "".join(
                getattr(b, "text", "") for b in msg.content if getattr(b, "type", None) == "text"
            ).strip()
            if not text or text.upper() == "UNKNOWN":
                return CaptchaResult(False, CaptchaType.IMAGE.value, service="claude-vision", error="vision could not read")
            # Keep only the transcription (models occasionally add stray whitespace).
            text = text.split()[0] if text.split() else text
            self.log.info("captcha_vision_solved", chars=len(text))
            return CaptchaResult(
                True, CaptchaType.IMAGE.value, solution=text, service="claude-vision",
                elapsed=time.perf_counter() - started,
            )
        except Exception as e:
            self.log.warning("vision_solve_failed", error=str(e))
            return CaptchaResult(False, CaptchaType.IMAGE.value, service="claude-vision", error=str(e))


# --------------------------------------------------------------------------- #
# Unified async solver (facade with fallback chain + cache)
# --------------------------------------------------------------------------- #
class UnifiedAsyncCaptchaSolver:
    """Async facade: one call, tried across every configured service in order.

    Fallback order is ``primary`` first, then the remaining commercial services.
    Image CAPTCHAs additionally try Claude Vision first (free / local-ish) before
    paying a commercial service. Results are cached briefly to avoid re-solving
    identical work within a token's lifetime.
    """

    def __init__(self, config: Optional[CaptchaConfig] = None, logger: Any = None):
        self.config = config or CaptchaConfig()
        self.log = logger or get_logger("apiscan.captcha")
        # Internal httpx client tuned for solver APIs (big bodies, own retries).
        scan_cfg = ScanConfig(
            timeout=self.config.timeout,
            retries=self.config.retries,
            retry_backoff=self.config.retry_backoff,
            verify_tls=True,
            http2=True,
            cache_responses=False,          # never cache poll responses
            response_body_limit=65536,      # tokens can be a couple of KB
        )
        self.http = AsyncHTTPClient(scan_cfg, logger=self.log)
        self._cache = _TTLCache() if self.config.cache_enabled else None
        self.vision = VisionCaptchaSolver(self.config, logger=self.log)

        # Instantiate one adapter per service that has a key.
        self._services: Dict[CaptchaService, AsyncServiceSolver] = {}
        keys = {
            CaptchaService.CAPSOLVER: self.config.capsolver_key,
            CaptchaService.TWOCAPTCHA: self.config.twocaptcha_key,
            CaptchaService.ANTICAPTCHA: self.config.anticaptcha_key,
        }
        for svc, key in keys.items():
            if key:
                self._services[svc] = AsyncServiceSolver(svc, key, self.config, self.http, logger=self.log)

        if not self._services:
            self.log.warning("captcha_no_services", note="no CAPSOLVER/2CAPTCHA/ANTICAPTCHA key configured")
        self.log.info(
            "captcha_solver_ready",
            services=[s.value for s in self._services],
            vision=self.vision.enabled,
            primary=self.config.primary.value,
        )

    # -- ordering ------------------------------------------------------------ #
    def _service_order(self) -> List[AsyncServiceSolver]:
        order: List[AsyncServiceSolver] = []
        if self.config.primary in self._services:
            order.append(self._services[self.config.primary])
        for svc, solver in self._services.items():
            if svc != self.config.primary:
                order.append(solver)
        return order

    # -- cache helpers ------------------------------------------------------- #
    def _cache_get(self, key: str) -> Optional[CaptchaResult]:
        if self._cache is None:
            return None
        hit = self._cache.get(key)
        if hit is not None:
            self.log.info("captcha_cache_hit", key=key[:48])
            cached = CaptchaResult(**{**hit.__dict__})
            cached.from_cache = True
            return cached
        return None

    def _cache_put(self, key: str, result: CaptchaResult, ttl: float) -> None:
        if self._cache is not None and result.success:
            self._cache.put(key, result, ttl)

    # -- generic token solve across services -------------------------------- #
    async def _solve_token(self, captcha_type: CaptchaType, cache_key: str, **kw: Any) -> CaptchaResult:
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        errors: List[str] = []
        attempts = 0
        for solver in self._service_order():
            # per-service retry with exponential backoff
            for attempt in range(self.config.retries + 1):
                attempts += 1
                result = await solver.solve(captcha_type, **kw)
                result.attempts = attempts
                if result.success:
                    self._cache_put(cache_key, result, self.config.cache_ttl)
                    return result
                errors.append(f"{solver.service.value}: {result.error}")
                if attempt < self.config.retries:
                    await asyncio.sleep(_backoff_delay(attempt, self.config.retry_backoff, self.config.retry_backoff_max))
        return CaptchaResult(
            success=False, captcha_type=captcha_type.value, attempts=attempts,
            error="; ".join(errors) or "no solving service available",
        )

    # -- public API ---------------------------------------------------------- #
    async def solve_turnstile(
        self, website_url: str, sitekey: str, *, action: Optional[str] = None,
        cdata: Optional[str] = None, chl_page_data: Optional[str] = None,
    ) -> CaptchaResult:
        """Solve a Cloudflare Turnstile challenge (critical for VN gov sites)."""
        ck = f"turnstile:{sitekey}:{website_url}:{action}"
        return await self._solve_token(
            CaptchaType.TURNSTILE, ck, website_url=website_url, sitekey=sitekey,
            action=action, cdata=cdata, chl_page_data=chl_page_data,
        )

    async def solve_recaptcha_v2(
        self, website_url: str, sitekey: str, *, enterprise: bool = False,
        is_invisible: bool = False, enterprise_payload: Optional[Dict[str, Any]] = None,
    ) -> CaptchaResult:
        ctype = CaptchaType.RECAPTCHA_ENTERPRISE if enterprise else CaptchaType.RECAPTCHA_V2
        ck = f"{ctype.value}:{sitekey}:{website_url}"
        return await self._solve_token(
            ctype, ck, website_url=website_url, sitekey=sitekey,
            is_invisible=is_invisible, enterprise_payload=enterprise_payload,
        )

    async def solve_recaptcha_v3(
        self, website_url: str, sitekey: str, *, action: str = "verify",
        min_score: Optional[float] = None,
    ) -> CaptchaResult:
        ck = f"recaptcha_v3:{sitekey}:{website_url}:{action}"
        return await self._solve_token(
            CaptchaType.RECAPTCHA_V3, ck, website_url=website_url, sitekey=sitekey,
            action=action, min_score=min_score if min_score is not None else self.config.v3_min_score,
        )

    async def solve_hcaptcha(self, website_url: str, sitekey: str) -> CaptchaResult:
        ck = f"hcaptcha:{sitekey}:{website_url}"
        return await self._solve_token(CaptchaType.HCAPTCHA, ck, website_url=website_url, sitekey=sitekey)

    async def solve_image(
        self, image_bytes: bytes, *, media_type: str = "image/png",
        case_sensitive: Optional[bool] = None, numeric: Optional[int] = None,
    ) -> CaptchaResult:
        """Solve an image/text CAPTCHA: Claude Vision first, then commercial services."""
        digest = hashlib.sha256(image_bytes).hexdigest()
        ck = f"image:{digest}"
        cached = self._cache_get(ck)
        if cached is not None:
            return cached

        errors: List[str] = []
        attempts = 0

        # 1) Vision (cheap / no third-party account needed)
        if self.vision.enabled:
            attempts += 1
            v = await self.vision.solve_image(image_bytes, media_type=media_type)
            v.attempts = attempts
            if v.success:
                self._cache_put(ck, v, self.config.image_cache_ttl)
                return v
            errors.append(f"claude-vision: {v.error}")

        # 2) Commercial ImageToText fallback
        image_b64 = base64.b64encode(image_bytes).decode()
        for solver in self._service_order():
            for attempt in range(self.config.retries + 1):
                attempts += 1
                r = await solver.solve(
                    CaptchaType.IMAGE, image_b64=image_b64,
                    case_sensitive=case_sensitive, numeric=numeric,
                )
                r.attempts = attempts
                if r.success:
                    self._cache_put(ck, r, self.config.image_cache_ttl)
                    return r
                errors.append(f"{solver.service.value}: {r.error}")
                if attempt < self.config.retries:
                    await asyncio.sleep(_backoff_delay(attempt, self.config.retry_backoff, self.config.retry_backoff_max))

        return CaptchaResult(
            success=False, captcha_type=CaptchaType.IMAGE.value, attempts=attempts,
            error="; ".join(errors) or "no image solver available",
        )

    # -- introspection / lifecycle ------------------------------------------ #
    def get_status(self) -> Dict[str, Any]:
        return {
            "services": [s.value for s in self._services],
            "primary": self.config.primary.value,
            "vision_enabled": self.vision.enabled,
            "cache_enabled": self._cache is not None,
            "any_service": bool(self._services) or self.vision.enabled,
        }

    async def aclose(self) -> None:
        await self.http.aclose()

    async def __aenter__(self) -> "UnifiedAsyncCaptchaSolver":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


def _loads(text: str) -> Dict[str, Any]:
    import json

    return json.loads(text or "{}")


def create_solver(config: Optional[CaptchaConfig] = None, **kwargs: Any) -> UnifiedAsyncCaptchaSolver:
    """Build a :class:`UnifiedAsyncCaptchaSolver`.

    ``create_solver(primary=CaptchaService.TWOCAPTCHA, twocaptcha_key="...")``
    still works: bare kwargs are folded into a :class:`CaptchaConfig`.
    """
    if config is None:
        config = CaptchaConfig(**kwargs) if kwargs else CaptchaConfig()
    return UnifiedAsyncCaptchaSolver(config)


__all__ = [
    "CaptchaType",
    "CaptchaService",
    "CaptchaConfig",
    "CaptchaResult",
    "AsyncServiceSolver",
    "VisionCaptchaSolver",
    "UnifiedAsyncCaptchaSolver",
    "create_solver",
]


# --------------------------------------------------------------------------- #
# CLI (diagnostics + one-off solves)
# --------------------------------------------------------------------------- #
def _main() -> int:
    import argparse
    import json as _json

    p = argparse.ArgumentParser(description="APISCAN async CAPTCHA solver")
    p.add_argument("--type", choices=[t.value for t in CaptchaType], help="CAPTCHA type to solve")
    p.add_argument("--url", help="Page URL hosting the CAPTCHA")
    p.add_argument("--sitekey", help="Widget sitekey")
    p.add_argument("--action", default="verify", help="reCAPTCHA v3 / Turnstile action")
    p.add_argument("--image", help="Path to an image CAPTCHA to solve")
    p.add_argument("--status", action="store_true", help="Print solver capability status and exit")
    args = p.parse_args()

    async def _run() -> int:
        async with create_solver() as solver:
            if args.status or not args.type:
                print(_json.dumps(solver.get_status(), indent=2))
                return 0
            ct = CaptchaType(args.type)
            if ct == CaptchaType.IMAGE:
                if not args.image:
                    print("--image required for image type")
                    return 2
                from pathlib import Path
                res = await solver.solve_image(Path(args.image).read_bytes())
            elif ct == CaptchaType.TURNSTILE:
                res = await solver.solve_turnstile(args.url, args.sitekey, action=args.action)
            elif ct == CaptchaType.RECAPTCHA_V3:
                res = await solver.solve_recaptcha_v3(args.url, args.sitekey, action=args.action)
            elif ct == CaptchaType.RECAPTCHA_ENTERPRISE:
                res = await solver.solve_recaptcha_v2(args.url, args.sitekey, enterprise=True)
            elif ct == CaptchaType.HCAPTCHA:
                res = await solver.solve_hcaptcha(args.url, args.sitekey)
            else:
                res = await solver.solve_recaptcha_v2(args.url, args.sitekey)
            print(_json.dumps(res.__dict__, indent=2, default=str))
            return 0 if res.success else 1

    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(_main())
