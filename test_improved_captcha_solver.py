#!/usr/bin/env python3
"""Tests for improved_captcha_solver.py (async multi-service CAPTCHA solver).

Covers, per the audit brief:
  * UnifiedAsyncCaptchaSolver initialization (with/without keys, get_status)
  * Commercial service adapters: task construction for Turnstile / reCAPTCHA
    v2 / v3 / Enterprise / hCaptcha / image, and solution extraction
  * Fallback chains across services (create/poll mocked, no network)
  * Result caching (cache hit -> from_cache, no second network round trip)
  * Vision solver graceful degradation (no ANTHROPIC_API_KEY -> disabled)
  * Error handling (createTask errorId, missing taskId, poll timeout)
  * TTL cache behaviour and backoff maths

No network access is used: the HTTP transport is replaced with a fake that
returns canned createTask / getTaskResult envelopes.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

import improved_captcha_solver as mod
from improved_captcha_solver import (
    AsyncServiceSolver,
    CaptchaConfig,
    CaptchaResult,
    CaptchaService,
    CaptchaType,
    UnifiedAsyncCaptchaSolver,
    VisionCaptchaSolver,
    _backoff_delay,
    _TTLCache,
    create_solver,
)


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeResp:
    """Mimics improved_common.ProbeResponse's surface used by the solver."""

    def __init__(self, text: str = "", error: Optional[str] = None):
        self.text = text
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None


class FakeHTTP:
    """Fake AsyncHTTPClient: routes createTask/getTaskResult to canned JSON.

    ``create`` and ``result`` are JSON strings (or callables returning a
    FakeResp). Records every call for assertions.
    """

    def __init__(self, create: Any, result: Any):
        self._create = create
        self._result = result
        self.calls: List[str] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> FakeResp:
        self.calls.append(url)
        target = self._create if url.endswith("/createTask") else self._result
        if callable(target):
            return target(url, kwargs)
        return FakeResp(text=target)

    async def aclose(self) -> None:  # for UnifiedAsyncCaptchaSolver.aclose()
        pass


def _wire(solver: UnifiedAsyncCaptchaSolver, fake: FakeHTTP) -> None:
    """Point the unified solver and all its service adapters at the fake HTTP."""
    solver.http = fake
    for svc in solver._services.values():
        svc.http = fake


# --------------------------------------------------------------------------- #
# TTL cache + backoff
# --------------------------------------------------------------------------- #
def test_ttl_cache_hit_and_clear():
    c = _TTLCache()
    r = CaptchaResult(success=True, solution="tok")
    c.put("k", r, ttl=100)
    assert c.get("k") is r
    c.clear()
    assert c.get("k") is None


def test_ttl_cache_expiry(monkeypatch):
    c = _TTLCache()
    t = {"now": 1000.0}
    monkeypatch.setattr(mod.time, "monotonic", lambda: t["now"])
    c.put("k", CaptchaResult(success=True, solution="tok"), ttl=10)
    t["now"] = 1005.0
    assert c.get("k") is not None          # still inside TTL
    t["now"] = 1011.0
    assert c.get("k") is None              # expired and evicted


def test_backoff_delay_is_exponential_and_capped():
    assert _backoff_delay(0, base=1.0, cap=30.0) == 1.0
    assert _backoff_delay(1, base=1.0, cap=30.0) == 2.0
    assert _backoff_delay(2, base=1.0, cap=30.0) == 4.0
    assert _backoff_delay(10, base=1.0, cap=30.0) == 30.0   # capped


# --------------------------------------------------------------------------- #
# CaptchaResult
# --------------------------------------------------------------------------- #
def test_result_token_alias():
    r = CaptchaResult(success=True, solution="abc")
    assert r.token == "abc"
    assert CaptchaResult(success=False).token is None


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def test_config_reads_env_keys(monkeypatch):
    monkeypatch.setenv("CAPSOLVER_API_KEY", "cs-key")
    monkeypatch.setenv("2CAPTCHA_API_KEY", "2c-key")
    monkeypatch.delenv("TWOCAPTCHA_API_KEY", raising=False)
    monkeypatch.setenv("ANTICAPTCHA_API_KEY", "ac-key")
    cfg = CaptchaConfig()
    assert cfg.capsolver_key == "cs-key"
    assert cfg.twocaptcha_key == "2c-key"       # falls back to 2CAPTCHA_API_KEY
    assert cfg.anticaptcha_key == "ac-key"


def test_config_validation_rejects_bad_values():
    with pytest.raises(Exception):
        CaptchaConfig(v3_min_score=5.0)         # must be 0..1
    with pytest.raises(Exception):
        CaptchaConfig(timeout=0)                # gt=0


# --------------------------------------------------------------------------- #
# Service adapter: task construction (commercial API correctness)
# --------------------------------------------------------------------------- #
def _adapter(service=CaptchaService.CAPSOLVER) -> AsyncServiceSolver:
    cfg = CaptchaConfig()
    return AsyncServiceSolver(service, "key", cfg, http=FakeHTTP("{}", "{}"))


def test_build_task_turnstile():
    a = _adapter()
    task = a._build_task(
        CaptchaType.TURNSTILE, website_url="https://x.vn", sitekey="0xAAA",
        action="login", cdata="cd", chl_page_data="cp",
    )
    assert task["type"] == "AntiTurnstileTaskProxyLess"
    assert task["websiteURL"] == "https://x.vn"
    assert task["websiteKey"] == "0xAAA"
    assert task["action"] == "login"
    assert task["cdata"] == "cd"
    assert task["chlPageData"] == "cp"


def test_build_task_recaptcha_v2_invisible():
    a = _adapter()
    task = a._build_task(
        CaptchaType.RECAPTCHA_V2, website_url="https://x.vn", sitekey="6Lc",
        is_invisible=True,
    )
    assert task["type"] == "ReCaptchaV2TaskProxyLess"
    assert task["isInvisible"] is True


def test_build_task_recaptcha_v3_carries_action_and_score():
    a = _adapter()
    task = a._build_task(
        CaptchaType.RECAPTCHA_V3, website_url="https://x.vn", sitekey="6Lc",
        action="submit", min_score=0.9,
    )
    assert task["type"] == "ReCaptchaV3TaskProxyLess"
    assert task["pageAction"] == "submit"
    assert task["minScore"] == 0.9


def test_build_task_enterprise_payload():
    a = _adapter()
    task = a._build_task(
        CaptchaType.RECAPTCHA_ENTERPRISE, website_url="https://x.vn",
        sitekey="6Lc", enterprise_payload={"s": "tok"},
    )
    assert task["type"] == "ReCaptchaV2EnterpriseTaskProxyLess"
    assert task["enterprisePayload"] == {"s": "tok"}


def test_build_task_hcaptcha_and_image():
    a = _adapter()
    h = a._build_task(CaptchaType.HCAPTCHA, website_url="https://x.vn", sitekey="k")
    assert h["type"] == "HCaptchaTaskProxyLess"
    img = a._build_task(CaptchaType.IMAGE, image_b64="Zm9v", numeric=1, case_sensitive=True)
    assert img["type"] == "ImageToTextTask"
    assert img["body"] == "Zm9v"
    assert img["numeric"] == 1
    assert img["case"] is True


def test_task_type_names_differ_by_provider():
    # Turnstile task name differs: capsolver AntiTurnstile* vs 2captcha Turnstile*
    cs = _adapter(CaptchaService.CAPSOLVER)._build_task(
        CaptchaType.TURNSTILE, website_url="u", sitekey="k")
    tc = _adapter(CaptchaService.TWOCAPTCHA)._build_task(
        CaptchaType.TURNSTILE, website_url="u", sitekey="k")
    assert cs["type"] == "AntiTurnstileTaskProxyLess"
    assert tc["type"] == "TurnstileTaskProxyless"


def test_extract_solution_tries_multiple_keys():
    assert AsyncServiceSolver._extract_solution({"gRecaptchaResponse": "g"}) == "g"
    assert AsyncServiceSolver._extract_solution({"token": "t"}) == "t"
    assert AsyncServiceSolver._extract_solution({"text": "abc"}) == "abc"
    assert AsyncServiceSolver._extract_solution({"nope": "x"}) is None


# --------------------------------------------------------------------------- #
# Initialization / status
# --------------------------------------------------------------------------- #
def _no_keys(monkeypatch):
    for v in ("CAPSOLVER_API_KEY", "TWOCAPTCHA_API_KEY", "2CAPTCHA_API_KEY",
              "ANTICAPTCHA_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY"):
        monkeypatch.delenv(v, raising=False)


def test_init_no_services(monkeypatch):
    _no_keys(monkeypatch)
    solver = UnifiedAsyncCaptchaSolver(CaptchaConfig(use_vision=False))
    st = solver.get_status()
    assert st["services"] == []
    assert st["vision_enabled"] is False
    assert st["any_service"] is False


def test_init_with_keys_orders_primary_first(monkeypatch):
    _no_keys(monkeypatch)
    cfg = CaptchaConfig(
        capsolver_key="cs", twocaptcha_key="2c", anticaptcha_key="ac",
        primary=CaptchaService.TWOCAPTCHA, use_vision=False,
    )
    solver = UnifiedAsyncCaptchaSolver(cfg)
    order = [s.service for s in solver._service_order()]
    assert order[0] == CaptchaService.TWOCAPTCHA        # primary first
    assert set(order) == {CaptchaService.CAPSOLVER, CaptchaService.TWOCAPTCHA,
                          CaptchaService.ANTICAPTCHA}


def test_create_solver_folds_kwargs(monkeypatch):
    _no_keys(monkeypatch)
    solver = create_solver(capsolver_key="k", use_vision=False)
    assert CaptchaService.CAPSOLVER in solver._services


# --------------------------------------------------------------------------- #
# Vision graceful degradation
# --------------------------------------------------------------------------- #
def test_vision_disabled_without_api_key(monkeypatch):
    _no_keys(monkeypatch)
    v = VisionCaptchaSolver(CaptchaConfig(use_vision=True))
    assert v.enabled is False


def test_vision_disabled_when_use_vision_false(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    v = VisionCaptchaSolver(CaptchaConfig(use_vision=False))
    assert v.enabled is False


@pytest.mark.asyncio
async def test_vision_solve_returns_failure_when_disabled(monkeypatch):
    _no_keys(monkeypatch)
    v = VisionCaptchaSolver(CaptchaConfig(use_vision=True))
    res = await v.solve_image(b"\x89PNG fake")
    assert res.success is False
    assert res.service == "claude-vision"
    assert "disabled" in (res.error or "")


# --------------------------------------------------------------------------- #
# Fallback chains + caching + error handling (mocked transport)
# --------------------------------------------------------------------------- #
def _fast_solver(monkeypatch, fake: FakeHTTP, **cfg_kw) -> UnifiedAsyncCaptchaSolver:
    _no_keys(monkeypatch)
    params = dict(
        capsolver_key="cs", use_vision=False,
        poll_interval=0.001, poll_timeout=1.0, retries=0, retry_backoff=0.0,
    )
    params.update(cfg_kw)          # caller overrides win (e.g. poll_timeout)
    cfg = CaptchaConfig(**params)
    solver = UnifiedAsyncCaptchaSolver(cfg)
    _wire(solver, fake)
    return solver


@pytest.mark.asyncio
async def test_turnstile_solve_success(monkeypatch):
    fake = FakeHTTP(
        create='{"errorId":0,"taskId":"T1"}',
        result='{"errorId":0,"status":"ready","solution":{"token":"cf-token"}}',
    )
    solver = _fast_solver(monkeypatch, fake)
    res = await solver.solve_turnstile("https://x.vn", "0xAAA", action="login")
    assert res.success is True
    assert res.solution == "cf-token"
    assert res.token == "cf-token"
    assert res.service == "capsolver"
    await solver.aclose()


@pytest.mark.asyncio
async def test_result_caching_second_call_no_network(monkeypatch):
    fake = FakeHTTP(
        create='{"errorId":0,"taskId":"T1"}',
        result='{"errorId":0,"status":"ready","solution":{"token":"cf-token"}}',
    )
    solver = _fast_solver(monkeypatch, fake)
    r1 = await solver.solve_turnstile("https://x.vn", "0xAAA", action="login")
    calls_after_first = len(fake.calls)
    r2 = await solver.solve_turnstile("https://x.vn", "0xAAA", action="login")
    assert r1.from_cache is False
    assert r2.from_cache is True
    assert r2.solution == "cf-token"
    assert len(fake.calls) == calls_after_first     # no new HTTP calls
    await solver.aclose()


@pytest.mark.asyncio
async def test_error_createtask_errorid(monkeypatch):
    fake = FakeHTTP(
        create='{"errorId":1,"errorDescription":"ERROR_KEY_DENIED"}',
        result='{}',
    )
    solver = _fast_solver(monkeypatch, fake)
    res = await solver.solve_turnstile("https://x.vn", "0xAAA")
    assert res.success is False
    assert "ERROR_KEY_DENIED" in (res.error or "")
    await solver.aclose()


@pytest.mark.asyncio
async def test_error_missing_taskid(monkeypatch):
    fake = FakeHTTP(create='{"errorId":0}', result='{}')
    solver = _fast_solver(monkeypatch, fake)
    res = await solver.solve_hcaptcha("https://x.vn", "k")
    assert res.success is False
    assert "taskId" in (res.error or "")
    await solver.aclose()


@pytest.mark.asyncio
async def test_poll_timeout(monkeypatch):
    # createTask ok, but getTaskResult never becomes "ready"
    fake = FakeHTTP(
        create='{"errorId":0,"taskId":"T1"}',
        result='{"errorId":0,"status":"processing"}',
    )
    solver = _fast_solver(monkeypatch, fake, poll_timeout=0.05, poll_interval=0.001)
    res = await solver.solve_recaptcha_v2("https://x.vn", "6Lc")
    assert res.success is False
    assert "timeout" in (res.error or "")
    await solver.aclose()


@pytest.mark.asyncio
async def test_fallback_to_second_service(monkeypatch):
    # Primary (capsolver) fails createTask; anticaptcha succeeds.
    def create(url, kwargs):
        if "capsolver" in url:
            return FakeResp('{"errorId":7,"errorDescription":"CAPSOLVER_DOWN"}')
        return FakeResp('{"errorId":0,"taskId":"T2"}')

    def result(url, kwargs):
        return FakeResp('{"errorId":0,"status":"ready","solution":{"token":"ac-token"}}')

    _no_keys(monkeypatch)
    cfg = CaptchaConfig(
        capsolver_key="cs", anticaptcha_key="ac", use_vision=False,
        primary=CaptchaService.CAPSOLVER,
        poll_interval=0.001, poll_timeout=1.0, retries=0, retry_backoff=0.0,
    )
    solver = UnifiedAsyncCaptchaSolver(cfg)
    fake = FakeHTTP(create, result)
    _wire(solver, fake)
    res = await solver.solve_turnstile("https://x.vn", "0xAAA")
    assert res.success is True
    assert res.solution == "ac-token"
    assert res.service == "anticaptcha"
    await solver.aclose()


@pytest.mark.asyncio
async def test_no_service_available_returns_failure(monkeypatch):
    _no_keys(monkeypatch)
    solver = UnifiedAsyncCaptchaSolver(CaptchaConfig(use_vision=False))
    res = await solver.solve_turnstile("https://x.vn", "0xAAA")
    assert res.success is False
    await solver.aclose()


@pytest.mark.asyncio
async def test_async_context_manager(monkeypatch):
    _no_keys(monkeypatch)
    async with create_solver(use_vision=False) as solver:
        assert isinstance(solver, UnifiedAsyncCaptchaSolver)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
