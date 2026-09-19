#!/usr/bin/env python3
"""Tests for improved_gdt_captcha_solver.py (page-level CAPTCHA workflow).

Covers, per the audit brief:
  * CaptchaDetector on mock HTML: Turnstile (incl. managed interstitial),
    reCAPTCHA v2 / v3 / Enterprise, hCaptcha, image, and "nothing detected"
  * BrowserCaptchaHarvester graceful degradation when Playwright is absent
  * LocalImageOCR graceful degradation when no OCR engine is installed
  * Token injection (replace existing field / append hidden input)
  * Fallback chains in AsyncGDTCaptchaSolver (browser -> commercial; and
    image: vision -> local OCR -> commercial) with the solver mocked
  * solve_from_html when no CAPTCHA is present, and error handling

No network or browser is used; the commercial solver and image fetch are mocked.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest

import improved_gdt_captcha_solver as gdt
from improved_captcha_solver import CaptchaConfig, CaptchaResult, CaptchaType
from improved_gdt_captcha_solver import (
    AsyncGDTCaptchaSolver,
    BrowserCaptchaHarvester,
    CaptchaChallenge,
    CaptchaDetector,
    LocalImageOCR,
)


def _no_keys(monkeypatch):
    for v in ("CAPSOLVER_API_KEY", "TWOCAPTCHA_API_KEY", "2CAPTCHA_API_KEY",
              "ANTICAPTCHA_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY"):
        monkeypatch.delenv(v, raising=False)


# --------------------------------------------------------------------------- #
# CaptchaDetector
# --------------------------------------------------------------------------- #
def test_detect_turnstile_widget():
    html = '<div class="cf-turnstile" data-sitekey="0x4AAAAAAABkMYinukE8nzY"></div>'
    ch = CaptchaDetector().detect(html)
    assert ch is not None
    assert ch.captcha_type == CaptchaType.TURNSTILE
    assert ch.sitekey == "0x4AAAAAAABkMYinukE8nzY"


def test_detect_turnstile_script_src():
    html = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
    ch = CaptchaDetector().detect(html)
    assert ch is not None and ch.captcha_type == CaptchaType.TURNSTILE


def test_detect_turnstile_managed_interstitial():
    html = "<title>Just a moment...</title><script>window._cf_chl_opt={}</script> cloudflare"
    ch = CaptchaDetector().detect(html)
    assert ch is not None and ch.captcha_type == CaptchaType.TURNSTILE


def test_detect_recaptcha_v2_checkbox():
    html = '<div class="g-recaptcha" data-sitekey="6LcAAA"></div><script src="https://www.google.com/recaptcha/api.js"></script>'
    ch = CaptchaDetector().detect(html)
    assert ch is not None
    assert ch.captcha_type == CaptchaType.RECAPTCHA_V2
    assert ch.sitekey == "6LcAAA"


def test_detect_recaptcha_v3_execute():
    html = (
        '<script src="https://www.google.com/recaptcha/api.js?render=6LcV3KEY"></script>'
        '<script>grecaptcha.ready(function(){grecaptcha.execute("6LcV3KEY",{action:"login"});});</script>'
    )
    ch = CaptchaDetector().detect(html)
    assert ch is not None
    assert ch.captcha_type == CaptchaType.RECAPTCHA_V3
    assert ch.action == "login"


def test_detect_recaptcha_enterprise():
    html = (
        '<script src="https://www.google.com/recaptcha/enterprise.js?render=6LcENT"></script>'
        '<script>grecaptcha.enterprise.ready(function(){'
        'grecaptcha.enterprise.execute("6LcENT",{action:"submit"});});</script>'
    )
    ch = CaptchaDetector().detect(html)
    assert ch is not None
    assert ch.captcha_type == CaptchaType.RECAPTCHA_ENTERPRISE
    assert ch.is_enterprise is True
    assert ch.action == "submit"


def test_detect_hcaptcha():
    html = '<div class="h-captcha" data-sitekey="hc-key"></div><script src="https://js.hcaptcha.com/1/api.js"></script>'
    ch = CaptchaDetector().detect(html)
    assert ch is not None
    assert ch.captcha_type == CaptchaType.HCAPTCHA
    assert ch.sitekey == "hc-key"


def test_detect_image_captcha_absolute_and_relative():
    html_abs = '<img id="captcha" src="https://gdt.gov.vn/captcha.png">'
    ch = CaptchaDetector().detect(html_abs)
    assert ch is not None and ch.captcha_type == CaptchaType.IMAGE
    assert ch.image_url == "https://gdt.gov.vn/captcha.png"

    html_rel = '<img class="captcha-img" src="/gen/captcha_image.jpg">'
    ch2 = CaptchaDetector().detect(html_rel, page_url="https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp")
    assert ch2 is not None and ch2.captcha_type == CaptchaType.IMAGE
    assert ch2.image_url.startswith("https://tracuunnt.gdt.gov.vn/")


def test_detect_none():
    assert CaptchaDetector().detect("<html><body>no challenge here</body></html>") is None
    assert CaptchaDetector().detect("") is None


def test_turnstile_checked_before_recaptcha():
    # A page that mentions both must resolve to Turnstile (checked first).
    html = '<div class="cf-turnstile" data-sitekey="0xKEY"></div><!-- recaptcha fallback -->'
    ch = CaptchaDetector().detect(html)
    assert ch.captcha_type == CaptchaType.TURNSTILE


# --------------------------------------------------------------------------- #
# BrowserCaptchaHarvester graceful degradation (Playwright absent)
# --------------------------------------------------------------------------- #
def _playwright_installed() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


@pytest.mark.asyncio
async def test_browser_harvester_start_without_playwright(monkeypatch):
    if _playwright_installed():
        pytest.skip("Playwright is installed; degradation path not exercised")
    h = BrowserCaptchaHarvester(CaptchaConfig())
    started = await h.start()
    assert started is False
    assert h.available is False


@pytest.mark.asyncio
async def test_browser_harvest_when_unavailable():
    h = BrowserCaptchaHarvester(CaptchaConfig())
    # Never started -> available is False regardless of Playwright.
    ch = CaptchaChallenge(CaptchaType.TURNSTILE, sitekey="0xKEY")
    res = await h.harvest(ch, "https://x.vn")
    assert res.success is False
    assert "unavailable" in (res.error or "")


# --------------------------------------------------------------------------- #
# LocalImageOCR graceful degradation (no OCR engines installed)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_local_ocr_degrades_without_engines():
    ocr = LocalImageOCR()
    # With no amazoncaptcha / easyocr / pytesseract installed, each method
    # raises ImportError internally and is skipped -> returns None (no crash).
    res = await ocr.solve(b"not-a-real-image")
    assert res is None


# --------------------------------------------------------------------------- #
# Token injection
# --------------------------------------------------------------------------- #
def test_inject_token_replaces_existing_field():
    html = '<form><textarea name="g-recaptcha-response"></textarea></form>'
    out = AsyncGDTCaptchaSolver.inject_token(html, "TOK", CaptchaType.RECAPTCHA_V2)
    assert 'value="TOK"' in out
    assert out.count("g-recaptcha-response") == 1


def test_inject_token_appends_when_absent():
    html = "<form></form>"
    out = AsyncGDTCaptchaSolver.inject_token(html, "TOK", CaptchaType.TURNSTILE)
    assert 'name="cf-turnstile-response"' in out
    assert 'value="TOK"' in out


# --------------------------------------------------------------------------- #
# AsyncGDTCaptchaSolver workflow + fallback chains (mocked)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_solve_from_html_no_captcha(monkeypatch):
    _no_keys(monkeypatch)
    async with AsyncGDTCaptchaSolver(use_browser=False) as s:
        out = await s.solve_from_html("<html>nothing</html>", "https://x.vn")
    assert out is None


@pytest.mark.asyncio
async def test_token_chain_falls_through_to_commercial(monkeypatch):
    _no_keys(monkeypatch)
    async with AsyncGDTCaptchaSolver(use_browser=False) as s:
        async def fake_turnstile(url, sitekey, action=None):
            return CaptchaResult(True, CaptchaType.TURNSTILE.value, solution="cf-tok",
                                 service="capsolver")
        monkeypatch.setattr(s.solver, "solve_turnstile", fake_turnstile)
        ch = CaptchaChallenge(CaptchaType.TURNSTILE, sitekey="0xKEY", action="login")
        res = await s.solve_challenge(ch, "https://x.vn")
    assert res.success is True
    assert res.solution == "cf-tok"
    assert res.service == "capsolver"


@pytest.mark.asyncio
async def test_image_chain_uses_local_ocr(monkeypatch):
    _no_keys(monkeypatch)
    async with AsyncGDTCaptchaSolver(use_browser=False) as s:
        async def fake_fetch(url):
            return b"fake-image-bytes"
        async def fake_ocr(image_bytes):
            return "AB12CD"
        monkeypatch.setattr(s, "_fetch_image", fake_fetch)
        monkeypatch.setattr(s.ocr, "solve", fake_ocr)
        # vision disabled (no key) so chain reaches OCR
        assert s.solver.vision.enabled is False
        ch = CaptchaChallenge(CaptchaType.IMAGE, image_url="https://x.vn/c.png")
        res = await s.solve_challenge(ch, "https://x.vn")
    assert res.success is True
    assert res.solution == "AB12CD"
    assert res.service == "local-ocr"


@pytest.mark.asyncio
async def test_image_chain_falls_through_to_commercial(monkeypatch):
    _no_keys(monkeypatch)
    async with AsyncGDTCaptchaSolver(use_browser=False) as s:
        async def fake_fetch(url):
            return b"img"
        async def fake_ocr(image_bytes):
            return None                       # OCR fails
        async def fake_commercial(img, **kw):
            return CaptchaResult(True, CaptchaType.IMAGE.value, solution="XY99",
                                 service="capsolver")
        monkeypatch.setattr(s, "_fetch_image", fake_fetch)
        monkeypatch.setattr(s.ocr, "solve", fake_ocr)
        monkeypatch.setattr(s.solver, "solve_image", fake_commercial)
        ch = CaptchaChallenge(CaptchaType.IMAGE, image_url="https://x.vn/c.png")
        res = await s.solve_challenge(ch, "https://x.vn")
    assert res.success is True
    assert res.service == "capsolver"


@pytest.mark.asyncio
async def test_solve_challenge_no_sitekey_errors(monkeypatch):
    _no_keys(monkeypatch)
    async with AsyncGDTCaptchaSolver(use_browser=False) as s:
        ch = CaptchaChallenge(CaptchaType.RECAPTCHA_V2, sitekey=None)
        res = await s.solve_challenge(ch, "https://x.vn")
    assert res.success is False
    assert "sitekey" in (res.error or "")


@pytest.mark.asyncio
async def test_solve_from_html_end_to_end_shape(monkeypatch):
    _no_keys(monkeypatch)
    html = '<div class="cf-turnstile" data-sitekey="0xKEY"></div>'
    async with AsyncGDTCaptchaSolver(use_browser=False) as s:
        async def fake_turnstile(url, sitekey, action=None):
            return CaptchaResult(True, CaptchaType.TURNSTILE.value, solution="cf-tok",
                                 service="capsolver", elapsed=0.5)
        monkeypatch.setattr(s.solver, "solve_turnstile", fake_turnstile)
        out = await s.solve_from_html(html, "https://x.vn")
    assert out["type"] == "turnstile"
    assert out["field_name"] == "cf-turnstile-response"
    assert out["token"] == "cf-tok"
    assert out["success"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
