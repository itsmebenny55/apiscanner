"""Tests for improved_broken_auth_audit.py — modernized async Broken-Auth (API2).

Run:  python3 -m pytest test_improved_broken_auth_audit.py -v
"""
from __future__ import annotations

import base64
import json

import httpx
import pytest

import improved_common as ic
from improved_common import ScanConfig
from improved_broken_auth_audit import AsyncAuthAuditor, AuthAuditor

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _install_mock(monkeypatch, handler):
    def factory(*args, **kwargs):
        for k in ("http2", "proxy", "limits"):
            kwargs.pop(k, None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(ic.httpx, "AsyncClient", factory)


def _fast_cfg(**kw):
    base = dict(stream_results=False, cache_responses=False, retries=0,
                retry_backoff=0, rps=1000, timeout=2.0)
    base.update(kw)
    return ScanConfig(**base)


def _jwt(header: dict, payload: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg(header)}.{seg(payload)}.sig"


# --------------------------------------------------------------------------- #
# unit: endpoint selection + JWT analysis + transport
# --------------------------------------------------------------------------- #
def test_select_auth_endpoints():
    a = AsyncAuthAuditor(base_url="http://example.com", config=_fast_cfg())
    eps = [
        {"path": "/login", "method": "POST", "tags": []},
        {"path": "/products", "method": "GET", "tags": []},
        {"path": "/password/reset", "method": "POST", "tags": []},   # skip hint
    ]
    selected = a._select_auth_endpoints(eps)
    paths = {e["path"] for e in selected}
    assert "/login" in paths
    assert "/password/reset" not in paths


def test_analyze_jwt_alg_none():
    tok = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "1"})
    out = AsyncAuthAuditor._analyze_jwt(tok)
    assert out["alg_none"] is True


def test_analyze_jwt_weak_hs256_and_no_exp():
    tok = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
    out = AsyncAuthAuditor._analyze_jwt(tok)
    assert out["weak_alg"] == "HS256"
    assert out["no_exp"] is True


def test_extract_jwt():
    tok = _jwt({"alg": "HS256"}, {"sub": "1"})
    blob = f"here is your token: {tok} thanks"
    assert AsyncAuthAuditor._extract_jwt(blob) == tok
    assert AsyncAuthAuditor._extract_jwt("no token here") is None


def test_plaintext_http_flagged():
    a = AsyncAuthAuditor(base_url="http://example.com", config=_fast_cfg())
    a._test_secure_transport()
    assert any("plaintext" in i["description"].lower() for i in a.auth_issues)


def test_https_not_flagged_plaintext():
    a = AsyncAuthAuditor(base_url="https://example.com", config=_fast_cfg())
    a._test_secure_transport()
    assert not any("plaintext" in i["description"].lower() for i in a.auth_issues)


# --------------------------------------------------------------------------- #
# integration: weak-credential + full run
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_weak_credentials_detected(monkeypatch):
    tok = _jwt({"alg": "HS256"}, {"sub": "admin"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": tok, "success": True})

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/login": {"post": {"tags": ["auth"]}}}}
    a = AsyncAuthAuditor(base_url="http://example.com", swagger_spec=spec, config=_fast_cfg())
    issues = await a.test_authentication_mechanisms_async()
    descs = " ".join(i["description"].lower() for i in issues)
    assert "weak/default credentials" in descs
    # base_url is http:// -> plaintext transport also flagged
    assert "plaintext" in descs


def test_sync_wrapper_and_report(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/login": {"post": {"tags": ["auth"]}}}}
    a = AuthAuditor(base_url="https://example.com", swagger_spec=spec, config=_fast_cfg())
    issues = a.test_authentication_mechanisms()   # sync entrypoint
    assert isinstance(issues, list)
    md = a.generate_report("markdown")
    assert isinstance(md, str) and len(md) > 0
    html = a.generate_report("html")
    assert isinstance(html, str) and len(html) > 0


def test_missing_auth_detected(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # A protected-looking endpoint returns user data with no creds.
        if "/profile" in str(request.url):
            return httpx.Response(200, json={"email": "a@b.com", "role": "admin", "id": 1})
        return httpx.Response(404, text="nope")

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/profile": {"get": {}}}}
    a = AsyncAuthAuditor(base_url="https://example.com", swagger_spec=spec, config=_fast_cfg())
    issues = a.test_authentication_mechanisms()
    assert any("without authentication" in i["description"].lower() for i in issues)


def test_websocket_probe_graceful_when_absent(monkeypatch):
    # No ws handler needed: websockets is absent, probe must degrade silently.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="{}")

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/login": {"post": {"tags": ["auth"]}}}}
    a = AsyncAuthAuditor(base_url="https://example.com", swagger_spec=spec, config=_fast_cfg())
    issues = a.test_authentication_mechanisms()   # must not raise
    assert isinstance(issues, list)
