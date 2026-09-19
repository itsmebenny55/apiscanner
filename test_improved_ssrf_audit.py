"""Tests for improved_ssrf_audit.py — modernized async SSRF (OWASP API7) auditor.

Uses an httpx MockTransport (no external targets) to drive a full async scan and
verify finding detection, the sync wrapper, correlation, and report generation.

Run:  python3 -m pytest test_improved_ssrf_audit.py -v
"""
from __future__ import annotations

import json

import httpx
import pytest

import improved_common as ic
from improved_common import ProbeResponse, ScanConfig
from improved_ssrf_audit import AsyncSSRFAuditor, SSRFAuditor

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _install_mock(monkeypatch, handler):
    """Force every AsyncHTTPClient to use a MockTransport-backed httpx client."""

    def factory(*args, **kwargs):
        for k in ("http2", "proxy", "limits"):
            kwargs.pop(k, None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(ic.httpx, "AsyncClient", factory)


def _fast_cfg(**kw):
    base = dict(stream_results=False, cache_responses=True, retries=0,
                retry_backoff=0, baseline_samples=1, rps=1000)
    base.update(kw)
    return ScanConfig(**base)


# --------------------------------------------------------------------------- #
# unit: encoding / exclusion / swagger parsing
# --------------------------------------------------------------------------- #
def test_encode_variants():
    enc = AsyncSSRFAuditor._encode
    assert enc("a b", "default") == "a+b"
    assert enc("http://x/", "base64")  # base64 non-empty
    assert enc("http://x/", "double_url").count("%25")   # double-encoded
    assert enc("<x>", "html") == "&lt;x&gt;"


def test_should_exclude_sensitive_params():
    a = AsyncSSRFAuditor(base_url="http://example.com", config=_fast_cfg())
    assert a._should_exclude("auth_token") is True
    assert a._should_exclude("password") is True
    assert a._should_exclude("url") is False


def test_endpoints_from_swagger(tmp_path):
    spec = {
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/fetch": {"get": {"parameters": [{"name": "url", "in": "query"}]}},
            "/ping": {"post": {}},
        },
    }
    p = tmp_path / "swagger.json"
    p.write_text(json.dumps(spec))
    eps = AsyncSSRFAuditor.endpoints_from_swagger(str(p))
    methods = {(e["method"], e["path"]) for e in eps}
    assert ("GET", "/fetch") in methods
    assert ("POST", "/ping") in methods


def test_endpoints_from_swagger_missing_file():
    assert AsyncSSRFAuditor.endpoints_from_swagger("/no/such/file.json") == []


# --------------------------------------------------------------------------- #
# unit: analysis logic (no network)
# --------------------------------------------------------------------------- #
def test_analyze_records_reflected_indicator():
    a = AsyncSSRFAuditor(base_url="http://example.com", config=_fast_cfg())
    ep = {"method": "GET", "path": "/fetch"}
    resp = ProbeResponse(200, {}, "root:x:0:0:root:/root", "http://example.com/fetch", 0.1)
    a._analyze(ep, resp, "file:///etc/passwd", "url", "default", baseline=0.0)
    assert len(a._issues) == 1
    assert a._issues[0]["severity"] == "High"
    assert a._issues[0]["confidence"] == "High"


def test_analyze_blind_latency():
    a = AsyncSSRFAuditor(base_url="http://example.com",
                         config=_fast_cfg(blind_threshold=1.0))
    ep = {"method": "GET", "path": "/fetch"}
    resp = ProbeResponse(200, {}, "nothing interesting", "http://example.com/fetch", 5.0)
    a._analyze(ep, resp, "http://169.254.169.254/", "url", "default", baseline=0.0)
    assert len(a._issues) == 1
    assert "blind" in a._issues[0]["description"].lower()


def test_analyze_clean_response_no_finding():
    a = AsyncSSRFAuditor(base_url="http://example.com", config=_fast_cfg())
    ep = {"method": "GET", "path": "/fetch"}
    resp = ProbeResponse(200, {}, "totally benign json {}", "http://example.com/fetch", 0.05)
    a._analyze(ep, resp, "http://127.0.0.1/", "url", "default", baseline=0.0)
    assert a._issues == []


# --------------------------------------------------------------------------- #
# integration: full async scan against mock transport
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_async_scan_detects_ssrf(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # Reflect a metadata/passwd indicator on any probe.
        return httpx.Response(200, text="uid=0 root:x:0:0 169.254.169.254")

    _install_mock(monkeypatch, handler)
    a = AsyncSSRFAuditor(base_url="http://example.com", config=_fast_cfg())
    eps = [{"method": "GET", "path": "/fetch",
            "parameters": [{"name": "url", "in": "query"}]}]
    findings = await a.test_endpoints_async(eps)
    assert len(findings) >= 1
    assert all(f["severity"] in ("High", "Medium") for f in findings)
    corr = a.correlation()
    assert corr["total_findings"] == len(findings)


def test_sync_wrapper_and_report(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="root:x:0:0")

    _install_mock(monkeypatch, handler)
    a = SSRFAuditor(base_url="http://example.com", config=_fast_cfg())
    eps = [{"method": "GET", "path": "/fetch",
            "parameters": [{"name": "url", "in": "query"}]}]
    findings = a.test_endpoints(eps)   # sync entrypoint (asyncio.run path)
    assert isinstance(findings, list)
    html = a.generate_report("html")
    assert isinstance(html, str) and len(html) > 0
    md = a.generate_report("markdown")
    assert isinstance(md, str) and len(md) > 0


def test_report_with_no_findings(monkeypatch):
    a = AsyncSSRFAuditor(base_url="http://example.com", config=_fast_cfg())
    # No scan run -> report should still render an Info placeholder.
    md = a.generate_report("markdown")
    assert isinstance(md, str) and len(md) > 0


def test_localhost_endpoint_skipped(monkeypatch):
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, text="root:x:")

    _install_mock(monkeypatch, handler)
    a = AsyncSSRFAuditor(base_url="http://127.0.0.1", config=_fast_cfg())
    findings = a.test_endpoints([{"method": "GET", "path": "/", "parameters": []}])
    # loopback host is explicitly skipped by _scan_endpoint
    assert findings == []
