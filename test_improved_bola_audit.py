"""Tests for improved_bola_audit.py — modernized async BOLA/IDOR (API1) auditor.

Run:  python3 -m pytest test_improved_bola_audit.py -v
"""
from __future__ import annotations

import httpx
import pytest

import improved_common as ic
from improved_common import ScanConfig
from improved_bola_audit import AsyncBOLAAuditor, BOLAAuditor

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
                retry_backoff=0, rps=1000)
    base.update(kw)
    return ScanConfig(**base)


# --------------------------------------------------------------------------- #
# unit: discovery / materialization / shape
# --------------------------------------------------------------------------- #
def test_get_object_endpoints_from_template():
    spec = {"paths": {
        "/users/{id}": {"get": {}, "delete": {}},
        "/health": {"get": {}},                      # no id -> excluded
    }}
    a = AsyncBOLAAuditor(base_url="http://example.com", swagger_spec=spec, config=_fast_cfg())
    eps = a.get_object_endpoints()
    paths = {(e["method"], e["path"]) for e in eps}
    assert ("GET", "/users/{id}") in paths
    assert ("DELETE", "/users/{id}") in paths
    assert all(e["path"] != "/health" for e in eps)


def test_materialize_template_and_numeric():
    a = AsyncBOLAAuditor(base_url="http://example.com", config=_fast_cfg())
    tmpl = {"url": "http://example.com/users/{id}", "id_params": ["id"]}
    assert a._materialize(tmpl, "42") == "http://example.com/users/42"
    numeric = {"url": "http://example.com/orders/7", "id_params": []}
    assert a._materialize(numeric, "9") == "http://example.com/orders/9"


def test_json_shape_ignores_volatile_keys():
    a = AsyncBOLAAuditor(base_url="http://example.com", config=_fast_cfg())
    s1 = a._json_shape('{"id":1,"name":"a","timestamp":"t1"}')
    s2 = a._json_shape('{"id":2,"name":"b","timestamp":"t2"}')
    assert s1 == s2   # same shape, volatile keys stripped


def test_is_generic_success_and_sensitive():
    assert AsyncBOLAAuditor._is_generic_success("{}") is True
    assert AsyncBOLAAuditor._is_generic_success('{"status":"ok"}') is True
    assert AsyncBOLAAuditor._is_generic_success('{"email":"a@b.com"}') is False
    assert AsyncBOLAAuditor._detect_sensitive('{"email":"a@b.com"}') is True
    assert AsyncBOLAAuditor._detect_sensitive('{"color":"red"}') is False


# --------------------------------------------------------------------------- #
# integration: cross-user access detection
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_async_scan_detects_bola(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # Every object id returns a same-shaped record with sensitive data.
        return httpx.Response(200, json={"id": 1, "email": "victim@example.com", "name": "V"})

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/users/{id}": {"get": {}}}}
    a = AsyncBOLAAuditor(base_url="http://example.com", swagger_spec=spec, config=_fast_cfg())
    results = await a.run_async(spec)
    assert len(results) >= 1
    assert any(r.is_vulnerable for r in results)
    corr = a.correlation()
    assert corr["total_findings"] == len(a.issues)


def test_sync_wrapper_and_report(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "email": "v@x.com"})

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/accounts/{accountId}": {"get": {}}}}
    a = BOLAAuditor(base_url="http://example.com", swagger_spec=spec, config=_fast_cfg())
    results = a.run(spec)     # sync entrypoint
    assert isinstance(results, list)
    html = a.generate_report("html")
    assert isinstance(html, str) and len(html) > 0


def test_no_findings_when_403(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    _install_mock(monkeypatch, handler)
    spec = {"paths": {"/users/{id}": {"get": {}}}}
    a = AsyncBOLAAuditor(base_url="http://example.com", swagger_spec=spec, config=_fast_cfg())
    results = a.run(spec)
    assert results == []
    md = a.generate_report("markdown")   # renders Info placeholder
    assert isinstance(md, str) and len(md) > 0
