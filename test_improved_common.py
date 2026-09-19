"""Tests for improved_common.py — the async foundation of the modernized auditors.

Covers: config validation, rate limiting, the async HTTP client (via httpx
MockTransport — no external targets), retries/error handling, response caching,
result streaming, passive fingerprinting, vuln-graph correlation, the LLM payload
generator's static fallback, and graceful degradation when the optional deps
(playwright / websockets / networkx / structlog) are absent.

Run:  python3 -m pytest test_improved_common.py -v
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

import improved_common as ic
from improved_common import (
    AsyncHTTPClient,
    LLMPayloadGenerator,
    PassiveFingerprinter,
    PlaywrightProbe,
    ProbeResponse,
    RateLimiter,
    ResponseCache,
    ResultStreamer,
    ScanConfig,
    VulnerabilityGraph,
    WebSocketProbe,
    capabilities,
    get_logger,
    run_async,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _swap_transport(client: AsyncHTTPClient, handler) -> None:
    """Replace the wrapped httpx client with a MockTransport-backed one."""
    await client._client.aclose()
    client._client = _mock_client(handler)


# --------------------------------------------------------------------------- #
# ScanConfig (pydantic)
# --------------------------------------------------------------------------- #
def test_scanconfig_defaults():
    c = ScanConfig()
    assert c.concurrency == 20
    assert c.rps == 15.0
    assert c.retries == 2
    assert c.cache_responses is True


def test_scanconfig_validation_bounds():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanConfig(concurrency=0)          # ge=1
    with pytest.raises(ValidationError):
        ScanConfig(concurrency=1000)       # le=500
    with pytest.raises(ValidationError):
        ScanConfig(rps=0)                  # gt=0


def test_scanconfig_ignores_extra():
    c = ScanConfig(concurrency=5, not_a_field=123)
    assert c.concurrency == 5


# --------------------------------------------------------------------------- #
# RateLimiter
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_rate_limiter_paces():
    rl = RateLimiter(rps=50)   # 20ms gap
    import time

    start = time.monotonic()
    await rl.acquire()
    await rl.acquire()
    await rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.03   # at least two 20ms gaps


@pytest.mark.asyncio
async def test_rate_limiter_disabled():
    rl = RateLimiter(rps=0)
    await rl.acquire()   # must not raise or block


# --------------------------------------------------------------------------- #
# AsyncHTTPClient — success / caching / retries / errors / context mgmt
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_async_client_success_maps_proberesponse():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"X-Test": "1"}, text="hello")

    client = AsyncHTTPClient(ScanConfig(retries=0, retry_backoff=0))
    await _swap_transport(client, handler)
    resp = await client.request("GET", "http://example.com/")
    assert isinstance(resp, ProbeResponse)
    assert resp.status_code == 200
    assert resp.ok is True
    assert resp.text == "hello"
    assert resp.headers.get("x-test") == "1"
    assert resp.source == "httpx"
    assert resp.elapsed >= 0.0
    await client.aclose()


@pytest.mark.asyncio
async def test_async_client_caches_by_key():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="cached-body")

    client = AsyncHTTPClient(ScanConfig(cache_responses=True))
    await _swap_transport(client, handler)
    r1 = await client.request("GET", "http://example.com/x", cache_key="K1")
    r2 = await client.request("GET", "http://example.com/x", cache_key="K1")
    assert r1.text == r2.text == "cached-body"
    assert calls["n"] == 1     # second call served from cache
    await client.aclose()


@pytest.mark.asyncio
async def test_async_client_retries_then_succeeds():
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, text="recovered")

    client = AsyncHTTPClient(ScanConfig(retries=2, retry_backoff=0))
    await _swap_transport(client, handler)
    resp = await client.request("GET", "http://example.com/retry")
    assert resp.ok is True
    assert resp.text == "recovered"
    assert state["n"] == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_async_client_error_after_exhausting_retries():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("always down", request=request)

    client = AsyncHTTPClient(ScanConfig(retries=1, retry_backoff=0))
    await _swap_transport(client, handler)
    resp = await client.request("GET", "http://example.com/down")
    assert resp.ok is False
    assert resp.source == "error"
    assert resp.status_code == 0
    assert "ConnectError" in (resp.error or "")
    await client.aclose()


@pytest.mark.asyncio
async def test_async_client_context_manager():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    async with AsyncHTTPClient(ScanConfig()) as client:
        await _swap_transport(client, handler)
        resp = await client.request("GET", "http://example.com/")
        assert resp.status_code == 204


def test_from_requests_session_copies_state():
    class FakeCookies:
        def get_dict(self):
            return {"sid": "abc"}

    class FakeSession:
        headers = {"User-Agent": "apiscan-test"}
        cookies = FakeCookies()
        verify = False
        proxies = {"https": "http://127.0.0.1:8080"}

    client = AsyncHTTPClient.from_requests_session(FakeSession(), ScanConfig())
    assert isinstance(client, AsyncHTTPClient)


# --------------------------------------------------------------------------- #
# ResponseCache
# --------------------------------------------------------------------------- #
def test_response_cache_put_get_and_cap():
    cache = ResponseCache(max_entries=2)
    r = ProbeResponse(200, {}, "b", "u", 0.1)
    cache.put("a", r)
    cache.put("b", r)
    cache.put("c", r)   # over cap: ignored
    assert cache.get("a") is r
    assert cache.get("c") is None


# --------------------------------------------------------------------------- #
# ResultStreamer — dedupe + lazy file open
# --------------------------------------------------------------------------- #
def test_result_streamer_dedupe_no_path():
    s = ResultStreamer(None, key_fields=("endpoint", "description"))
    f = {"endpoint": "/a", "description": "x"}
    assert s.emit(f) is True
    assert s.emit(dict(f)) is False   # duplicate key
    assert s.emit({"endpoint": "/a", "description": "y"}) is True


def test_result_streamer_writes_jsonl_lazily(tmp_path):
    p = tmp_path / "sub" / "findings.jsonl"
    s = ResultStreamer(p, key_fields=("endpoint",))
    assert not p.exists()   # constructing must not touch disk
    s.emit({"endpoint": "/a", "sev": "High"})
    s.emit({"endpoint": "/a"})          # dup -> not written
    s.emit({"endpoint": "/b"})
    s.close()
    assert p.exists()
    lines = [json.loads(x) for x in p.read_text().splitlines()]
    assert [l["endpoint"] for l in lines] == ["/a", "/b"]


# --------------------------------------------------------------------------- #
# LLMPayloadGenerator — static fallback (no key / disabled)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_llm_generator_disabled_returns_seeds(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    gen = LLMPayloadGenerator(ScanConfig(use_llm=True))   # no key -> disabled
    assert gen.enabled is False
    seeds = ["a", "b"]
    out = await gen.generate("SSRF", "ctx", seeds)
    assert out == seeds


def test_parse_json_array_variants():
    assert ic._parse_json_array('["a","b"]') == ["a", "b"]
    assert ic._parse_json_array('```json\n["x"]\n```') == ["x"]
    assert ic._parse_json_array('junk ["y","z"] trailing') == ["y", "z"]
    assert ic._parse_json_array("not json") == []


def test_dedupe_preserves_order():
    assert ic._dedupe(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


# --------------------------------------------------------------------------- #
# PassiveFingerprinter
# --------------------------------------------------------------------------- #
def test_fingerprint_detects_cloudflare_and_challenge():
    fp = PassiveFingerprinter()
    out = fp.fingerprint(
        {"Server": "cloudflare", "CF-RAY": "abc"},
        "Just a moment... checking your browser",
    )
    assert out["waf"] == "cloudflare"
    assert out["js_challenge"] is True
    assert out["needs_browser"] is True


def test_fingerprint_clean_response():
    fp = PassiveFingerprinter()
    out = fp.fingerprint({"Server": "nginx"}, "<html>ok</html>")
    assert out["waf"] is None
    assert out["needs_browser"] is False


def test_recommend_throttles_under_waf():
    fp = PassiveFingerprinter()
    cfg = ScanConfig(rps=15.0)
    rec = fp.recommend({"waf": "cloudflare", "needs_browser": True}, cfg)
    assert rec["rps"] <= 4.0
    assert rec["use_browser"] is True


# --------------------------------------------------------------------------- #
# VulnerabilityGraph (dict fallback path when networkx absent)
# --------------------------------------------------------------------------- #
def test_vuln_graph_correlation_systemic():
    g = VulnerabilityGraph()
    g.add_finding({"endpoint": "/a", "parameter": "url", "payload": "P", "severity": "High"})
    g.add_finding({"endpoint": "/b", "parameter": "url", "payload": "P", "severity": "High"})
    g.add_finding({"endpoint": "/c", "parameter": "other", "payload": "Q", "severity": "Low"})
    corr = g.correlate()
    assert corr["total_findings"] == 3
    assert corr["by_severity"]["High"] == 2
    # 'url' recurs across /a and /b -> systemic
    assert any(sp["param"] == "url" and sp["endpoints"] == 2 for sp in corr["systemic_params"])
    assert corr["graph_backend"] in ("dict", "networkx")


# --------------------------------------------------------------------------- #
# Graceful degradation for optional deps
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_playwright_probe_unavailable_degrades():
    probe = PlaywrightProbe(ScanConfig())
    # start() returns False when playwright missing; if installed it may launch.
    started = await probe.start()
    if not started:
        assert probe.available is False
        r = await probe.fetch("http://example.com")
        assert r.ok is False
        assert r.source == "error"
    await probe.close()


@pytest.mark.asyncio
async def test_websocket_probe_degrades_when_absent():
    probe = WebSocketProbe(ScanConfig(timeout=1.0))
    import importlib.util

    if importlib.util.find_spec("websockets") is None:
        res = await probe.probe("ws://example.com/ws", ['{"a":1}'], collect=1)
        assert res["ok"] is False
        assert "websockets" in res["error"]


def test_ws_url_conversion():
    assert WebSocketProbe.to_ws_url("https://x.com", "/ws") == "wss://x.com/ws"
    assert WebSocketProbe.to_ws_url("http://x.com") == "ws://x.com"


def test_capabilities_reports_bools():
    caps = capabilities()
    assert caps["httpx"] is True and caps["pydantic"] is True
    for k in ("structlog", "networkx", "anthropic", "playwright", "websockets"):
        assert isinstance(caps[k], bool)


# --------------------------------------------------------------------------- #
# run_async bridge (sync + inside-running-loop thread fallback)
# --------------------------------------------------------------------------- #
def test_run_async_from_sync():
    async def coro():
        await asyncio.sleep(0)
        return 42

    assert run_async(coro()) == 42


@pytest.mark.asyncio
async def test_run_async_inside_running_loop():
    async def coro():
        await asyncio.sleep(0)
        return "threaded"

    # Called from within a running loop -> uses worker-thread fallback.
    assert run_async(coro()) == "threaded"


def test_get_logger_has_kwargs_api():
    log = get_logger("apiscan.test")
    # Must accept structlog-style kwargs whether or not structlog is installed.
    log.info("event", key="value", n=1)
