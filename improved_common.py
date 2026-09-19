########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                          #
#                                                       #
# improved_common.py                                    #
# Shared async foundation for the modernized audit      #
# tools (improved_ssrf_audit / improved_bola_audit /    #
# improved_broken_auth_audit).                          #
#                                                       #
# Bleeding-edge stack:                                  #
#   * httpx.AsyncClient + asyncio  (concurrency)        #
#   * Playwright                   (JS / WAF handling)  #
#   * Ollama (Qwen 7B)             (local LLM fuzzing)  #
#   * Anthropic Claude             (cloud LLM fallback) #
#   * networkx                     (finding correlation)#
#   * structlog                    (structured logs)    #
#   * websockets                   (real-time API test) #
#                                                       #
# Every heavy dependency is imported lazily and         #
# degrades gracefully: the tools import and run even    #
# when Ollama / Playwright / networkx / structlog /     #
# websockets / anthropic are not installed.             #
########################################################
"""Async foundation shared by the modernized APISCAN auditors.

The classic auditors (``ssrf_audit.py``, ``bola_audit.py``,
``broken_auth_audit.py``) are built on ``requests`` + ``ThreadPoolExecutor``.
This module provides the modern equivalents so the ``improved_*`` auditors can
share one implementation of:

* :class:`ScanConfig`         - validated (pydantic) run configuration.
* :class:`AsyncHTTPClient`    - httpx.AsyncClient wrapper with a shared
                                concurrency semaphore, RPS pacing, retries and
                                per-request timing.
* :class:`RateLimiter`        - async requests-per-second limiter.
* :class:`ResultStreamer`     - incremental JSONL result streaming + dedupe.
* :class:`ResponseCache`      - in-memory response cache (avoid re-probing).
* :class:`LLMPayloadGenerator`- Claude API-backed intelligent fuzzing payloads.
* :class:`OllamaPayloadGenerator` - Local Ollama-backed payload generation (Qwen).
* :func:`create_llm_payload_generator` - Smart LLM backend selection (Ollama→Claude→seeds).
* :class:`PlaywrightProbe`    - headless-browser probe for JS/WAF endpoints.
* :class:`WebSocketProbe`     - real-time WebSocket API testing.
* :class:`PassiveFingerprinter`- header/body fingerprint to balance passive vs
                                active scanning.
* :class:`VulnerabilityGraph` - networkx-based cross-finding correlation.
* :func:`get_logger`          - structlog logger (stdlib fallback).
* :func:`run_async`           - run a coroutine from sync code (apiscan compat).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Optional dependencies - imported lazily / guarded so the toolkit still loads
# --------------------------------------------------------------------------- #
import logging as _logging

# Keep third-party transport loggers quiet; the auditors log their own events.
for _noisy in ("httpx", "httpcore", "hpack", "websockets", "anthropic"):
    _logging.getLogger(_noisy).setLevel(_logging.WARNING)

try:  # structured logging
    import structlog  # type: ignore

    _HAVE_STRUCTLOG = True
except Exception:  # pragma: no cover - optional
    structlog = None  # type: ignore
    _HAVE_STRUCTLOG = False

try:  # graph correlation
    import networkx as nx  # type: ignore

    _HAVE_NETWORKX = True
except Exception:  # pragma: no cover - optional
    nx = None  # type: ignore
    _HAVE_NETWORKX = False

try:  # LLM payload generation
    from anthropic import AsyncAnthropic  # type: ignore

    _HAVE_ANTHROPIC = True
except Exception:  # pragma: no cover - optional
    AsyncAnthropic = None  # type: ignore
    _HAVE_ANTHROPIC = False


# --------------------------------------------------------------------------- #
# Logging - structlog with a stdlib-logging fallback
# --------------------------------------------------------------------------- #
_STRUCTLOG_CONFIGURED = False


class _StdlibLoggerShim:
    """Give a stdlib logger a structlog-style kwargs API.

    ``log.info("probing", url=u, status=200)`` becomes
    ``probing url=... status=200`` so call sites are identical whether or not
    structlog is installed.
    """

    def __init__(self, name: str):
        import logging

        self._log = logging.getLogger(name)

    @staticmethod
    def _fmt(event: str, kwargs: Dict[str, Any]) -> str:
        if not kwargs:
            return event
        extras = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
        return f"{event} {extras}"

    def debug(self, event: str, **kw: Any) -> None:
        self._log.debug(self._fmt(event, kw))

    def info(self, event: str, **kw: Any) -> None:
        self._log.info(self._fmt(event, kw))

    def warning(self, event: str, **kw: Any) -> None:
        self._log.warning(self._fmt(event, kw))

    warn = warning

    def error(self, event: str, **kw: Any) -> None:
        self._log.error(self._fmt(event, kw))

    def exception(self, event: str, **kw: Any) -> None:
        self._log.exception(self._fmt(event, kw))


def get_logger(name: str = "apiscan.improved") -> Any:
    """Return a structlog logger, or a stdlib-backed shim with the same API."""
    global _STRUCTLOG_CONFIGURED
    if _HAVE_STRUCTLOG:
        if not _STRUCTLOG_CONFIGURED:
            structlog.configure(
                processors=[
                    structlog.processors.add_log_level,
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.dev.ConsoleRenderer(colors=True),
                ],
                wrapper_class=structlog.make_filtering_bound_logger(
                    _level_to_int(os.getenv("APISCAN_LOG_LEVEL", "INFO"))
                ),
                cache_logger_on_first_use=True,
            )
            _STRUCTLOG_CONFIGURED = True
        return structlog.get_logger(name)
    return _StdlibLoggerShim(name)


def _level_to_int(level: str) -> int:
    import logging

    return getattr(logging, str(level).upper(), logging.INFO)


# --------------------------------------------------------------------------- #
# Configuration (pydantic-validated)
# --------------------------------------------------------------------------- #
class ScanConfig(BaseModel):
    """Validated configuration shared by the async auditors."""

    # concurrency / pacing
    concurrency: int = Field(default=20, ge=1, le=500)
    rps: float = Field(default=15.0, gt=0, description="Requests per second cap.")
    timeout: float = Field(default=15.0, gt=0)
    retries: int = Field(default=2, ge=0, le=10)
    retry_backoff: float = Field(default=0.5, ge=0)

    # transport
    verify_tls: bool = Field(default=False)
    follow_redirects: bool = Field(default=True)
    max_redirects: int = Field(default=5, ge=0)
    http2: bool = Field(default=True)

    # analysis
    blind_threshold: float = Field(default=4.0, gt=0)
    baseline_samples: int = Field(default=2, ge=1)
    response_body_limit: int = Field(default=4096, ge=256)

    # modern features
    use_browser: bool = Field(default=False, description="Use Playwright on WAF/JS endpoints.")
    browser_auto: bool = Field(default=True, description="Auto-enable browser when fingerprint flags WAF/JS.")
    use_llm: bool = Field(default=False, description="Use LLM for payload generation.")
    llm_backend: str = Field(default="ollama", description="LLM backend: 'ollama' (local), 'claude' (API), or 'auto' (try Ollama first)")
    llm_model: str = Field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"))
    ollama_model: str = Field(default="qwen:7b", description="Ollama model to use (e.g. 'qwen:7b', 'qwen:14b', 'mistral')")
    ollama_url: str = Field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434"))
    llm_max_payloads: int = Field(default=12, ge=1, le=64)

    # output / caching
    output_dir: str = Field(default="scan_output")
    stream_results: bool = Field(default=True)
    cache_responses: bool = Field(default=True)

    model_config = {"extra": "ignore"}


# --------------------------------------------------------------------------- #
# Async rate limiter (requests-per-second)
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Simple async RPS limiter (monotonic-clock gap pacing)."""

    def __init__(self, rps: float):
        self._min_gap = 1.0 / float(rps) if rps > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._min_gap <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._min_gap - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# --------------------------------------------------------------------------- #
# Response object (uniform across httpx / playwright / cache)
# --------------------------------------------------------------------------- #
@dataclass
class ProbeResponse:
    status_code: int
    headers: Dict[str, str]
    text: str
    url: str
    elapsed: float
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    source: str = "httpx"           # httpx | browser | cache | error
    error: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None


# --------------------------------------------------------------------------- #
# Async HTTP client (httpx) with concurrency + pacing + retries
# --------------------------------------------------------------------------- #
class AsyncHTTPClient:
    """httpx.AsyncClient wrapper with a shared semaphore, RPS pacing and retries.

    Replaces ``requests.Session`` + ``ThreadPoolExecutor``. Construct directly,
    or seed headers/cookies/verify from an existing ``requests.Session`` via
    :meth:`from_requests_session` for drop-in compatibility with apiscan.py.
    """

    def __init__(
        self,
        config: ScanConfig,
        *,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxies: Optional[str] = None,
        proxy_manager: Optional[Any] = None,
        logger: Any = None,
    ):
        self.config = config
        self.log = logger or get_logger("apiscan.http")
        self._sem = asyncio.Semaphore(config.concurrency)
        self._limiter = RateLimiter(config.rps)
        self._cache = ResponseCache() if config.cache_responses else None
        self._proxy_manager = proxy_manager  # IPRoyal or other proxy manager

        limits = httpx.Limits(
            max_connections=config.concurrency,
            max_keepalive_connections=config.concurrency,
        )
        client_kwargs: Dict[str, Any] = dict(
            timeout=httpx.Timeout(config.timeout),
            verify=config.verify_tls,
            follow_redirects=config.follow_redirects,
            max_redirects=config.max_redirects,
            limits=limits,
            headers=headers or {},
            cookies=cookies or {},
        )
        # http2 requires the 'h2' package; fall back silently if missing.
        try:
            self._client = httpx.AsyncClient(http2=config.http2, **client_kwargs)
        except Exception:
            self._client = httpx.AsyncClient(http2=False, **client_kwargs)
        if proxies:
            # httpx uses a single proxy string / mounts; re-create with proxy.
            try:
                self._client = httpx.AsyncClient(proxy=proxies, http2=False, **client_kwargs)
            except Exception:
                pass

    @classmethod
    def from_requests_session(cls, session: Any, config: ScanConfig, **kw: Any) -> "AsyncHTTPClient":
        """Build from a ``requests.Session`` (copy headers/cookies/verify/proxies)."""
        headers = dict(getattr(session, "headers", {}) or {})
        cookies = {}
        try:
            cookies = session.cookies.get_dict()
        except Exception:
            cookies = {}
        # honor session.verify -> config.verify_tls
        try:
            config = config.model_copy(update={"verify_tls": bool(getattr(session, "verify", config.verify_tls))})
        except Exception:
            pass
        proxies = None
        try:
            pxy = getattr(session, "proxies", None) or {}
            proxies = pxy.get("https") or pxy.get("http") or None
        except Exception:
            proxies = None
        return cls(config, headers=headers, cookies=cookies, proxies=proxies, **kw)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        cache_key: Optional[str] = None,
    ) -> ProbeResponse:
        """Perform one request under the shared semaphore + rate limiter."""
        if self._cache is not None and cache_key:
            hit = self._cache.get(cache_key)
            if hit is not None:
                return hit

        # Determine proxy for this URL (if using proxy_manager)
        proxy_for_url = None
        if self._proxy_manager:
            proxy_for_url = self._proxy_manager.get_proxy(url)

        attempt = 0
        last_err: Optional[str] = None
        while attempt <= self.config.retries:
            async with self._sem:
                await self._limiter.acquire()
                started = time.perf_counter()
                try:
                    # Use proxy-specific client if needed
                    client = self._client
                    if proxy_for_url and proxy_for_url != getattr(self._client, '_proxy', None):
                        # Create temporary client with specific proxy for this request
                        limits = httpx.Limits(
                            max_connections=1,
                            max_keepalive_connections=1,
                        )
                        client = httpx.AsyncClient(
                            proxy=proxy_for_url,
                            timeout=httpx.Timeout(self.config.timeout),
                            verify=self.config.verify_tls,
                            follow_redirects=self.config.follow_redirects,
                            max_redirects=self.config.max_redirects,
                            limits=limits,
                            headers=self._client._mounts or {},
                        )

                    resp = await client.request(
                        method.upper(),
                        url,
                        params=params,
                        json=json_body,
                        data=data,
                        headers=headers,
                    )

                    # Close temporary client
                    if proxy_for_url and client != self._client:
                        await client.aclose()
                    elapsed = time.perf_counter() - started
                    body = resp.text or ""
                    if len(body) > self.config.response_body_limit * 4:
                        body = body[: self.config.response_body_limit * 4]
                    out = ProbeResponse(
                        status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items()},
                        text=body,
                        url=str(resp.url),
                        elapsed=elapsed,
                        request_headers={k: v for k, v in resp.request.headers.items()},
                        request_body=_body_to_str(getattr(resp.request, "content", None)),
                        cookies=_cookies_to_dict(resp.cookies),
                        source="httpx",
                    )
                    if self._cache is not None and cache_key:
                        self._cache.put(cache_key, out)
                    return out
                except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                except Exception as e:  # pragma: no cover - defensive
                    last_err = f"{type(e).__name__}: {e}"
            attempt += 1
            if attempt <= self.config.retries:
                await asyncio.sleep(self.config.retry_backoff * attempt)

        return ProbeResponse(
            status_code=0, headers={}, text="", url=url, elapsed=0.0,
            source="error", error=last_err or "request failed",
        )

    async def aclose(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass

    async def __aenter__(self) -> "AsyncHTTPClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


def _body_to_str(content: Any, limit: int = 2048) -> Optional[str]:
    if content is None:
        return None
    try:
        if isinstance(content, (bytes, bytearray)):
            return content.decode("utf-8", "replace")[:limit]
        return str(content)[:limit]
    except Exception:
        return None


def _cookies_to_dict(cookies: Any) -> Dict[str, str]:
    try:
        return {k: v for k, v in cookies.items()}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Result streaming + response cache
# --------------------------------------------------------------------------- #
class ResultStreamer:
    """Stream findings to a JSONL file as they are discovered, with dedupe."""

    def __init__(self, path: Optional[str | Path], key_fields: Iterable[str] = ("endpoint", "description")):
        self.path = Path(path) if path else None
        self._key_fields = tuple(key_fields)
        self._seen: set = set()
        self._fh = None  # opened lazily on first emit - constructing never touches disk

    def _key(self, finding: Dict[str, Any]) -> Tuple:
        return tuple(finding.get(f) for f in self._key_fields)

    def _ensure_open(self) -> None:
        if self._fh is None and self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("w", encoding="utf-8")

    def emit(self, finding: Dict[str, Any]) -> bool:
        """Write a finding if new. Returns True when actually emitted."""
        k = self._key(finding)
        if k in self._seen:
            return False
        self._seen.add(k)
        if self.path is not None:
            try:
                self._ensure_open()
                self._fh.write(json.dumps(finding, ensure_ascii=False, default=str) + "\n")
                self._fh.flush()
            except Exception:
                pass
        return True

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass


class ResponseCache:
    """Tiny in-memory response cache to avoid re-probing identical requests."""

    def __init__(self, max_entries: int = 20000):
        self._store: Dict[str, ProbeResponse] = {}
        self._max = max_entries

    def get(self, key: str) -> Optional[ProbeResponse]:
        return self._store.get(key)

    def put(self, key: str, resp: ProbeResponse) -> None:
        if len(self._store) >= self._max:
            return
        self._store[key] = resp


# --------------------------------------------------------------------------- #
# LLM payload generation (Anthropic Claude)
# --------------------------------------------------------------------------- #
class LLMPayloadGenerator:
    """Generate context-aware fuzzing payloads with Claude.

    Used only for the operator's own authorized API security audit. When the
    ``anthropic`` package is missing, no API key is configured, or the call
    fails for any reason, this falls back to the provided static seed payloads
    so scans never depend on network/LLM availability.
    """

    _SYSTEM = (
        "You are a payload generator for APISCAN, an authorized API security "
        "scanner running against targets the operator is permitted to test. "
        "Given a vulnerability class and endpoint context, return additional "
        "test payloads that a DAST tool would send to detect the issue. "
        "Return ONLY a JSON array of strings, no prose, no code fences."
    )

    def __init__(self, config: ScanConfig, logger: Any = None):
        self.config = config
        self.log = logger or get_logger("apiscan.llm")
        self._cache: Dict[str, List[str]] = {}
        self._client = None
        api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("LLM_API_KEY")
        self.enabled = bool(config.use_llm and _HAVE_ANTHROPIC and api_key)
        if self.enabled:
            try:
                self._client = AsyncAnthropic(api_key=api_key)
            except Exception as e:  # pragma: no cover
                self.log.warning("llm_init_failed", error=str(e))
                self.enabled = False

    async def generate(
        self,
        category: str,
        context: str,
        seed_payloads: List[str],
        n: Optional[int] = None,
    ) -> List[str]:
        """Return seed payloads augmented with LLM-generated ones (deduped)."""
        if not self.enabled or self._client is None:
            return list(seed_payloads)

        n = n or self.config.llm_max_payloads
        cache_key = f"{category}:{context}:{n}"
        if cache_key in self._cache:
            return _dedupe(seed_payloads + self._cache[cache_key])

        prompt = (
            f"Vulnerability class: {category}\n"
            f"Endpoint context: {context}\n"
            f"Existing seed payloads: {json.dumps(seed_payloads[:8])}\n"
            f"Return up to {n} NEW payloads (strings) that complement the seeds "
            f"for detecting {category}. JSON array only."
        )
        try:
            msg = await self._client.messages.create(
                model=self.config.llm_model,
                max_tokens=1024,
                system=self._SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(
                getattr(block, "text", "") for block in msg.content
                if getattr(block, "type", None) == "text"
            )
            payloads = _parse_json_array(text)
            payloads = [p for p in payloads if isinstance(p, str) and p][:n]
            self._cache[cache_key] = payloads
            self.log.info("llm_payloads", category=category, count=len(payloads))
            return _dedupe(seed_payloads + payloads)
        except Exception as e:
            self.log.warning("llm_generate_failed", category=category, error=str(e))
            return list(seed_payloads)


# --------------------------------------------------------------------------- #
# Ollama local LLM support (Qwen 7B recommended)
# --------------------------------------------------------------------------- #
class OllamaPayloadGenerator:
    """Generate context-aware fuzzing payloads with local Ollama.

    Uses Ollama API (localhost:11434) to run open-source models like Qwen locally.
    Requires Ollama installed and a model pulled (e.g. ``ollama pull qwen:7b``).

    Falls back to static seed payloads if Ollama is unavailable.
    """

    _SYSTEM = (
        "You are a payload generator for APISCAN, an authorized API security "
        "scanner. Given a vulnerability class and endpoint context, return "
        "additional test payloads. Return ONLY a JSON array of strings, no prose."
    )

    def __init__(self, config: ScanConfig, logger: Any = None, model: str = "qwen:7b"):
        self.config = config
        self.log = logger or get_logger("apiscan.ollama")
        self.model = model
        self._cache: Dict[str, List[str]] = {}
        self.enabled = False
        self.base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")

        # Check if Ollama is reachable
        try:
            import httpx
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    model_names = [m.get("name") for m in models]
                    if any(self.model in name for name in model_names):
                        self.enabled = True
                        self.log.info("ollama_ready", model=self.model, url=self.base_url)
                    else:
                        self.log.warning("ollama_model_missing", model=self.model, available=model_names)
                else:
                    self.log.warning("ollama_request_failed", status=resp.status_code)
        except Exception as e:
            self.log.debug("ollama_unavailable", error=str(e))

    async def generate(
        self,
        category: str,
        context: str,
        seed_payloads: List[str],
        n: Optional[int] = None,
    ) -> List[str]:
        """Return seed payloads augmented with Ollama-generated ones (deduped)."""
        if not self.enabled:
            return list(seed_payloads)

        n = n or self.config.llm_max_payloads
        cache_key = f"{category}:{context}:{n}"
        if cache_key in self._cache:
            return _dedupe(seed_payloads + self._cache[cache_key])

        prompt = (
            f"Vulnerability class: {category}\n"
            f"Endpoint context: {context}\n"
            f"Existing seed payloads: {json.dumps(seed_payloads[:8])}\n"
            f"Return up to {n} NEW payloads (strings) that complement the seeds "
            f"for detecting {category}. JSON array only."
        )
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "system": self._SYSTEM,
                        "stream": False,
                    }
                )
                if resp.status_code != 200:
                    self.log.warning("ollama_error", status=resp.status_code, category=category)
                    return list(seed_payloads)

                text = resp.json().get("response", "")
                payloads = _parse_json_array(text)
                payloads = [p for p in payloads if isinstance(p, str) and p][:n]
                self._cache[cache_key] = payloads
                self.log.info("ollama_payloads", category=category, count=len(payloads), model=self.model)
                return _dedupe(seed_payloads + payloads)
        except Exception as e:
            self.log.warning("ollama_generate_failed", category=category, error=str(e))
            return list(seed_payloads)


def _parse_json_array(text: str) -> List[Any]:
    text = (text or "").strip()
    # strip accidental code fences
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        val = json.loads(text)
        if isinstance(val, list):
            return val
    except Exception:
        pass
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if m:
        try:
            val = json.loads(m.group(0))
            if isinstance(val, list):
                return val
        except Exception:
            pass
    return []


# --------------------------------------------------------------------------- #
# LLM backend factory (smart selection)
# --------------------------------------------------------------------------- #
def create_llm_payload_generator(config: ScanConfig, logger: Any = None) -> Any:
    """Create the best available LLM payload generator.

    Priority:
    1. Ollama (local, free, fast) if available and enabled
    2. Claude API (if API key present and enabled)
    3. Falls back to static seed payloads if neither available

    Args:
        config: ScanConfig with llm_backend, use_llm, ollama_model, etc.
        logger: Optional logger instance

    Returns:
        Generator instance (OllamaPayloadGenerator, LLMPayloadGenerator, or stub)
    """
    log = logger or get_logger("apiscan.llm_factory")

    if not config.use_llm:
        # LLM disabled entirely, return stub
        return _StubPayloadGenerator(config, log)

    # Try backend selection
    if config.llm_backend in ("auto", "ollama"):
        # Try Ollama first
        ollama_gen = OllamaPayloadGenerator(config, log, model=config.ollama_model)
        if ollama_gen.enabled:
            log.info("llm_backend_selected", backend="ollama", model=config.ollama_model)
            return ollama_gen
        elif config.llm_backend == "ollama":
            # Explicit Ollama requested but not available
            log.warning("ollama_not_available", model=config.ollama_model)
            return _StubPayloadGenerator(config, log)

    if config.llm_backend in ("auto", "claude"):
        # Try Claude API
        claude_gen = LLMPayloadGenerator(config, log)
        if claude_gen.enabled:
            log.info("llm_backend_selected", backend="claude", model=config.llm_model)
            return claude_gen
        elif config.llm_backend == "claude":
            # Explicit Claude requested but not available
            log.warning("claude_not_available")
            return _StubPayloadGenerator(config, log)

    # No backend available, return stub (falls back to seeds)
    log.info("no_llm_backend_available", using="static_seeds")
    return _StubPayloadGenerator(config, log)


class _StubPayloadGenerator:
    """Stub generator that always returns seed payloads (no LLM)."""

    def __init__(self, config: ScanConfig, logger: Any):
        self.config = config
        self.log = logger or get_logger("apiscan.stub")

    async def generate(
        self,
        category: str,
        context: str,
        seed_payloads: List[str],
        n: Optional[int] = None,
    ) -> List[str]:
        """Return seed payloads unchanged."""
        return list(seed_payloads)


def _dedupe(items: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# --------------------------------------------------------------------------- #
# Passive fingerprinting - balances passive detection vs active scanning
# --------------------------------------------------------------------------- #
class PassiveFingerprinter:
    """Derive server/WAF/cloud signals from a response WITHOUT sending attacks.

    The improved auditors fingerprint a baseline response first, then use the
    result to decide how aggressively to scan and whether a headless browser is
    needed (JS challenge / WAF interstitial).
    """

    _WAF_SIGNS = {
        "cloudflare": ("cf-ray", "cf-cache-status", "__cfduid", "cloudflare"),
        "akamai": ("akamai", "akamaighost", "x-akamai"),
        "aws-waf": ("x-amzn-requestid", "x-amz-cf-id", "awselb"),
        "imperva": ("incap_ses", "visid_incap", "x-iinfo"),
        "f5-bigip": ("bigipserver", "x-waf-event", "ts01"),
        "envoy": ("x-envoy", "server: envoy"),
    }
    _CLOUD_SIGNS = {
        "aws": ("x-amz", "amazon"),
        "gcp": ("x-goog", "gse", "google frontend"),
        "azure": ("x-azure", "x-ms-", "microsoft-azure"),
    }
    _JS_CHALLENGE = ("just a moment", "checking your browser", "enable javascript",
                     "_cf_chl_opt", "challenge-platform", "ddos protection")

    def fingerprint(self, headers: Dict[str, str], body: str) -> Dict[str, Any]:
        hdr_blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        body_low = (body or "")[:8192].lower()

        server = ""
        for k, v in (headers or {}).items():
            if k.lower() == "server":
                server = v
                break

        waf = None
        for name, signs in self._WAF_SIGNS.items():
            if any(s in hdr_blob or s in body_low for s in signs):
                waf = name
                break

        cloud = None
        for name, signs in self._CLOUD_SIGNS.items():
            if any(s in hdr_blob for s in signs):
                cloud = name
                break

        js_challenge = any(s in body_low for s in self._JS_CHALLENGE)
        powered_by = headers.get("x-powered-by", "") if headers else ""

        return {
            "server": server,
            "x_powered_by": powered_by,
            "waf": waf,
            "cloud": cloud,
            "js_challenge": js_challenge,
            "needs_browser": bool(js_challenge or waf in {"cloudflare", "imperva", "akamai"}),
        }

    def recommend(self, fp: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        """Turn a fingerprint into scan-intensity recommendations."""
        use_browser = config.use_browser or (config.browser_auto and fp.get("needs_browser"))
        # Behind an aggressive WAF, throttle to avoid triggering blocks.
        rps = config.rps
        if fp.get("waf"):
            rps = min(rps, 4.0)
        return {"use_browser": bool(use_browser), "rps": rps, "reason": fp}


# --------------------------------------------------------------------------- #
# Playwright probe - headless-browser fetch for JS/WAF endpoints
# --------------------------------------------------------------------------- #
class PlaywrightProbe:
    """Optional headless-browser probe. Lazy-imports Playwright.

    ``available`` is False when Playwright is not installed; callers then skip
    browser probing and stay on httpx.
    """

    def __init__(self, config: ScanConfig, logger: Any = None):
        self.config = config
        self.log = logger or get_logger("apiscan.browser")
        self._pw = None
        self._browser = None
        self.available = False

    async def start(self) -> bool:
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception:
            self.log.info("playwright_unavailable")
            self.available = False
            return False
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=True)
            self.available = True
            return True
        except Exception as e:  # pragma: no cover
            self.log.warning("playwright_launch_failed", error=str(e))
            self.available = False
            return False

    async def fetch(self, url: str, *, wait_ms: int = 2500) -> ProbeResponse:
        """Load ``url`` in a real browser (executes JS, clears WAF interstitials)."""
        if not self.available or self._browser is None:
            return ProbeResponse(0, {}, "", url, 0.0, source="error", error="browser unavailable")
        started = time.perf_counter()
        ctx = None
        try:
            ctx = await self._browser.new_context(ignore_https_errors=not self.config.verify_tls)
            page = await ctx.new_page()
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=int(self.config.timeout * 1000))
            await page.wait_for_timeout(wait_ms)
            body = await page.content()
            status = resp.status if resp else 0
            headers = dict(resp.headers) if resp else {}
            return ProbeResponse(
                status_code=status, headers=headers, text=body,
                url=page.url, elapsed=time.perf_counter() - started, source="browser",
            )
        except Exception as e:
            return ProbeResponse(0, {}, "", url, time.perf_counter() - started, source="error", error=str(e))
        finally:
            if ctx is not None:
                try:
                    await ctx.close()
                except Exception:
                    pass

    async def close(self) -> None:
        try:
            if self._browser is not None:
                await self._browser.close()
            if self._pw is not None:
                await self._pw.stop()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# WebSocket probe - real-time API testing
# --------------------------------------------------------------------------- #
class WebSocketProbe:
    """Real-time WebSocket API tester (lazy-imports ``websockets``)."""

    def __init__(self, config: ScanConfig, logger: Any = None):
        self.config = config
        self.log = logger or get_logger("apiscan.ws")

    @staticmethod
    def to_ws_url(http_url: str, path: Optional[str] = None) -> str:
        u = http_url.replace("https://", "wss://").replace("http://", "ws://")
        if path:
            u = u.rstrip("/") + "/" + path.lstrip("/")
        return u

    async def probe(
        self,
        ws_url: str,
        messages: List[str],
        *,
        headers: Optional[Dict[str, str]] = None,
        collect: int = 3,
    ) -> Dict[str, Any]:
        """Connect, send ``messages``, collect up to ``collect`` responses."""
        try:
            import websockets  # type: ignore
        except Exception:
            return {"ok": False, "error": "websockets not installed", "url": ws_url}

        received: List[str] = []
        try:
            extra = list((headers or {}).items())
            async with websockets.connect(
                ws_url, additional_headers=extra, open_timeout=self.config.timeout
            ) as ws:
                for m in messages:
                    await ws.send(m)
                for _ in range(collect):
                    try:
                        r = await asyncio.wait_for(ws.recv(), timeout=self.config.timeout)
                        received.append(r if isinstance(r, str) else r.decode("utf-8", "replace"))
                    except asyncio.TimeoutError:
                        break
            return {"ok": True, "url": ws_url, "sent": messages, "received": received}
        except TypeError:
            # older websockets used extra_headers=
            try:
                import websockets  # type: ignore

                async with websockets.connect(ws_url, extra_headers=list((headers or {}).items())) as ws:  # type: ignore
                    for m in messages:
                        await ws.send(m)
                    for _ in range(collect):
                        try:
                            r = await asyncio.wait_for(ws.recv(), timeout=self.config.timeout)
                            received.append(r if isinstance(r, str) else r.decode("utf-8", "replace"))
                        except asyncio.TimeoutError:
                            break
                return {"ok": True, "url": ws_url, "sent": messages, "received": received}
            except Exception as e:  # pragma: no cover
                return {"ok": False, "error": str(e), "url": ws_url}
        except Exception as e:
            return {"ok": False, "error": str(e), "url": ws_url}


# --------------------------------------------------------------------------- #
# Vulnerability correlation graph (networkx)
# --------------------------------------------------------------------------- #
class VulnerabilityGraph:
    """Correlate findings across endpoints/params/payloads using a graph.

    Nodes are typed ("endpoint", "param", "payload", "finding"); edges connect a
    finding to the endpoint/param/payload that produced it. Correlation surfaces
    systemic issues - e.g. one parameter vulnerable across many endpoints, or a
    payload family that repeatedly succeeds - which single findings miss.

    Falls back to plain dict aggregation when networkx is not installed.
    """

    def __init__(self):
        self._use_nx = _HAVE_NETWORKX
        self._g = nx.DiGraph() if self._use_nx else None
        self._findings: List[Dict[str, Any]] = []

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self._findings.append(finding)
        if not self._use_nx:
            return
        fid = f"finding:{len(self._findings)}"
        endpoint = finding.get("endpoint") or finding.get("url") or "?"
        param = finding.get("parameter") or finding.get("param") or "-"
        payload = finding.get("payload") or "-"
        sev = finding.get("severity", "Info")

        self._g.add_node(fid, kind="finding", severity=sev, **{"desc": finding.get("description", "")})
        self._g.add_node(f"ep:{endpoint}", kind="endpoint")
        self._g.add_edge(f"ep:{endpoint}", fid, rel="has_finding")
        if param and param != "-":
            self._g.add_node(f"param:{param}", kind="param")
            self._g.add_edge(f"param:{param}", fid, rel="via_param")
        if payload and payload != "-":
            self._g.add_node(f"payload:{payload}", kind="payload")
            self._g.add_edge(f"payload:{payload}", fid, rel="via_payload")

    def correlate(self) -> Dict[str, Any]:
        """Return cross-finding clusters and systemic signals."""
        total = len(self._findings)
        by_severity: Dict[str, int] = {}
        for f in self._findings:
            by_severity[f.get("severity", "Info")] = by_severity.get(f.get("severity", "Info"), 0) + 1

        # Params / payloads that recur across multiple endpoints.
        param_eps: Dict[str, set] = {}
        payload_eps: Dict[str, set] = {}
        for f in self._findings:
            ep = f.get("endpoint") or f.get("url") or "?"
            p = f.get("parameter") or f.get("param")
            pl = f.get("payload")
            if p:
                param_eps.setdefault(p, set()).add(ep)
            if pl:
                payload_eps.setdefault(pl, set()).add(ep)

        systemic_params = sorted(
            ({"param": k, "endpoints": len(v)} for k, v in param_eps.items() if len(v) > 1),
            key=lambda x: x["endpoints"], reverse=True,
        )
        systemic_payloads = sorted(
            ({"payload": k, "endpoints": len(v)} for k, v in payload_eps.items() if len(v) > 1),
            key=lambda x: x["endpoints"], reverse=True,
        )

        result: Dict[str, Any] = {
            "total_findings": total,
            "by_severity": by_severity,
            "systemic_params": systemic_params[:20],
            "systemic_payloads": systemic_payloads[:20],
            "graph_backend": "networkx" if self._use_nx else "dict",
        }
        if self._use_nx and self._g is not None:
            result["nodes"] = self._g.number_of_nodes()
            result["edges"] = self._g.number_of_edges()
            # Endpoints ranked by finding count (in-graph degree of finding edges).
            ep_scores = []
            for n, d in self._g.nodes(data=True):
                if d.get("kind") == "endpoint":
                    ep_scores.append((n[3:], self._g.out_degree(n)))
            result["hotspot_endpoints"] = [
                {"endpoint": e, "findings": c}
                for e, c in sorted(ep_scores, key=lambda x: x[1], reverse=True)[:10]
            ]
        return result

    def export_graphml(self, path: str | Path) -> Optional[Path]:
        if not self._use_nx or self._g is None:
            return None
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            nx.write_graphml(self._g, str(p))
            return p
        except Exception:
            return None


# --------------------------------------------------------------------------- #
# sync <-> async bridge (so apiscan.py can call the improved auditors)
# --------------------------------------------------------------------------- #
def run_async(coro: Awaitable[Any]) -> Any:
    """Run ``coro`` to completion from synchronous code.

    Uses ``asyncio.run`` when no loop is active; falls back to a private loop
    in a worker thread if called from within a running loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # Already inside a loop: run in a dedicated thread with its own loop.
    import threading

    result: Dict[str, Any] = {}

    def _worker() -> None:
        loop = asyncio.new_event_loop()
        try:
            result["value"] = loop.run_until_complete(coro)
        except Exception as e:  # pragma: no cover
            result["error"] = e
        finally:
            loop.close()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


# convenience: capability report for the guide / diagnostics
def capabilities() -> Dict[str, bool]:
    return {
        "httpx": True,
        "pydantic": True,
        "structlog": _HAVE_STRUCTLOG,
        "networkx": _HAVE_NETWORKX,
        "anthropic": _HAVE_ANTHROPIC,
        "playwright": _module_present("playwright"),
        "websockets": _module_present("websockets"),
    }


def _module_present(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


if __name__ == "__main__":
    log = get_logger("apiscan.improved.selftest")
    log.info("capabilities", **capabilities())
