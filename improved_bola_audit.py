########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                          #
#                                                       #
# improved_bola_audit.py                                #
# Modernized BOLA / IDOR (OWASP API1) auditor.          #
#                                                       #
# Async rewrite of bola_audit.py:                       #
#   httpx.AsyncClient + asyncio  (was requests+threads) #
#   LLM-generated object-id candidates (Claude fuzzing) #
#   Passive fingerprint -> active scan balance          #
#   Playwright fallback for JS/WAF endpoints            #
#   networkx finding correlation                        #
#   structlog logging + JSONL streaming                 #
#                                                       #
# Reuses TestResult + classify_risk from bola_audit for #
# identical report output; exposes run()/generate_report#
# /save_report and a sync entrypoint for apiscan.py.    #
########################################################
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from report_utils import ReportGenerator

# Reuse the legacy result model + risk classifier for report parity.
from bola_audit import TestResult, classify_risk

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


# object-id path segment: /users/{id}, /orders/{orderId}, or numeric /users/42
_TEMPLATE_ID_RE = re.compile(r"\{([^}]+)\}")
_NUMERIC_SEG_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_SENSITIVE_HINTS = (
    "password", "passwd", "secret", "token", "ssn", "social security",
    "credit", "card_number", "cardnumber", "iban", "api_key", "apikey",
    "private_key", "email", "phone", "address", "date_of_birth", "dob",
)


class AsyncBOLAAuditor:
    """Async BOLA / IDOR auditor (drop-in for ``BOLAAuditor``)."""

    def __init__(
        self,
        *args: Any,
        session: Any = None,
        base_url: Optional[str] = None,
        swagger_spec: Optional[Dict[str, Any]] = None,
        config: Optional[ScanConfig] = None,
        show_subbars: bool = True,
        **kwargs: Any,
    ) -> None:
        if base_url is None and args:
            for a in args:
                if isinstance(a, str) and base_url is None:
                    base_url = a
                elif session is None and not isinstance(a, str):
                    session = a
        if not base_url:
            raise ValueError("base_url is required")

        if "://" not in base_url:
            base_url = "http://" + base_url
        self.base_url = base_url.rstrip("/") + "/"
        self._session = session
        self.swagger_spec = swagger_spec or {}
        self.show_progress = show_subbars
        self.config = config or ScanConfig(
            concurrency=int(kwargs.get("concurrency", 12)),
            rps=float(kwargs.get("rps", 10.0)),
            timeout=float(kwargs.get("timeout", 15.0)),
            use_llm=bool(kwargs.get("use_llm", False)),
            use_browser=bool(kwargs.get("use_browser", False)),
        )
        self.log = get_logger("apiscan.bola")
        self.graph = VulnerabilityGraph()
        self.results: List[TestResult] = []
        self.issues: List[dict] = []
        stream_path = kwargs.get("stream_path") or (
            Path(self.config.output_dir) / "bola_findings.jsonl" if self.config.stream_results else None
        )
        self._streamer = ResultStreamer(stream_path, key_fields=("url", "method", "description"))
        self._fp = PassiveFingerprinter()
        self._recommend: Dict[str, Any] = {}
        # baselines keyed by canonical endpoint -> (id_value, response shape)
        self._baselines: Dict[str, Dict[str, Any]] = {}

    # ---- endpoint discovery ---------------------------------------------- #
    def _abs_url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return urljoin(self.base_url, path.lstrip("/"))

    def get_object_endpoints(self, spec: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        spec = spec or self.swagger_spec or {}
        paths = spec.get("paths") or {}
        out: List[Dict[str, Any]] = []
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            id_params = _TEMPLATE_ID_RE.findall(path)
            if not id_params and not self._is_bola_candidate(path):
                continue
            for method, meta in item.items():
                if method.upper() not in {"GET", "PUT", "PATCH", "DELETE"}:
                    continue
                params = []
                if isinstance(item.get("parameters"), list):
                    params.extend(item["parameters"])
                if isinstance(meta, dict) and isinstance(meta.get("parameters"), list):
                    params.extend(meta["parameters"])
                out.append({
                    "method": method.upper(),
                    "path": path,
                    "url": self._abs_url(path),
                    "id_params": id_params,
                    "parameters": params,
                })
        return out

    @staticmethod
    def _is_bola_candidate(path: str) -> bool:
        segs = [s for s in path.split("/") if s]
        return any(_NUMERIC_SEG_RE.match(s) or _UUID_RE.match(s) for s in segs)

    # ---- id candidate generation ----------------------------------------- #
    async def _id_candidates(self, llm: LLMPayloadGenerator, endpoint: Dict[str, Any]) -> List[str]:
        """Derive object-id values to try in place of the owner's id."""
        seeds = ["1", "2", "0", "1000", "9999", "00000000-0000-0000-0000-000000000001",
                 "admin", "me", "-1", "999999999"]
        ctx = f"path={endpoint['path']} id_params={endpoint.get('id_params')}"
        return await llm.generate("BOLA/IDOR object identifier", ctx, seeds, n=8)

    # ---- scanning -------------------------------------------------------- #
    async def _run_async(self, spec: Optional[Dict[str, Any]] = None) -> List[TestResult]:
        self.results.clear()
        self.issues.clear()
        endpoints = self.get_object_endpoints(spec or self.swagger_spec)
        client = AsyncHTTPClient.from_requests_session(self._session, self.config, logger=self.log) \
            if self._session is not None else AsyncHTTPClient(self.config, logger=self.log)
        browser: Optional[PlaywrightProbe] = None
        try:
            await self._passive_fingerprint(client)
            if self._recommend.get("use_browser"):
                browser = PlaywrightProbe(self.config, logger=self.log)
                await browser.start()
            llm = LLMPayloadGenerator(self.config, logger=self.log)
            self.log.info("bola_targets", endpoints=len(endpoints), llm=llm.enabled)

            tasks = [self._scan_endpoint(client, browser, llm, ep) for ep in endpoints]
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await client.aclose()
            if browser is not None:
                await browser.close()
            self._streamer.close()
        return self.results

    async def _passive_fingerprint(self, client: AsyncHTTPClient) -> None:
        resp = await client.request("GET", self.base_url)
        fp = self._fp.fingerprint(resp.headers, resp.text)
        self._recommend = self._fp.recommend(fp, self.config)
        if self._recommend.get("rps") and self._recommend["rps"] < self.config.rps:
            client._limiter._min_gap = 1.0 / float(self._recommend["rps"])
        self.log.info("fingerprint", **fp)

    async def _scan_endpoint(
        self,
        client: AsyncHTTPClient,
        browser: Optional[PlaywrightProbe],
        llm: LLMPayloadGenerator,
        endpoint: Dict[str, Any],
    ) -> None:
        method = endpoint["method"]
        candidates = await self._id_candidates(llm, endpoint)

        # Establish a baseline with the first candidate (the "owner" view).
        baseline_id = candidates[0] if candidates else "1"
        baseline_url = self._materialize(endpoint, baseline_id)
        baseline_resp = await client.request(method, baseline_url)
        baseline_shape = self._json_shape(baseline_resp.text)
        self._baselines[endpoint["path"]] = {
            "id": baseline_id, "status": baseline_resp.status_code, "shape": baseline_shape,
            "len": len(baseline_resp.text or ""),
        }

        tasks = []
        for cid in candidates[1:]:
            tasks.append(self._probe_id(client, browser, endpoint, cid, baseline_resp))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _materialize(self, endpoint: Dict[str, Any], id_value: str) -> str:
        """Replace the object-id in the path/URL with a candidate value."""
        url = endpoint["url"]
        id_params = endpoint.get("id_params") or []
        if id_params:
            for p in id_params:
                url = url.replace(f"{{{p}}}", id_value)
            return url
        # numeric/uuid segment substitution
        parts = urlparse(url)
        segs = parts.path.split("/")
        for i, s in enumerate(segs):
            if _NUMERIC_SEG_RE.match(s) or _UUID_RE.match(s):
                segs[i] = id_value
                break
        new_path = "/".join(segs)
        return f"{parts.scheme}://{parts.netloc}{new_path}" + (f"?{parts.query}" if parts.query else "")

    async def _probe_id(
        self,
        client: AsyncHTTPClient,
        browser: Optional[PlaywrightProbe],
        endpoint: Dict[str, Any],
        id_value: str,
        baseline_resp: ProbeResponse,
    ) -> None:
        method = endpoint["method"]
        url = self._materialize(endpoint, id_value)
        cache_key = f"{method}|{url}"
        resp = await client.request(method, url, cache_key=cache_key)
        if not resp.ok:
            return
        if browser is not None and browser.available and method == "GET" and resp.status_code in (403, 429, 503):
            b = await browser.fetch(url)
            if b.ok:
                resp = b

        self._evaluate(endpoint, id_value, resp, baseline_resp)

    def _evaluate(self, endpoint: Dict[str, Any], id_value: str, resp: ProbeResponse, baseline: ProbeResponse) -> None:
        method = endpoint["method"]
        status = resp.status_code
        body = resp.text or ""

        # Cross-user access heuristic: a different object id returns 2xx with a
        # response shape matching the baseline object (i.e. we read someone
        # else's record) and non-trivial content.
        same_shape = self._json_shape(body) == self._json_shape(baseline.text or "")
        cross_user = (
            200 <= status < 300
            and same_shape
            and len(body) > 0
            and not self._is_generic_success(body)
        )
        sensitive = self._detect_sensitive(body)
        true_positive = cross_user or (200 <= status < 300 and sensitive)

        if not true_positive:
            return

        note = f"Possible BOLA/IDOR: object id '{id_value}' returned {status} with " + (
            "matching record shape" if cross_user else "sensitive data"
        )
        tr = TestResult(
            test_case=note,
            method=method,
            url=resp.url,
            status_code=status,
            response_time=round(resp.elapsed, 3),
            is_vulnerable=True,
            response_sample=body[: self.config.response_body_limit],
            request_sample=resp.request_body or "",
            params={"object_id": id_value},
            headers=list(resp.request_headers.items()),
            response_headers=list(resp.headers.items()),
            response_cookies=resp.cookies,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sensitive_hit=sensitive,
            cross_user=cross_user,
            true_positive=True,
        )
        issue = tr.to_dict()
        issue.setdefault("parameter", "object_id")
        issue.setdefault("payload", id_value)
        issue["detected_via"] = resp.source
        if self._streamer.emit(issue):
            self.results.append(tr)
            self.issues.append(issue)
            self.graph.add_finding(issue)
            if self.show_progress:
                self.log.info("bola_finding", url=resp.url, id=id_value, cross_user=cross_user, sensitive=sensitive, via=resp.source)

    # ---- helpers --------------------------------------------------------- #
    def _json_shape(self, text: str) -> str:
        if not text:
            return ""
        try:
            data = json.loads(text)
        except Exception:
            return re.sub(r"\s+", " ", text).strip()[:512]

        def norm(v: Any) -> Any:
            if isinstance(v, dict):
                return {k: norm(x) for k, x in sorted(v.items())
                        if k not in {"timestamp", "time", "date", "requestId", "request_id"}}
            if isinstance(v, list):
                return [norm(v[0])] if v else []
            if isinstance(v, str):
                return "S"
            if isinstance(v, bool):
                return "B"
            if isinstance(v, (int, float)):
                return "N"
            return "null" if v is None else "X"

        try:
            return json.dumps(norm(data), separators=(",", ":"), ensure_ascii=False)[:4096]
        except Exception:
            return ""

    @staticmethod
    def _is_generic_success(text: str) -> bool:
        low = (text or "").strip().lower()
        if len(low) < 3:
            return True
        for marker in ('{"success":true}', '{"status":"ok"}', "ok", '{"result":null}', "[]", "{}"):
            if low == marker:
                return True
        return False

    @staticmethod
    def _detect_sensitive(text: str) -> bool:
        low = (text or "")[:8192].lower()
        return any(h in low for h in _SENSITIVE_HINTS)

    # ---- public API (compatible with legacy BOLAAuditor) ----------------- #
    async def run_async(self, spec: Optional[Dict[str, Any]] = None) -> List[TestResult]:
        return await self._run_async(spec)

    def run(self, swagger_spec: Optional[Dict[str, Any]] = None) -> List[TestResult]:
        """Synchronous wrapper so apiscan.py can call it like the legacy auditor."""
        return run_async(self._run_async(swagger_spec))

    def correlation(self) -> Dict[str, Any]:
        return self.graph.correlate()

    def _report_issues(self) -> List[dict]:
        if self.issues:
            return self.issues
        return [{
            "endpoint": "-", "url": "-", "method": "GET",
            "description": "No BOLA/IDOR findings detected", "severity": "Info",
            "status_code": 200, "timestamp": datetime.now(timezone.utc).isoformat(),
        }]

    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(self._report_issues(), scanner="BOLA (API1) [improved]", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "html") -> None:
        gen = ReportGenerator(self._report_issues(), scanner="BOLA (API1) [improved]", base_url=self.base_url)
        if fmt == "markdown":
            Path(path).write_text(gen.generate_markdown(), encoding="utf-8")
        else:
            gen.save(path)


# Legacy alias.
BOLAAuditor = AsyncBOLAAuditor


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Modernized async BOLA/IDOR auditor")
    ap.add_argument("--url", required=True)
    ap.add_argument("--swagger")
    ap.add_argument("--use-llm", action="store_true")
    ap.add_argument("--use-browser", action="store_true")
    ap.add_argument("--report", default="bola_report.html")
    args = ap.parse_args()

    spec = {}
    if args.swagger:
        raw = Path(args.swagger).read_text(encoding="utf-8")
        try:
            spec = json.loads(raw)
        except Exception:
            import yaml
            spec = yaml.safe_load(raw) or {}

    cfg = ScanConfig(use_llm=args.use_llm, use_browser=args.use_browser)
    auditor = AsyncBOLAAuditor(base_url=args.url, swagger_spec=spec, config=cfg)
    results = auditor.run(spec)
    auditor.save_report(args.report, fmt="html")
    print(json.dumps({"findings": len(results), "correlation": auditor.correlation()}, indent=2))
