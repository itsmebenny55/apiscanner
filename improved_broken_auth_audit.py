########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                          #
#                                                       #
# improved_broken_auth_audit.py                         #
# Modernized Broken Authentication (OWASP API2) auditor.#
#                                                       #
# Async rewrite of broken_auth_audit.py:                #
#   httpx.AsyncClient + asyncio  (was requests+threads) #
#   LLM-generated credential lists (Claude fuzzing)     #
#   Passive fingerprint -> active scan balance          #
#   WebSocket auth testing (real-time API)              #
#   Playwright fallback for JS/WAF login pages          #
#   networkx finding correlation                        #
#   structlog logging + JSONL streaming                 #
#                                                       #
# Exposes test_authentication_mechanisms()/             #
# generate_report/save_report and a sync entrypoint so  #
# apiscan.py can call it like the legacy AuthAuditor.   #
########################################################
from __future__ import annotations

import asyncio
import base64
import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from report_utils import ReportGenerator

from improved_common import (
    AsyncHTTPClient,
    LLMPayloadGenerator,
    PassiveFingerprinter,
    ProbeResponse,
    ResultStreamer,
    ScanConfig,
    VulnerabilityGraph,
    WebSocketProbe,
    get_logger,
    run_async,
)

_AUTH_PATH_HINTS = ("auth", "login", "token", "signin", "authenticate", "oauth",
                    "saml", "jwt", "oidc", "mfa", "2fa", "sso", "session")
_AUTH_SKIP = ("forget", "reset", "change", "activate", "verify", "confirm", "revoke", "refresh")

_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("test", "test"), ("user", "user"),
    ("administrator", "administrator"), ("guest", "guest"),
]


class AsyncAuthAuditor:
    """Async Broken-Authentication auditor (drop-in for ``AuthAuditor``)."""

    def __init__(
        self,
        session: Any = None,
        *,
        base_url: str,
        swagger_spec: Optional[Dict[str, Any]] = None,
        config: Optional[ScanConfig] = None,
        show_progress: bool = True,
        **kwargs: Any,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/") + "/"
        self._session = session
        self.spec = swagger_spec or {}
        self.show_progress = show_progress
        self.config = config or ScanConfig(
            concurrency=int(kwargs.get("concurrency", 10)),
            rps=float(kwargs.get("rps", 8.0)),
            timeout=float(kwargs.get("timeout", 10.0)),
            use_llm=bool(kwargs.get("use_llm", False)),
        )
        self.log = get_logger("apiscan.auth")
        self.graph = VulnerabilityGraph()
        self.auth_issues: List[Dict[str, Any]] = []
        stream_path = kwargs.get("stream_path") or (
            Path(self.config.output_dir) / "auth_findings.jsonl" if self.config.stream_results else None
        )
        self._streamer = ResultStreamer(stream_path, key_fields=("endpoint", "description"))
        self._fp = PassiveFingerprinter()

    @property
    def _host(self) -> str:
        p = urlparse(self.base_url)
        return p.hostname or p.netloc.split(":")[0]

    @property
    def _port(self) -> int:
        p = urlparse(self.base_url)
        return p.port or (443 if p.scheme == "https" else 80)

    # ---- finding recording ----------------------------------------------- #
    def _log_issue(self, endpoint: str, description: str, severity: str,
                   resp: Optional[ProbeResponse] = None, extra: Optional[dict] = None) -> None:
        entry: Dict[str, Any] = {
            "endpoint": endpoint,
            "url": (resp.url if resp else endpoint),
            "method": (extra or {}).get("method", "GET"),
            "description": description,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status_code": resp.status_code if resp else 0,
            "request_headers": list(resp.request_headers.items()) if resp else [],
            "request_body": resp.request_body if resp else None,
            "response_headers": list(resp.headers.items()) if resp else [],
            "response_body": (resp.text[:2048] if resp else ""),
            "response_cookies": resp.cookies if resp else {},
        }
        if extra:
            entry.update(extra)
        entry["detected_via"] = resp.source if resp else "analysis"
        if self._streamer.emit(entry):
            self.auth_issues.append(entry)
            self.graph.add_finding(entry)
            if self.show_progress:
                self.log.info("auth_finding", endpoint=endpoint, severity=severity, desc=description)

    # ---- endpoint discovery ---------------------------------------------- #
    def _endpoints_from_spec(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        paths = (self.spec or {}).get("paths") or {}
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method, meta in item.items():
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                tags = (meta.get("tags") if isinstance(meta, dict) else None) or []
                out.append({
                    "path": path, "method": method.upper(),
                    "url": urljoin(self.base_url, path.lstrip("/")), "tags": tags,
                })
        return out

    def _select_auth_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        eps: List[Dict[str, Any]] = []
        for ep in endpoints:
            blob = (ep.get("path", "") + " " + " ".join(ep.get("tags", []))).lower()
            if any(k in blob for k in _AUTH_PATH_HINTS) and not any(s in blob for s in _AUTH_SKIP):
                eps.append(ep)
        return eps or endpoints

    # ---- async orchestration --------------------------------------------- #
    async def _run_async(self, swagger_endpoints: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        self.auth_issues.clear()
        endpoints = swagger_endpoints or self._endpoints_from_spec()
        auth_eps = self._select_auth_endpoints(endpoints)

        client = AsyncHTTPClient.from_requests_session(self._session, self.config, logger=self.log) \
            if self._session is not None else AsyncHTTPClient(self.config, logger=self.log)
        try:
            await self._passive_fingerprint(client)
            llm = LLMPayloadGenerator(self.config, logger=self.log)
            creds = await self._credential_list(llm)

            tasks: List[Any] = []
            for ep in auth_eps:
                tasks.append(self._test_weak_credentials(client, ep, creds))
                tasks.append(self._test_rate_limiting(client, ep))
                tasks.append(self._test_jwt_and_tokens(client, ep))
            # broken function-level access: hit protected endpoints without creds
            for ep in endpoints:
                tasks.append(self._test_missing_auth(client, ep))
            await asyncio.gather(*tasks, return_exceptions=True)

            # passive transport checks (no HTTP body)
            self._test_secure_transport()
            self._test_tls_version()

            # WebSocket auth check (feature: real-time API testing)
            await self._test_websocket_auth()
        finally:
            await client.aclose()
            self._streamer.close()
        return self.auth_issues

    async def _passive_fingerprint(self, client: AsyncHTTPClient) -> None:
        resp = await client.request("GET", self.base_url)
        fp = self._fp.fingerprint(resp.headers, resp.text)
        rec = self._fp.recommend(fp, self.config)
        if rec.get("rps") and rec["rps"] < self.config.rps:
            client._limiter._min_gap = 1.0 / float(rec["rps"])
        # passive: token/session cookies without Secure/HttpOnly
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                low = v.lower()
                if "secure" not in low or "httponly" not in low:
                    self._log_issue(self.base_url, "Session cookie missing Secure/HttpOnly flags", "Medium", resp)
        self.log.info("fingerprint", **fp)

    async def _credential_list(self, llm: LLMPayloadGenerator) -> List[tuple]:
        seeds = [f"{u}:{p}" for u, p in _DEFAULT_CREDS]
        expanded = await llm.generate("default/weak API credentials", f"base={self.base_url}", seeds, n=8)
        creds: List[tuple] = []
        for item in expanded:
            if ":" in item:
                u, p = item.split(":", 1)
                creds.append((u, p))
        return creds or _DEFAULT_CREDS

    # ---- individual tests ------------------------------------------------- #
    async def _test_weak_credentials(self, client: AsyncHTTPClient, ep: Dict[str, Any], creds: List[tuple]) -> None:
        url = ep["url"]
        method = ep.get("method", "POST")
        for user, pwd in creds:
            body = {"username": user, "password": pwd}
            resp = await client.request(method if method in {"POST", "PUT"} else "POST", url, json_body=body)
            if not resp.ok:
                continue
            low = (resp.text or "").lower()
            if 200 <= resp.status_code < 300 and any(t in low for t in ("token", "jwt", "session", "access_token", '"success":true')):
                self._log_issue(url, f"Weak/default credentials accepted: {user}:{pwd}", "High", resp, {"method": method})
                return

    async def _test_rate_limiting(self, client: AsyncHTTPClient, ep: Dict[str, Any]) -> None:
        url = ep["url"]
        method = ep.get("method", "POST")
        burst = 15
        tasks = [
            client.request(method if method in {"POST", "PUT"} else "POST", url,
                           json_body={"username": "ratelimit_probe", "password": f"x{i}"})
            for i in range(burst)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        statuses = [r.status_code for r in responses if isinstance(r, ProbeResponse) and r.ok]
        if statuses and 429 not in statuses and all(s < 400 or s in (401, 403) for s in statuses):
            # no 429 across a burst of auth attempts
            self._log_issue(url, f"No rate limiting on auth endpoint ({len(statuses)} rapid attempts, no HTTP 429)", "Medium",
                            extra={"method": method})

    async def _test_jwt_and_tokens(self, client: AsyncHTTPClient, ep: Dict[str, Any]) -> None:
        url = ep["url"]
        method = ep.get("method", "POST")
        resp = await client.request(method if method in {"POST", "PUT"} else "POST", url,
                                    json_body={"username": "test", "password": "test"})
        if not resp.ok:
            return
        token = self._extract_jwt(resp.text) or self._extract_jwt(json.dumps(dict(resp.headers)))
        if not token:
            return
        analysis = self._analyze_jwt(token)
        if analysis.get("alg_none"):
            self._log_issue(url, "JWT accepts 'alg:none' (unsigned tokens)", "High", resp, {"method": method})
        if analysis.get("weak_alg"):
            self._log_issue(url, f"JWT uses weak algorithm: {analysis['weak_alg']}", "Medium", resp, {"method": method})
        if analysis.get("no_exp"):
            self._log_issue(url, "JWT has no expiry (exp) claim", "Medium", resp, {"method": method})

    async def _test_missing_auth(self, client: AsyncHTTPClient, ep: Dict[str, Any]) -> None:
        """Broken authentication: protected-looking endpoint returns data with no creds."""
        blob = ep.get("path", "").lower()
        if not any(k in blob for k in ("admin", "account", "profile", "user", "order", "me", "private", "settings")):
            return
        url = ep["url"]
        method = ep.get("method", "GET")
        if method != "GET":
            return
        # Strip Authorization for this probe.
        resp = await client.request("GET", url, headers={"Authorization": ""})
        if resp.ok and 200 <= resp.status_code < 300 and len(resp.text or "") > 2:
            low = (resp.text or "").lower()
            if any(h in low for h in ("email", "user", "id", "name", "token", "role")):
                self._log_issue(url, "Protected endpoint returns data without authentication", "High", resp, {"method": "GET"})

    async def _test_websocket_auth(self) -> None:
        """Check whether a WebSocket endpoint accepts unauthenticated connections."""
        ws = WebSocketProbe(self.config, logger=self.log)
        for path in ("/ws", "/websocket", "/socket", "/api/ws"):
            ws_url = WebSocketProbe.to_ws_url(self.base_url, path)
            result = await ws.probe(ws_url, ['{"action":"ping"}'], collect=1)
            if result.get("ok") and result.get("received"):
                self._log_issue(ws_url, "WebSocket endpoint accepts unauthenticated connection", "High",
                                extra={"method": "WS", "ws_response": result["received"][:1]})
                return

    # ---- passive transport checks ---------------------------------------- #
    def _test_secure_transport(self) -> None:
        if urlparse(self.base_url).scheme != "https":
            self._log_issue(self.base_url, "API served over plaintext HTTP (no TLS)", "High")

    def _test_tls_version(self) -> None:
        if urlparse(self.base_url).scheme != "https":
            return
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self._host, self._port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self._host) as ss:
                    ver = ss.version()
                    if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self._log_issue(self.base_url, f"Weak TLS version negotiated: {ver}", "High")
        except Exception as e:
            self.log.debug("tls_check_failed", error=str(e))

    # ---- JWT helpers ------------------------------------------------------ #
    @staticmethod
    def _extract_jwt(text: str) -> Optional[str]:
        import re
        m = re.search(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", text or "")
        return m.group(0) if m else None

    @staticmethod
    def _analyze_jwt(token: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        try:
            header_b64 = token.split(".")[0]
            payload_b64 = token.split(".")[1]
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
            alg = str(header.get("alg", "")).lower()
            out["alg_none"] = alg == "none"
            out["weak_alg"] = header.get("alg") if alg in ("hs256",) else None
            out["no_exp"] = "exp" not in payload
        except Exception:
            pass
        return out

    # ---- public API (compatible with legacy AuthAuditor) ----------------- #
    async def test_authentication_mechanisms_async(self, swagger_endpoints: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        return await self._run_async(swagger_endpoints)

    def test_authentication_mechanisms(self, swagger_endpoints: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Synchronous wrapper so apiscan.py can call it like the legacy auditor."""
        return run_async(self._run_async(swagger_endpoints))

    def correlation(self) -> Dict[str, Any]:
        return self.graph.correlate()

    def _report_issues(self) -> List[dict]:
        if self.auth_issues:
            return self.auth_issues
        return [{
            "endpoint": "-", "description": "No broken-authentication findings detected",
            "severity": "Info", "status_code": 200, "timestamp": datetime.now(timezone.utc).isoformat(),
        }]

    def generate_report(self, fmt: str = "markdown") -> str:
        gen = ReportGenerator(self._report_issues(), scanner="Broken Auth (API2) [improved]", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "markdown") -> None:
        gen = ReportGenerator(self._report_issues(), scanner="Broken Auth (API2) [improved]", base_url=self.base_url)
        if fmt == "html":
            gen.save(path)
        else:
            Path(path).write_text(gen.generate_markdown(), encoding="utf-8")


# Legacy alias.
AuthAuditor = AsyncAuthAuditor


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Modernized async Broken-Auth auditor")
    ap.add_argument("--url", required=True)
    ap.add_argument("--swagger")
    ap.add_argument("--use-llm", action="store_true")
    ap.add_argument("--report", default="auth_report.html")
    args = ap.parse_args()

    spec = {}
    if args.swagger:
        raw = Path(args.swagger).read_text(encoding="utf-8")
        try:
            spec = json.loads(raw)
        except Exception:
            import yaml
            spec = yaml.safe_load(raw) or {}

    cfg = ScanConfig(use_llm=args.use_llm)
    auditor = AsyncAuthAuditor(base_url=args.url, swagger_spec=spec, config=cfg)
    issues = auditor.test_authentication_mechanisms()
    auditor.save_report(args.report, fmt="html")
    print(json.dumps({"findings": len(issues), "correlation": auditor.correlation()}, indent=2))
