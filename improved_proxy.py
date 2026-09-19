#!/usr/bin/env python3
########################################################
# Improved Proxy Management - IPRoyal + Domain Bypass  #
# Residential proxy rotation with selective bypass     #
########################################################
"""
Residential proxy support with intelligent domain-based routing.

Features:
- IPRoyal gateway integration (residential proxy rotation)
- Automatic IP rotation per-request or per-endpoint
- Domain-based bypass (e.g., .gov domains use direct connection)
- Sticky session support (same IP for correlated requests)
- Automatic failover (proxy unavailable → direct)
- Health tracking and rate-limit detection
"""

import asyncio
import logging
import time
from typing import Optional, Dict, List, Set, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import os

logger = logging.getLogger("apiscan.proxy")


@dataclass
class ProxyConfig:
    """IPRoyal proxy configuration."""
    # Gateway auth
    username: str
    password: str
    gateway_url: str = "http://geo.iproyal.com:12321"

    # Routing
    rotation_strategy: str = "per-request"  # "per-request", "per-endpoint", "sticky"
    bypass_domains: Set[str] = field(default_factory=lambda: {".gov", ".gov.vn"})
    fallback_to_direct: bool = True

    # Health
    check_interval: float = 300.0  # 5 min
    max_failures: int = 3
    timeout: float = 10.0


class IPRoyalProxyManager:
    """Manages IPRoyal residential proxies with domain-based routing."""

    def __init__(self, config: ProxyConfig, logger_inst: Optional[Any] = None):
        self.config = config
        self.log = logger_inst or logger

        self._last_ip = None
        self._endpoint_ips: Dict[str, str] = {}  # Sticky: endpoint → IP
        self._ip_failures: Dict[str, int] = {}
        self._last_health_check = 0.0
        self._enabled = False

        # Validate config
        if not config.username or not config.password:
            self.log.warning("iproyal_no_auth", msg="Username/password not configured")
            return

        self._enabled = True
        self.log.info("iproyal_ready",
                     gateway=config.gateway_url,
                     strategy=config.rotation_strategy,
                     bypass=config.bypass_domains)

    def should_bypass(self, url: str) -> bool:
        """Check if URL should bypass proxy (direct connection)."""
        if not self._enabled or not url:
            return True

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()

            # Check bypass domains
            for bypass_domain in self.config.bypass_domains:
                bypass_domain_lower = bypass_domain.lower()
                # Match: exact hostname OR hostname.endswith(domain)
                if hostname == bypass_domain_lower or hostname.endswith(bypass_domain_lower):
                    self.log.debug("proxy_bypass", url=hostname, reason="bypass_domain")
                    return True

            return False
        except Exception as e:
            self.log.warning("bypass_check_failed", url=url, error=str(e))
            return True

    def get_proxy_url(self, url: str) -> Optional[str]:
        """Get proxy URL for request (or None for direct)."""
        if self.should_bypass(url):
            return None

        if not self._enabled:
            return None

        try:
            parsed = urlparse(url)
            endpoint = parsed.hostname or "default"

            # Get IP for this request
            ip = None
            if self.config.rotation_strategy == "sticky":
                # Same IP per endpoint
                if endpoint not in self._endpoint_ips:
                    ip = self._get_random_ip()
                    self._endpoint_ips[endpoint] = ip
                else:
                    ip = self._endpoint_ips[endpoint]
            else:
                # New IP per request (or per-endpoint tracking)
                ip = self._get_random_ip()

            if not ip:
                self.log.warning("iproyal_no_ip", endpoint=endpoint)
                return None

            # Format: http://username:password@ip:port
            proxy_url = f"http://{self.config.username}:{self.config.password}@{ip}:12321"
            return proxy_url

        except Exception as e:
            self.log.warning("proxy_url_failed", url=url, error=str(e))
            return None

    def _get_random_ip(self) -> Optional[str]:
        """Get next residential IP (rotates through gateway)."""
        # In real implementation, this would call IPRoyal API
        # For now, returns gateway URL which IPRoyal gateway handles
        # The gateway handles IP rotation internally
        return self.config.gateway_url.split("://")[1].split(":")[0]

    def record_failure(self, ip: str, url: str = "") -> None:
        """Record failed request, update health tracking."""
        if not self._enabled:
            return

        self._ip_failures[ip] = self._ip_failures.get(ip, 0) + 1

        if self._ip_failures[ip] >= self.config.max_failures:
            self.log.warning("iproyal_blocked",
                           ip=ip,
                           failures=self._ip_failures[ip],
                           url=url)

    def record_success(self, ip: str) -> None:
        """Record successful request, reset failure count."""
        if ip in self._ip_failures:
            del self._ip_failures[ip]

    async def health_check(self) -> bool:
        """Verify proxy connectivity (throttled)."""
        if not self._enabled:
            return True

        now = time.time()
        if now - self._last_health_check < self.config.check_interval:
            return True

        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                proxy = f"http://{self.config.username}:{self.config.password}@{self.config.gateway_url.split('://')[-1]}"
                resp = await client.get("http://ipinfo.io/json", proxy=proxy)

                if resp.status_code == 200:
                    data = resp.json()
                    self._last_ip = data.get("ip")
                    self.log.info("iproyal_health_ok", ip=self._last_ip)
                    self._last_health_check = now
                    return True
                else:
                    self.log.warning("iproyal_health_failed", status=resp.status_code)
                    return False
        except Exception as e:
            self.log.warning("iproyal_health_error", error=str(e))
            return False


class DomainBypassRouter:
    """Routes traffic based on domain - proxy for external, direct for internal/gov."""

    def __init__(self,
                 proxy_manager: Optional[IPRoyalProxyManager] = None,
                 bypass_domains: Optional[Set[str]] = None):
        self.proxy_manager = proxy_manager
        self.bypass_domains = bypass_domains or {".gov", ".gov.vn", ".internal", "localhost"}
        self.log = logger

    def get_proxy(self, url: str) -> Optional[str]:
        """Get proxy for URL, or None for direct connection."""
        if not url:
            return None

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            # Check bypass domains first
            for domain in self.bypass_domains:
                if hostname.endswith(domain):
                    self.log.debug("route_direct", hostname=hostname)
                    return None

            # Route through proxy if available
            if self.proxy_manager:
                return self.proxy_manager.get_proxy_url(url)

            return None
        except Exception as e:
            self.log.warning("routing_failed", url=url, error=str(e))
            return None


# ============================================================================
# Integration with AsyncHTTPClient
# ============================================================================

def create_proxy_manager_from_env() -> Optional[IPRoyalProxyManager]:
    """Create IPRoyalProxyManager from environment variables."""
    username = os.getenv("IPROYAL_USERNAME")
    password = os.getenv("IPROYAL_PASSWORD")
    gateway = os.getenv("IPROYAL_GATEWAY", "http://geo.iproyal.com:12321")

    if not username or not password:
        logger.debug("iproyal_env_empty", msg="IPROYAL_USERNAME/PASSWORD not set")
        return None

    config = ProxyConfig(
        username=username,
        password=password,
        gateway_url=gateway,
        rotation_strategy=os.getenv("IPROYAL_ROTATION", "per-request"),
    )

    return IPRoyalProxyManager(config)


if __name__ == "__main__":
    # Example usage
    import sys

    print("IPRoyal Proxy Manager - Test")
    print("=" * 70)

    # Create config
    config = ProxyConfig(
        username=os.getenv("IPROYAL_USERNAME", "test_user"),
        password=os.getenv("IPROYAL_PASSWORD", "test_pass"),
        gateway_url="http://geo.iproyal.com:12321",
        bypass_domains={".gov", ".gov.vn"}
    )

    # Create manager
    manager = IPRoyalProxyManager(config)

    # Test routing
    test_urls = [
        "https://api.example.com/users",        # Should use proxy
        "https://api.gov.vn/data",               # Should bypass
        "https://customs.gov.vn/api",            # Should bypass
        "http://localhost:8080/test",            # Should bypass
    ]

    print("\nRouting tests:")
    for url in test_urls:
        proxy = manager.get_proxy_url(url)
        bypass = manager.should_bypass(url)
        print(f"  {url}")
        print(f"    Bypass: {bypass}, Proxy: {proxy}")

    print("\n✓ IPRoyal proxy manager ready")
    print("Usage:")
    print("  export IPROYAL_USERNAME=your_username")
    print("  export IPROYAL_PASSWORD=your_password")
    print("  python3 apiscan.py --url https://api.example.com")
