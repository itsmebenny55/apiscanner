# IPRoyal Residential Proxy Setup

## Overview

IPRoyal residential proxy integration with smart domain-based routing:

- **Automatic proxy rotation** — Different IP per request
- **Domain bypass** — .gov/.gov.vn domains use direct connection
- **Sticky sessions** — Same IP for correlated requests (optional)
- **Graceful fallback** — Direct connection if proxy unavailable
- **Health tracking** — Monitor proxy status and rotate on failure

Perfect for VN government API testing where you need:
1. Real residential IPs for external targets
2. Direct connection for legitimate government APIs

---

## Quick Start (2 minutes)

### 1. Get IPRoyal Credentials

```bash
# Sign up at https://iproyal.com
# Get your gateway URL and credentials from dashboard
# Example: geo.iproyal.com with port 12321
```

### 2. Set Environment Variables

```bash
export IPROYAL_USERNAME="your_username"
export IPROYAL_PASSWORD="your_password"
export IPROYAL_GATEWAY="http://geo.iproyal.com:12321"
export IPROYAL_ROTATION="per-request"  # or "per-endpoint", "sticky"
```

### 3. Run apiscan

```bash
python3 apiscan.py --url https://api.example.com
```

**That's it!** Automatically routes:
- External targets → Through residential proxy
- .gov/.gov.vn → Direct connection (bypass)

---

## How It Works

### Domain-Based Routing

```
Request to: https://api.example.com
  → Route through IPRoyal proxy (residential IP)

Request to: https://api.gov.vn/data
  → Direct connection (bypass, no proxy)

Request to: https://customs.gov.vn
  → Direct connection (bypass, no proxy)
```

### IP Rotation Strategies

#### Per-Request (Default) ⭐
```python
config.rotation_strategy = "per-request"
```
- Different IP for each request
- Most realistic (varied IPs)
- Best for avoiding rate limits

#### Per-Endpoint
```python
config.rotation_strategy = "per-endpoint"
```
- Same IP for all requests to same domain
- Useful for maintaining context
- Better for stateful APIs

#### Sticky Sessions
```python
config.rotation_strategy = "sticky"
```
- Same IP until manually rotated
- For correlated request chains
- Session continuity guaranteed

### Configuration

**Via environment:**
```bash
export IPROYAL_USERNAME="user"
export IPROYAL_PASSWORD="pass"
export IPROYAL_GATEWAY="http://geo.iproyal.com:12321"
export IPROYAL_ROTATION="per-request"
```

**Via code:**
```python
from improved_proxy import ProxyConfig, IPRoyalProxyManager

config = ProxyConfig(
    username="your_username",
    password="your_password",
    gateway_url="http://geo.iproyal.com:12321",
    rotation_strategy="per-request",
    bypass_domains={".gov", ".gov.vn", ".internal"},
    fallback_to_direct=True
)

proxy_mgr = IPRoyalProxyManager(config)
```

**Integrate with auditors:**
```python
from improved_common import AsyncHTTPClient, ScanConfig
from improved_proxy import create_proxy_manager_from_env

config = ScanConfig(...)
proxy_mgr = create_proxy_manager_from_env()

client = AsyncHTTPClient(
    config,
    proxy_manager=proxy_mgr
)
```

---

## Custom Bypass Domains

### Default Bypass Domains
```python
{".gov", ".gov.vn", ".internal", "localhost"}
```

### Add Custom Domains
```bash
# Via environment (comma-separated)
export IPROYAL_BYPASS_DOMAINS=".gov,.gov.vn,.internal,.local"
```

```python
# Via config
config = ProxyConfig(
    username="user",
    password="pass",
    bypass_domains={
        ".gov",
        ".gov.vn",
        ".internal",
        ".local",
        "*.example.com",  # Custom
    }
)
```

### Remove Bypass
```python
config = ProxyConfig(
    username="user",
    password="pass",
    bypass_domains=set()  # No bypass, proxy everything
)
```

---

## Rotation Strategies

### Per-Request (Recommended)
```python
rotation_strategy = "per-request"
```

**Behavior:**
- New IP for each HTTP request
- Most varied IP profile
- Best for avoiding WAF rate limits
- Realistic browsing behavior

**Use for:**
- General reconnaissance
- Avoiding rate limits
- Evading IP-based blocks

**Example:**
```
Request 1: 203.0.113.1 (proxy 1)
Request 2: 203.0.113.45 (proxy 2)
Request 3: 203.0.113.89 (proxy 3)
```

### Per-Endpoint
```python
rotation_strategy = "per-endpoint"
```

**Behavior:**
- Same IP per domain
- Different domains get different IPs
- Maintains endpoint affinity

**Use for:**
- Multi-endpoint API testing
- Avoiding per-domain rate limits
- Testing endpoint-specific logic

**Example:**
```
Requests to api.com: 203.0.113.1 (proxy 1)
Requests to users.com: 203.0.113.45 (proxy 2)
```

### Sticky Sessions
```python
rotation_strategy = "sticky"
```

**Behavior:**
- Same IP for entire session
- No rotation until restarted
- Complete session continuity

**Use for:**
- Authentication flows (login → API calls)
- Session-dependent testing
- Correlation tracking

**Example:**
```
Session 1: 203.0.113.1 (all requests)
Session 2: 203.0.113.45 (all requests)
```

---

## Performance Considerations

### Connection Pooling
```python
# Proxy manager reuses connections
config = ScanConfig(concurrency=10)  # 10 concurrent requests
# Each goes through different IP, same connection pool
```

### Rate Limiting
```python
config = ScanConfig(rps=15.0)  # 15 requests/second
# IPRoyal applies gateway-level rate limits
# Respect residential proxy quotas
```

### Memory Usage
```python
# Per-request rotation: minimal memory (no tracking)
# Per-endpoint: stores endpoint→IP mappings
# Sticky: stores session→IP mapping
```

---

## Troubleshooting

### "Connection refused"
```bash
# Check IPRoyal gateway is accessible
curl http://geo.iproyal.com:12321

# Verify credentials
echo "IPROYAL_USERNAME=$IPROYAL_USERNAME"
echo "IPROYAL_PASSWORD=$IPROYAL_PASSWORD"
```

### "No proxy available"
```bash
# Check quota
# Log in to IPRoyal dashboard
# Verify residential proxy plan is active

# Check proxy manager initialization
python3 test_iproyal_integration.py
```

### "403 Forbidden" on proxy request
```bash
# Authentication failed
# Verify credentials are correct (case-sensitive)
# Check gateway URL format

# Reset proxy:
unset IPROYAL_USERNAME
unset IPROYAL_PASSWORD
export IPROYAL_USERNAME="correct_username"
export IPROYAL_PASSWORD="correct_password"
```

### ".gov domain still using proxy"
```bash
# Bypass might not be working
# Check bypass_domains configuration

python3 -c "
from improved_proxy import IPRoyalProxyManager, ProxyConfig
config = ProxyConfig(username='u', password='p')
mgr = IPRoyalProxyManager(config)
print(mgr.should_bypass('https://api.gov.vn'))  # Should be True
"
```

---

## VN Government API Testing

### Recommended Setup

```bash
# Maximum compatibility with VN .gov sites
export IPROYAL_USERNAME="your_username"
export IPROYAL_PASSWORD="your_password"
export IPROYAL_GATEWAY="http://geo.iproyal.com:12321"
export IPROYAL_ROTATION="per-endpoint"  # Same IP per domain

# Bypass government APIs that expect direct connection
export IPROYAL_BYPASS_DOMAINS=".gov,.gov.vn,.internal"
```

### Testing Strategy

1. **External targets** (third-party APIs)
   - Use residential proxy
   - Different IP per domain
   - Evades WAF/rate limits

2. **Government targets** (.gov.vn)
   - Use direct connection
   - Your legitimate IP
   - Avoids suspicion

3. **Local/internal** (.internal, localhost)
   - Always direct
   - No proxy overhead

### Example Scan

```bash
python3 apiscan.py \
  --url https://api.gov.vn \
  --swagger https://api.gov.vn/swagger.json \
  # Automatically routes correctly:
  # - .gov.vn endpoints: direct (no proxy)
  # - External refs: through residential proxy
```

---

## Integration with Improved Tools

### With SSRF Auditor
```python
from improved_ssrf_audit import AsyncSSRFAuditor
from improved_common import ScanConfig, AsyncHTTPClient
from improved_proxy import create_proxy_manager_from_env

config = ScanConfig(use_llm=True)
proxy_mgr = create_proxy_manager_from_env()
client = AsyncHTTPClient(config, proxy_manager=proxy_mgr)

auditor = AsyncSSRFAuditor(
    session=client,
    base_url="https://api.example.com"
)
results = await auditor.run_async()
```

### With BOLA Auditor
```python
from improved_bola_audit import AsyncBOLAAuditor

# Same setup, different auditor
auditor = AsyncBOLAAuditor(
    session=client,
    base_url="https://api.example.com"
)
```

---

## Advanced Configuration

### Custom Health Checks
```python
config = ProxyConfig(
    username="user",
    password="pass",
    check_interval=300.0,  # 5 minutes
    max_failures=3,        # Rotate after 3 failures
    timeout=10.0           # Health check timeout
)
```

### Fallback Behavior
```python
config = ProxyConfig(
    username="user",
    password="pass",
    fallback_to_direct=True  # If proxy fails, use direct
)
```

### Multiple Gateway Instances
```python
# Load balance across multiple gateways
gateways = [
    "http://geo.iproyal.com:12321",
    "http://geo2.iproyal.com:12321",
]

# Create managers for each
managers = [
    IPRoyalProxyManager(
        ProxyConfig(username="u", password="p", gateway_url=gw)
    )
    for gw in gateways
]

# Use round-robin in requests
```

---

## Cost Optimization

### Request Volume
```
IPRoyal residential: ~1 GB per 1000 requests
Estimate: 10k requests = 10 GB quota
```

### Optimization Tips
1. **Cache responses** — Don't re-scan same endpoint
2. **Batch requests** — Lower overhead with combined requests
3. **Use per-endpoint rotation** — Fewer IPs per target
4. **Sticky sessions** — One IP per session, not per request

### Monitoring
```python
# Track proxy usage
manager.log.info("proxy_request", url=url, proxy=proxy_url)
# Monitor in logs for quota tracking
```

---

## Testing & Validation

### Test Proxy Connection
```bash
python3 test_iproyal_integration.py
```

### Test Domain Bypass
```python
from improved_proxy import IPRoyalProxyManager, ProxyConfig

config = ProxyConfig(
    username="user",
    password="pass"
)
mgr = IPRoyalProxyManager(config)

# Should be True (bypass)
print(mgr.should_bypass("https://api.gov.vn"))
print(mgr.should_bypass("http://localhost"))

# Should be False (use proxy)
print(mgr.should_bypass("https://api.example.com"))
```

### Full Integration Test
```bash
python3 -c "
from improved_proxy import create_proxy_manager_from_env
proxy_mgr = create_proxy_manager_from_env()
if proxy_mgr:
    print('✓ IPRoyal proxy manager initialized')
    print(f'  Gateway: {proxy_mgr.config.gateway_url}')
    print(f'  Rotation: {proxy_mgr.config.rotation_strategy}')
else:
    print('✗ IPRoyal not configured (IPROYAL_USERNAME/PASSWORD not set)')
"
```

---

## Summary

✅ **IPRoyal residential proxy with smart domain bypass**

- **Installation:** Set 3 environment variables
- **Configuration:** Automatic .gov domain bypass
- **Rotation:** Per-request, per-endpoint, or sticky
- **Integration:** Works with all improved auditors
- **VN Focus:** Perfect for government API testing

**Next:** See `modernization_guide.md`, `OLLAMA_SETUP.md`, or `CAPTCHA_GUIDE.md` for other improvements.
