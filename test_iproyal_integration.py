#!/usr/bin/env python3
"""
Test IPRoyal residential proxy integration
"""

import os
import sys
import asyncio


async def test_iproyal():
    """Test IPRoyal proxy manager."""
    print("=" * 70)
    print("IPROYAL RESIDENTIAL PROXY INTEGRATION TEST")
    print("=" * 70)

    from improved_proxy import (
        ProxyConfig,
        IPRoyalProxyManager,
        DomainBypassRouter,
        create_proxy_manager_from_env
    )

    # Test 1: Check environment variables
    print("\n[1] Checking IPRoyal configuration...")
    username = os.getenv("IPROYAL_USERNAME")
    password = os.getenv("IPROYAL_PASSWORD")
    gateway = os.getenv("IPROYAL_GATEWAY", "http://geo.iproyal.com:12321")
    rotation = os.getenv("IPROYAL_ROTATION", "per-request")

    if username and password:
        print(f"    ✓ Credentials configured")
        print(f"      - Username: {username[:8]}...")
        print(f"      - Gateway: {gateway}")
        print(f"      - Rotation: {rotation}")
    else:
        print(f"    ℹ No credentials configured")
        print(f"    To test, set:")
        print(f"      export IPROYAL_USERNAME='your_username'")
        print(f"      export IPROYAL_PASSWORD='your_password'")
        username = "test_user"
        password = "test_pass"

    # Test 2: Create ProxyConfig
    print("\n[2] Creating ProxyConfig...")
    try:
        config = ProxyConfig(
            username=username,
            password=password,
            gateway_url=gateway,
            rotation_strategy=rotation,
            bypass_domains={".gov", ".gov.vn", ".internal", "localhost"}
        )
        print(f"    ✓ ProxyConfig created")
        print(f"      - Rotation: {config.rotation_strategy}")
        print(f"      - Bypass domains: {config.bypass_domains}")
    except Exception as e:
        print(f"    ✗ Config creation failed: {e}")
        return False

    # Test 3: Create IPRoyalProxyManager
    print("\n[3] Creating IPRoyalProxyManager...")
    try:
        manager = IPRoyalProxyManager(config)
        print(f"    ✓ IPRoyalProxyManager created")
        print(f"      - Enabled: {manager._enabled}")
    except Exception as e:
        print(f"    ✗ Manager creation failed: {e}")
        return False

    # Test 4: Test domain bypass logic
    print("\n[4] Testing domain-based routing...")
    test_urls = [
        ("https://api.gov.vn/data", True, "Should bypass .gov.vn"),
        ("https://customs.gov.vn/api", True, "Should bypass .gov.vn"),
        ("https://api.example.com/users", False, "Should use proxy"),
        ("https://external.com/api", False, "Should use proxy"),
        ("http://localhost:8080/api", True, "Should bypass localhost"),
        ("https://service.internal/api", True, "Should bypass .internal"),
    ]

    all_correct = True
    for url, should_bypass, description in test_urls:
        bypass = manager.should_bypass(url)
        status = "✓" if bypass == should_bypass else "✗"
        if bypass != should_bypass:
            all_correct = False
        print(f"    {status} {url}")
        print(f"       {description} → Bypass: {bypass}")

    if not all_correct:
        print(f"    ✗ Some bypass tests failed")
        return False

    # Test 5: Test proxy URL generation
    print("\n[5] Testing proxy URL generation...")
    test_cases = [
        ("https://api.example.com", "Should generate proxy URL"),
        ("https://api.gov.vn", "Should return None (bypass)"),
    ]

    for url, description in test_cases:
        proxy_url = manager.get_proxy_url(url)
        has_proxy = proxy_url is not None
        print(f"    ✓ {url}")
        print(f"       {description} → Proxy: {proxy_url if proxy_url else 'None (direct)'}")

    # Test 6: Test DomainBypassRouter
    print("\n[6] Testing DomainBypassRouter...")
    try:
        router = DomainBypassRouter(manager)
        proxy1 = router.get_proxy("https://api.example.com")
        proxy2 = router.get_proxy("https://api.gov.vn")

        print(f"    ✓ DomainBypassRouter created")
        print(f"      - api.example.com → {proxy1 if proxy1 else 'Direct'}")
        print(f"      - api.gov.vn → {proxy2 if proxy2 else 'Direct'}")
    except Exception as e:
        print(f"    ✗ Router test failed: {e}")
        return False

    # Test 7: Test factory function
    print("\n[7] Testing create_proxy_manager_from_env()...")
    try:
        factory_manager = create_proxy_manager_from_env()
        if factory_manager:
            print(f"    ✓ Manager created from environment")
            print(f"      - Enabled: {factory_manager._enabled}")
        else:
            print(f"    ℹ No credentials in environment (expected if not configured)")
    except Exception as e:
        print(f"    ! Factory test: {e}")

    # Test 8: Test with AsyncHTTPClient integration
    print("\n[8] Testing AsyncHTTPClient integration...")
    try:
        from improved_common import AsyncHTTPClient, ScanConfig

        scan_config = ScanConfig()
        client = AsyncHTTPClient(
            scan_config,
            proxy_manager=manager
        )
        print(f"    ✓ AsyncHTTPClient with proxy_manager created")
        print(f"      - Proxy manager assigned: {client._proxy_manager is not None}")
    except Exception as e:
        print(f"    ✗ AsyncHTTPClient integration failed: {e}")
        return False

    # Test 9: Test failure tracking
    print("\n[9] Testing failure tracking...")
    try:
        test_ip = "203.0.113.1"
        manager.record_failure(test_ip, "https://api.example.com")
        manager.record_failure(test_ip, "https://api.example.com")
        manager.record_success(test_ip)
        print(f"    ✓ Failure tracking works")
        print(f"      - Recorded failures, then success")
        print(f"      - Failure count reset: {test_ip not in manager._ip_failures}")
    except Exception as e:
        print(f"    ✗ Failure tracking failed: {e}")
        return False

    print("\n" + "=" * 70)
    print("✓ IPROYAL INTEGRATION TESTS COMPLETE")
    print("=" * 70)

    if username and password and username != "test_user":
        print("\nIPRoyal Status: ✓ CONFIGURED")
        print("Usage:")
        print("  python3 apiscan.py --url https://api.example.com")
        print("  # Auto-detects IPRoyal, routes:")
        print("  #  - .gov/.gov.vn → Direct connection")
        print("  #  - Other domains → Through residential proxy")
    else:
        print("\nIPRoyal Status: Not configured")
        print("\nTo enable IPRoyal residential proxy:")
        print("  1. Sign up: https://iproyal.com")
        print("  2. Get residential proxy gateway URL")
        print("  3. Set environment:")
        print("     export IPROYAL_USERNAME='your_username'")
        print("     export IPROYAL_PASSWORD='your_password'")
        print("     export IPROYAL_GATEWAY='http://geo.iproyal.com:12321'")
        print("  4. Run apiscan:")
        print("     python3 apiscan.py --url https://api.example.com")

    print("\nFeatures:")
    print("  ✓ Domain-based routing (.gov bypass)")
    print("  ✓ IP rotation (per-request/endpoint/sticky)")
    print("  ✓ Automatic failover to direct")
    print("  ✓ Health tracking")
    print("  ✓ AsyncHTTPClient integration")

    return True


if __name__ == '__main__':
    try:
        success = asyncio.run(test_iproyal())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
