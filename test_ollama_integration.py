#!/usr/bin/env python3
"""
Test Ollama + Qwen integration with improved_common.py
"""

import sys
import asyncio

async def test_ollama():
    """Test Ollama payload generator."""
    print("=" * 70)
    print("OLLAMA INTEGRATION TEST")
    print("=" * 70)

    from improved_common import ScanConfig, OllamaPayloadGenerator, create_llm_payload_generator

    # Test 1: Check if Ollama is available
    print("\n[1] Checking Ollama availability...")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get("http://localhost:11434/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name") for m in models]
                print(f"    ✓ Ollama is running")
                print(f"    ✓ Available models: {model_names}")
                ollama_available = True
            else:
                print(f"    ✗ Ollama HTTP error: {resp.status_code}")
                ollama_available = False
    except Exception as e:
        print(f"    ✗ Ollama not available: {e}")
        ollama_available = False

    # Test 2: Create config with Ollama backend
    print("\n[2] Creating ScanConfig with Ollama backend...")
    try:
        config = ScanConfig(
            use_llm=True,
            llm_backend="auto",  # Try Ollama first, fallback to Claude
            ollama_model="qwen:7b"
        )
        print(f"    ✓ Config created")
        print(f"      - use_llm: {config.use_llm}")
        print(f"      - llm_backend: {config.llm_backend}")
        print(f"      - ollama_model: {config.ollama_model}")
    except Exception as e:
        print(f"    ✗ Config creation failed: {e}")
        return False

    # Test 3: Create OllamaPayloadGenerator directly
    print("\n[3] Testing OllamaPayloadGenerator...")
    try:
        ollama_gen = OllamaPayloadGenerator(config, model="qwen:7b")
        print(f"    ✓ OllamaPayloadGenerator created")
        print(f"      - enabled: {ollama_gen.enabled}")
        print(f"      - model: {ollama_gen.model}")
        print(f"      - url: {ollama_gen.base_url}")
    except Exception as e:
        print(f"    ✗ OllamaPayloadGenerator failed: {e}")
        return False

    # Test 4: Test smart backend selection
    print("\n[4] Testing smart LLM backend selection...")
    try:
        gen = create_llm_payload_generator(config)
        print(f"    ✓ LLM generator created")
        print(f"      - type: {gen.__class__.__name__}")

        # Check which backend was selected
        if hasattr(gen, 'enabled'):
            print(f"      - enabled: {gen.enabled}")
        if hasattr(gen, 'model'):
            print(f"      - model: {gen.model}")
    except Exception as e:
        print(f"    ✗ Backend selection failed: {e}")
        return False

    # Test 5: Test payload generation (if available)
    print("\n[5] Testing payload generation...")
    try:
        if ollama_available and hasattr(gen, 'enabled') and gen.enabled:
            print("    Testing with Ollama...")
            payloads = await gen.generate(
                category="SSRF",
                context="?redirect_url=",
                seed_payloads=["http://127.0.0.1:8080"],
                n=3
            )
            print(f"    ✓ Generated {len(payloads)} payloads")
            for i, p in enumerate(payloads[:5], 1):
                print(f"      {i}. {p}")
        else:
            print("    ℹ Ollama not available, skipping live test")
            print("    ℹ To test: install Ollama and run: ollama pull qwen:7b")
    except Exception as e:
        print(f"    ! Payload generation test failed: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 70)
    print("✓ OLLAMA INTEGRATION TESTS COMPLETE")
    print("=" * 70)

    if ollama_available:
        print("\nOllama Status: ✓ READY")
        print("Next: Run apiscan with LLM enabled:")
        print("  python3 apiscan.py --url https://api.example.com")
    else:
        print("\nOllama Status: Not installed")
        print("\nTo enable local Qwen 7B fuzzing:")
        print("  1. Install Ollama: https://ollama.ai")
        print("  2. Pull Qwen 7B: ollama pull qwen:7b")
        print("  3. Run Ollama: ollama serve")
        print("  4. Then run apiscan normally (auto-detects Ollama)")

    return True

if __name__ == '__main__':
    try:
        success = asyncio.run(test_ollama())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
