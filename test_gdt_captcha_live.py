#!/usr/bin/env python3
"""
Test Claude Vision against GDT CAPTCHAs from tracuunnt.gdt.gov.vn
This script captures CAPTCHA images and tests Claude Vision on them.

USAGE:
  python3 test_gdt_captcha_live.py --url "https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp"
  python3 test_gdt_captcha_live.py --download-captchas 10  # Capture 10 CAPTCHAs
  python3 test_gdt_captcha_live.py --test-local             # Test saved CAPTCHAs
"""

import asyncio
import argparse
import os
import sys
import time
import json
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime
import base64

import httpx
from PIL import Image
import pytesseract


class GDTCaptchaTester:
    """Test Claude Vision on GDT CAPTCHAs."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.gdt_url = "https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp"
        self.captcha_dir = Path("gdt_captcha_samples")
        self.captcha_dir.mkdir(exist_ok=True)

        if self.api_key:
            print("✓ Claude Vision API key detected")
        else:
            print("⚠️  ANTHROPIC_API_KEY not set - Vision testing disabled")

    async def download_captcha(self, session: httpx.AsyncClient, count: int = 1) -> list:
        """Download CAPTCHA images from GDT."""
        print(f"\n📥 Downloading {count} GDT CAPTCHA(s)...")

        results = []
        try:
            for i in range(count):
                print(f"  [{i+1}/{count}] Fetching...", end="", flush=True)

                # Get the page (which will have CAPTCHA)
                resp = await session.get(self.gdt_url, follow_redirects=True)

                # Extract CAPTCHA image URL from HTML
                # GDT uses: <img src="/tcnnt/captcha.png?..." />
                import re
                match = re.search(r'src=["\']([^"\']*captcha[^"\']*)["\']', resp.text)

                if not match:
                    print(" ✗ CAPTCHA not found in HTML")
                    continue

                captcha_url = match.group(1)
                if not captcha_url.startswith('http'):
                    captcha_url = "https://tracuunnt.gdt.gov.vn" + captcha_url

                # Download CAPTCHA image
                img_resp = await session.get(captcha_url)
                if img_resp.status_code != 200:
                    print(f" ✗ Failed to download (HTTP {img_resp.status_code})")
                    continue

                # Save CAPTCHA
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = self.captcha_dir / f"gdt_{timestamp}_{i}.png"
                filename.write_bytes(img_resp.content)

                print(f" ✓ {filename.name}")
                results.append(str(filename))

                # Rate limit
                await asyncio.sleep(1)

        except Exception as e:
            print(f"\n✗ Error downloading CAPTCHAs: {e}")

        return results

    async def test_vision(self, image_path: str) -> Tuple[Optional[str], float]:
        """Test Claude Vision on a single CAPTCHA."""
        if not self.api_key:
            return None, 0.0

        try:
            from anthropic import AsyncAnthropic

            with open(image_path, "rb") as f:
                image_data = base64.standard_b64encode(f.read()).decode("utf-8")

            client = AsyncAnthropic(api_key=self.api_key)

            started = time.perf_counter()
            message = await client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=100,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": image_data,
                                },
                            },
                            {
                                "type": "text",
                                "text": "What text/numbers are shown in this CAPTCHA image? Answer ONLY with the exact characters, nothing else."
                            }
                        ],
                    }
                ],
            )
            elapsed = time.perf_counter() - started

            text = message.content[0].text.strip()
            return text, elapsed

        except Exception as e:
            print(f"    ✗ Claude Vision error: {e}")
            return None, 0.0

    def test_ocr(self, image_path: str) -> Tuple[Optional[str], float]:
        """Test Tesseract OCR on a CAPTCHA."""
        try:
            started = time.perf_counter()
            text = pytesseract.image_to_string(image_path)
            elapsed = time.perf_counter() - started

            text = text.strip()
            return text, elapsed
        except Exception as e:
            print(f"    ✗ Tesseract error: {e}")
            return None, 0.0

    async def test_downloaded_captchas(self) -> None:
        """Test all downloaded CAPTCHAs."""
        images = sorted(self.captcha_dir.glob("gdt_*.png"))

        if not images:
            print("❌ No GDT CAPTCHAs found in gdt_captcha_samples/")
            print("   Run: python3 test_gdt_captcha_live.py --download-captchas 5")
            return

        print(f"\n🧪 Testing {len(images)} GDT CAPTCHAs...")

        results = []
        for i, img_path in enumerate(images, 1):
            print(f"\n[{i}/{len(images)}] {img_path.name}")

            # Test Vision
            print("  Claude Vision...", end="", flush=True)
            vision_text, vision_time = await self.test_vision(str(img_path))
            print(f" ✓ {vision_time:.2f}s")
            print(f"    Answer: {vision_text}")

            # Test OCR
            print("  Tesseract OCR...", end="", flush=True)
            ocr_text, ocr_time = self.test_ocr(str(img_path))
            print(f" ✓ {ocr_time:.2f}s")
            print(f"    Answer: {ocr_text}")

            # Compare
            if vision_text and ocr_text:
                match = "✓ MATCH" if vision_text.upper() == ocr_text.upper() else "✗ DIFFERENT"
                print(f"    {match}")

            results.append({
                "image": img_path.name,
                "vision_answer": vision_text,
                "vision_time": vision_time,
                "ocr_answer": ocr_text,
                "ocr_time": ocr_time,
                "match": vision_text and ocr_text and vision_text.upper() == ocr_text.upper()
            })

        # Summary
        print("\n" + "=" * 70)
        print("📊 SUMMARY")
        print("=" * 70)

        vision_answers = [r for r in results if r["vision_answer"]]
        ocr_answers = [r for r in results if r["ocr_answer"]]
        matches = [r for r in results if r["match"]]

        print(f"Total tested: {len(results)}")
        print(f"Claude Vision responses: {len(vision_answers)}/{len(results)}")
        print(f"Tesseract responses: {len(ocr_answers)}/{len(results)}")
        print(f"Matching answers: {len(matches)}/{len(results)}")

        if vision_answers:
            avg_vision_time = sum(r["vision_time"] for r in vision_answers) / len(vision_answers)
            print(f"Avg Claude Vision time: {avg_vision_time:.2f}s")

        if ocr_answers:
            avg_ocr_time = sum(r["ocr_time"] for r in ocr_answers) / len(ocr_answers)
            print(f"Avg Tesseract time: {avg_ocr_time:.2f}s")

        # Save results
        results_file = "gdt_captcha_test_results.json"
        with open(results_file, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total": len(results),
                "vision_responses": len(vision_answers),
                "ocr_responses": len(ocr_answers),
                "matches": len(matches),
                "results": results
            }, f, indent=2)

        print(f"\n💾 Results saved to {results_file}")
        print("\nNext steps:")
        print("  1. Manually verify answers (compare with CAPTCHA images)")
        print("  2. If >80% match: Claude Vision is working well")
        print("  3. If <70% match: Check API key, image quality, or CAPTCHA type")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test Claude Vision on GDT CAPTCHAs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download 5 GDT CAPTCHAs
  python3 test_gdt_captcha_live.py --download-captchas 5

  # Test downloaded CAPTCHAs
  python3 test_gdt_captcha_live.py --test-local

  # Both (download and test)
  python3 test_gdt_captcha_live.py --download-captchas 5 --test-local
        """
    )

    parser.add_argument("--url", default="https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp",
                       help="GDT CAPTCHA URL (default: tax authority)")
    parser.add_argument("--download-captchas", type=int, metavar="N",
                       help="Download N CAPTCHAs from GDT")
    parser.add_argument("--test-local", action="store_true",
                       help="Test locally saved CAPTCHAs")

    args = parser.parse_args()

    tester = GDTCaptchaTester()

    if args.download_captchas:
        print("=" * 70)
        print("GDT CAPTCHA DOWNLOADER")
        print("=" * 70)

        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=False,  # GDT may have cert issues
        ) as session:
            await tester.download_captcha(session, args.download_captchas)

    if args.test_local:
        print("\n" + "=" * 70)
        print("GDT CAPTCHA VISION TESTER")
        print("=" * 70)

        await tester.test_downloaded_captchas()

    if not args.download_captchas and not args.test_local:
        parser.print_help()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
