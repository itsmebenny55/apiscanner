#!/usr/bin/env python3
"""
Test Claude Vision for GDT CAPTCHA solving.
Benchmarks accuracy against Tesseract OCR and commercial services.
"""

import asyncio
import os
import sys
import json
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

import httpx
from PIL import Image
import pytesseract


@dataclass
class TestResult:
    """CAPTCHA test result."""
    filename: str
    expected_answer: Optional[str]
    claude_vision: Optional[str]
    tesseract_ocr: Optional[str]
    vision_confidence: float
    ocr_confidence: float
    vision_correct: bool
    ocr_correct: bool
    vision_time: float
    ocr_time: float


class CaptchaVisionTester:
    """Test Claude Vision on CAPTCHA images."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            print("⚠️  ANTHROPIC_API_KEY not set - Vision testing disabled")
            self.vision_enabled = False
        else:
            self.vision_enabled = True
            print("✓ Claude Vision API key detected")

    async def test_vision(self, image_path: str) -> Tuple[Optional[str], float]:
        """Test Claude Vision on CAPTCHA image."""
        if not self.vision_enabled:
            return None, 0.0

        try:
            import base64
            import time
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
                                "text": "What text is shown in this CAPTCHA image? Answer ONLY with the text characters, nothing else."
                            }
                        ],
                    }
                ],
            )
            elapsed = time.perf_counter() - started

            text = message.content[0].text.strip()
            return text, elapsed

        except Exception as e:
            print(f"  ✗ Claude Vision error: {e}")
            return None, 0.0

    def test_ocr(self, image_path: str) -> Tuple[Optional[str], float]:
        """Test Tesseract OCR on CAPTCHA image."""
        try:
            import time

            started = time.perf_counter()
            text = pytesseract.image_to_string(image_path)
            elapsed = time.perf_counter() - started

            # Clean up whitespace
            text = text.strip()
            return text, elapsed

        except Exception as e:
            print(f"  ✗ Tesseract error: {e}")
            return None, 0.0

    def calculate_confidence(self, answer: Optional[str], expected: Optional[str]) -> float:
        """Simple confidence based on string similarity."""
        if not answer or not expected:
            return 0.0

        answer = answer.upper().strip()
        expected = expected.upper().strip()

        # Exact match
        if answer == expected:
            return 1.0

        # Partial match
        matches = sum(1 for a, e in zip(answer, expected) if a == e)
        similarity = matches / max(len(answer), len(expected))
        return similarity

    async def test_images(
        self,
        image_dir: str,
        answers_file: Optional[str] = None
    ) -> List[TestResult]:
        """Test all CAPTCHA images in directory."""
        results = []
        image_dir = Path(image_dir)

        if not image_dir.exists():
            print(f"✗ Directory not found: {image_dir}")
            return results

        # Load answers if provided
        answers: Dict[str, str] = {}
        if answers_file and Path(answers_file).exists():
            with open(answers_file) as f:
                answers = json.load(f)

        # Find image files
        images = list(image_dir.glob("*.png")) + list(image_dir.glob("*.jpg"))
        print(f"\n📊 Testing {len(images)} CAPTCHA images...")

        for i, img_path in enumerate(images, 1):
            print(f"\n[{i}/{len(images)}] {img_path.name}")

            filename = img_path.stem
            expected = answers.get(filename)

            # Test Claude Vision
            print("  Testing Claude Vision...", end="", flush=True)
            vision_text, vision_time = await self.test_vision(str(img_path))
            print(f" ✓ {vision_time:.2f}s")

            # Test Tesseract OCR
            print("  Testing Tesseract OCR...", end="", flush=True)
            ocr_text, ocr_time = self.test_ocr(str(img_path))
            print(f" ✓ {ocr_time:.2f}s")

            # Calculate confidence/correctness
            vision_conf = self.calculate_confidence(vision_text, expected)
            ocr_conf = self.calculate_confidence(ocr_text, expected)
            vision_correct = vision_conf >= 0.9 if expected else False
            ocr_correct = ocr_conf >= 0.9 if expected else False

            # Display results
            if expected:
                print(f"  Expected: {expected}")
            print(f"  Vision:   {vision_text or '(no response)'} [{vision_conf*100:.0f}%]")
            print(f"  OCR:      {ocr_text or '(no response)'} [{ocr_conf*100:.0f}%]")

            result = TestResult(
                filename=filename,
                expected_answer=expected,
                claude_vision=vision_text,
                tesseract_ocr=ocr_text,
                vision_confidence=vision_conf,
                ocr_confidence=ocr_conf,
                vision_correct=vision_correct,
                ocr_correct=ocr_correct,
                vision_time=vision_time,
                ocr_time=ocr_time
            )
            results.append(result)

        return results


def print_summary(results: List[TestResult]) -> None:
    """Print test summary statistics."""
    if not results:
        return

    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)

    # Filter results with expected answers
    labeled_results = [r for r in results if r.expected_answer]
    unlabeled = len(results) - len(labeled_results)

    if not labeled_results:
        print(f"No labeled results (add answers.json with expected answers)")
        print(f"Unlabeled images tested: {unlabeled}")
        return

    # Vision stats
    vision_correct = sum(1 for r in labeled_results if r.vision_correct)
    vision_accuracy = vision_correct / len(labeled_results) * 100 if labeled_results else 0
    vision_avg_conf = sum(r.vision_confidence for r in labeled_results) / len(labeled_results)
    vision_avg_time = sum(r.vision_time for r in labeled_results) / len(labeled_results)

    # OCR stats
    ocr_correct = sum(1 for r in labeled_results if r.ocr_correct)
    ocr_accuracy = ocr_correct / len(labeled_results) * 100 if labeled_results else 0
    ocr_avg_conf = sum(r.ocr_confidence for r in labeled_results) / len(labeled_results)
    ocr_avg_time = sum(r.ocr_time for r in labeled_results) / len(labeled_results)

    print(f"\nTested: {len(labeled_results)} labeled images")

    print(f"\n{'Metric':<30} {'Claude Vision':<20} {'Tesseract OCR':<20}")
    print("-" * 70)
    print(f"{'Accuracy':<30} {vision_accuracy:>18.1f}% {ocr_accuracy:>18.1f}%")
    print(f"{'Avg Confidence':<30} {vision_avg_conf:>18.1%} {ocr_avg_conf:>18.1%}")
    print(f"{'Avg Speed':<30} {vision_avg_time:>17.2f}s {ocr_avg_time:>17.2f}s")

    # Winner
    print("\n🏆 Winner: ", end="")
    if vision_accuracy > ocr_accuracy:
        print(f"Claude Vision ({vision_accuracy:.1f}% vs {ocr_accuracy:.1f}%)")
    elif ocr_accuracy > vision_accuracy:
        print(f"Tesseract OCR ({ocr_accuracy:.1f}% vs {vision_accuracy:.1f}%)")
    else:
        print("Tie!")

    # Failure analysis
    vision_failures = [r for r in labeled_results if not r.vision_correct]
    ocr_failures = [r for r in labeled_results if not r.ocr_correct]

    if vision_failures:
        print(f"\n❌ Claude Vision failures ({len(vision_failures)}):")
        for r in vision_failures[:5]:
            print(f"   {r.filename}: expected '{r.expected_answer}', got '{r.claude_vision}'")
        if len(vision_failures) > 5:
            print(f"   ... and {len(vision_failures) - 5} more")

    if ocr_failures:
        print(f"\n❌ Tesseract OCR failures ({len(ocr_failures)}):")
        for r in ocr_failures[:5]:
            print(f"   {r.filename}: expected '{r.expected_answer}', got '{r.tesseract_ocr}'")
        if len(ocr_failures) > 5:
            print(f"   ... and {len(ocr_failures) - 5} more")

    # Save results
    results_file = "captcha_test_results.json"
    results_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tested": len(labeled_results),
            "vision_accuracy": vision_accuracy,
            "vision_avg_confidence": float(vision_avg_conf),
            "vision_avg_time": vision_avg_time,
            "ocr_accuracy": ocr_accuracy,
            "ocr_avg_confidence": float(ocr_avg_conf),
            "ocr_avg_time": ocr_avg_time,
        },
        "results": [
            {
                "filename": r.filename,
                "expected": r.expected_answer,
                "vision_answer": r.claude_vision,
                "vision_confidence": float(r.vision_confidence),
                "vision_correct": r.vision_correct,
                "vision_time": r.vision_time,
                "ocr_answer": r.tesseract_ocr,
                "ocr_confidence": float(r.ocr_confidence),
                "ocr_correct": r.ocr_correct,
                "ocr_time": r.ocr_time,
            }
            for r in labeled_results
        ]
    }

    with open(results_file, "w") as f:
        json.dump(results_data, f, indent=2)
    print(f"\n💾 Results saved to {results_file}")


async def main():
    """Main test runner."""
    print("=" * 70)
    print("CLAUDE VISION vs TESSERACT OCR - CAPTCHA BENCHMARK")
    print("=" * 70)

    # Check for test images
    test_dir = "captcha_samples"
    if not Path(test_dir).exists():
        print(f"\n📁 Test directory not found: {test_dir}")
        print("\nSetup instructions:")
        print("1. Create directory: mkdir captcha_samples")
        print("2. Add CAPTCHA PNG images: cp *.png captcha_samples/")
        print("3. Create answers.json with expected answers:")
        print('   {"captcha_001": "A7x2K", "captcha_002": "B9mL3", ...}')
        print("4. Run this script again")
        return

    # Initialize tester
    tester = CaptchaVisionTester()

    # Get answers file
    answers_file = "captcha_answers.json"
    if not Path(answers_file).exists():
        print(f"\n⚠️  No answers file: {answers_file}")
        print("   Create it with: {'filename': 'expected_answer', ...}")
        print("   Results will show without accuracy metrics")

    # Run tests
    results = await tester.test_images(test_dir, answers_file)

    # Print summary
    print_summary(results)


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
