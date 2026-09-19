# Claude Vision CAPTCHA Testing Guide

Benchmark Claude Vision API vs Tesseract OCR on GDT CAPTCHAs.

## Setup (5 minutes)

### 1. Install Dependencies

```bash
pip install anthropic pillow pytesseract httpx
python -m pip install -U pip setuptools wheel

# Install Tesseract
# macOS
brew install tesseract

# Linux
sudo apt-get install tesseract-ocr

# Windows
# Download from: https://github.com/UB-Mannheim/tesseract/wiki
```

### 2. Set API Key

```bash
export ANTHROPIC_API_KEY="sk-..."
```

### 3. Prepare Test Data

**Option A: Use Your Own GDT CAPTCHAs**

```bash
# Create test directory
mkdir captcha_samples

# Copy CAPTCHA images
cp /path/to/gdt/captchas/*.png captcha_samples/

# Create answers file
cat > captcha_answers.json << 'EOF'
{
  "captcha_001": "A7x2K",
  "captcha_002": "B9mL3",
  "captcha_003": "C5qP7",
  "captcha_...": "..."
}
EOF
```

**Option B: Download Sample GDT CAPTCHAs** (for testing)

```bash
# If you have saved CAPTCHA samples from previous scans
mkdir captcha_samples
# Move your samples here with known answers
```

### 4. Run Test

```bash
python3 test_claude_vision_captcha.py
```

---

## What Gets Tested

### Claude Vision
- Uses Anthropic's Claude 3.5 Sonnet vision model
- Optimized for text extraction
- Cost: ~$0.001 per image
- Speed: ~0.5-1 second per image

### Tesseract OCR
- Open-source OCR engine
- Fast, runs locally
- Free
- Speed: ~0.1-0.3 seconds per image

### Comparison Metrics
- **Accuracy**: % of images where answer is correct
- **Confidence**: How confident the model is (0-100%)
- **Speed**: Time to process one image
- **Correctness**: Exact match to expected answer

---

## Expected Results

### GDT CAPTCHAs (Simple Image-Based, Standard Fonts)

| Model | Expected Accuracy | Speed |
|-------|------------------|-------|
| Claude Vision | 80-85% | 0.5-1s |
| Tesseract OCR | 70-80% | 0.1s |
| **Combined** | 85-90% | varies |

### What This Means
- Claude Vision wins on accuracy
- Tesseract is faster and free
- Combined approach: Use Vision first, OCR as fallback

---

## Example Output

```
======================================================================
CLAUDE VISION vs TESSERACT OCR - CAPTCHA BENCHMARK
======================================================================

📊 Testing 10 CAPTCHA images...

[1/10] captcha_001.png
  Testing Claude Vision... ✓ 0.85s
  Testing Tesseract OCR... ✓ 0.12s
  Expected: A7x2K
  Vision:   A7x2K [100%]
  OCR:      A7x2K [100%]

[2/10] captcha_002.png
  Testing Claude Vision... ✓ 0.92s
  Testing Tesseract OCR... ✓ 0.11s
  Expected: B9mL3
  Vision:   B9mL3 [100%]
  OCR:      B9mL3 [100%]

...

======================================================================
📊 TEST SUMMARY
======================================================================

Tested: 10 labeled images

Metric                         Claude Vision        Tesseract OCR
----------------------------------------------------------------------
Accuracy                             85.0%                 80.0%
Avg Confidence                      92.0%                88.0%
Avg Speed                           0.89s                0.11s

🏆 Winner: Claude Vision (85.0% vs 80.0%)

💾 Results saved to captcha_test_results.json
```

---

## Interpreting Results

### High Confidence, Wrong Answer
- Model is unsure but made its best guess
- Suggests image quality issue or unusual CAPTCHA

### Low Confidence, Correct Answer
- Model got it right but wasn't confident
- Suggests distorted CAPTCHA challenging the model

### Consistent Errors
- Look at `captcha_test_results.json`
- Pattern: Vision struggles with rotation? OCR struggles with color?
- Can inform optimization strategy

---

## Using Results for Production

### If Claude Vision Wins (>85% accuracy)
```python
# Use Vision primarily, OCR as backup
config = CaptchaConfig(use_vision=True)
solver = UnifiedAsyncCaptchaSolver(config)
# Vision → Tesseract → Commercial fallback
```

### If OCR Wins (<70% vision accuracy)
```python
# Something is wrong - usually:
# 1. API key issue
# 2. Image encoding problem
# 3. CAPTCHA type not text-based

# Debug: Check actual responses
# Vision might be hallucinating due to image quality
```

### For Production Optimization
```python
# Use combined approach
results = await test_images("captcha_samples/", "answers.json")

# Analyze failure patterns
failures = [r for r in results if not r.vision_correct]

# If <5% failures:
# → Use Vision only, skip OCR for speed

# If 10-20% failures:
# → Use Vision + OCR fallback

# If >20% failures:
# → Consider commercial service or image preprocessing
```

---

## Customizing Tests

### Test Different Models

```python
# Modify test_claude_vision_captcha.py to test:
# - Different Claude models (3-opus, 3-sonnet, 3-haiku)
# - Different OCR engines (EasyOCR, Paddleocr)
# - Different confidence thresholds
```

### Test Image Preprocessing

```python
# Before sending to Vision:
from PIL import Image, ImageEnhance

img = Image.open("captcha.png")

# Enhance contrast
enhancer = ImageEnhance.Contrast(img)
img = enhancer.enhance(2.0)

# Sharpen
enhancer = ImageEnhance.Sharpness(img)
img = enhancer.enhance(2.0)

# Save and test
img.save("captcha_enhanced.png")
```

### Benchmark Against Commercial Services

```python
# Add 2Captcha, CapSolver, etc. to comparison
# Compare cost, speed, accuracy
```

---

## Troubleshooting

### "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY="sk-..."
echo $ANTHROPIC_API_KEY  # Verify it's set
```

### "Tesseract not found"
```bash
# macOS
brew install tesseract

# Linux
sudo apt-get install tesseract-ocr

# Windows
# Download & install: https://github.com/UB-Mannheim/tesseract/wiki
# Then add to PATH
```

### "Module not found: anthropic"
```bash
pip install anthropic
```

### "No labeled results"
Create `captcha_answers.json` with expected answers:
```json
{
  "image_filename_without_extension": "expected_text",
  "captcha_001": "A7x2K",
  "captcha_002": "B9mL3"
}
```

### Vision Accuracy Low (< 70%)
Possible causes:
1. API key issue - verify with:
   ```bash
   python3 -c "from anthropic import Anthropic; print('OK')"
   ```

2. Image quality - Vision works best on clear images
   - Check image format (PNG/JPG preferred)
   - Check contrast and brightness

3. Rate limiting - waiting too long between API calls
   - Add `asyncio.sleep(0.5)` between requests

---

## Integration with apiscan

Once you have test results, integrate into apiscan:

```python
# In improved_captcha_solver.py
from improved_common import CaptchaConfig

config = CaptchaConfig(
    use_vision=True,  # If Vision accuracy > 80%
    use_ocr=True,     # Always true
    vision_only=False  # Use fallback chain
)

solver = UnifiedAsyncCaptchaSolver(config)
```

---

## Next Steps

1. **Collect samples** - Gather 10-20 GDT CAPTCHA images with known answers
2. **Run benchmark** - `python3 test_claude_vision_captcha.py`
3. **Analyze results** - Check `captcha_test_results.json`
4. **Optimize** - If accuracy low, try preprocessing or different model
5. **Deploy** - Use best-performing configuration in apiscan

---

## Cost Analysis

### Per-CAPTCHA Costs (at scale)

| Approach | Cost/image | Accuracy | Speed |
|----------|-----------|----------|-------|
| Claude Vision only | $0.001 | 80-85% | 1s |
| Tesseract only | $0 | 70-80% | 0.1s |
| Vision + OCR + Commercial | $0.0002* | 95%+ | varies |

*Only use commercial fallback for failures (~5%)

### For 1M CAPTCHAs/month
- Vision only: $1,000
- Vision + OCR: $200 (only for failures)
- Tesseract: Free (but 70-80% accuracy)

---

## Questions?

See `IPROYAL_SETUP.md`, `OLLAMA_SETUP.md`, and `INTEGRATION_SUMMARY.md` for full context on how CAPTCHA solving integrates with the improved tools.
