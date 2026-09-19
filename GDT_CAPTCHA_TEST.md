# Test Claude Vision Against GDT CAPTCHAs

Directly test Claude Vision on actual CAPTCHAs from tracuunnt.gdt.gov.vn

## Quick Start

```bash
# 1. Set API key
export ANTHROPIC_API_KEY="sk-..."

# 2. Download 5 GDT CAPTCHAs
python3 test_gdt_captcha_live.py --download-captchas 5

# 3. Test Claude Vision on them
python3 test_gdt_captcha_live.py --test-local

# Or do both at once
python3 test_gdt_captcha_live.py --download-captchas 10 --test-local
```

## What It Does

### Step 1: Download CAPTCHAs
- Connects to `https://tracuunnt.gdt.gov.vn/tcnnt/mstcn.jsp`
- Extracts CAPTCHA image URL from HTML
- Downloads the PNG image
- Saves locally to `gdt_captcha_samples/`
- Repeats for N iterations

### Step 2: Test Claude Vision
- Loads each downloaded CAPTCHA
- Sends to Claude Vision API
- Extracts recognized text
- Compares with Tesseract OCR
- Generates report

## Output

```
======================================================================
GDT CAPTCHA VISION TESTER
======================================================================

[1/5] gdt_20250919_120534_0.png
  Claude Vision... ✓ 0.87s
    Answer: A7x2K
  Tesseract OCR... ✓ 0.11s
    Answer: A7x2K
    ✓ MATCH

[2/5] gdt_20250919_120535_1.png
  Claude Vision... ✓ 0.92s
    Answer: B9mL3
  Tesseract OCR... ✓ 0.10s
    Answer: B9mL3
    ✓ MATCH

...

======================================================================
📊 SUMMARY
======================================================================

Total tested: 5
Claude Vision responses: 5/5
Tesseract responses: 5/5
Matching answers: 5/5
Avg Claude Vision time: 0.89s
Avg Tesseract time: 0.10s

💾 Results saved to gdt_captcha_test_results.json
```

## Results File

```json
{
  "timestamp": "2025-09-19T12:05:34.123456",
  "total": 5,
  "vision_responses": 5,
  "ocr_responses": 5,
  "matches": 5,
  "results": [
    {
      "image": "gdt_20250919_120534_0.png",
      "vision_answer": "A7x2K",
      "vision_time": 0.87,
      "ocr_answer": "A7x2K",
      "ocr_time": 0.11,
      "match": true
    },
    ...
  ]
}
```

## Interpretation

### Perfect Match (5/5 or 4/5)
✅ Claude Vision is working excellently on GDT CAPTCHAs
- Vision accuracy: 80%+
- Ready for production

### Good Match (3/5 or 3/4)
⚠️ Claude Vision is working reasonably well
- Vision accuracy: 60-80%
- Use with OCR fallback for robustness

### Poor Match (<2/5)
❌ Something is wrong
- Check API key
- Check image format
- Verify CAPTCHA type hasn't changed
- May need different approach

## Expected Results for GDT

Based on GDT CAPTCHA characteristics (simple image, standard fonts):

| Metric | Expected |
|--------|----------|
| Vision accuracy | 80-85% |
| OCR accuracy | 70-80% |
| Match rate | 70-80% (both get same answer) |
| Vision speed | 0.5-1.0 sec |
| OCR speed | 0.1 sec |

## Troubleshooting

### "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY="sk-..."
python3 test_gdt_captcha_live.py --download-captchas 5
```

### "CAPTCHA not found in HTML"
- GDT HTML structure may have changed
- Check the actual HTML for image src pattern
- Manual download may be needed

### "Failed to download (HTTP 403/429)"
- GDT may be blocking automated access
- Try with delays: `await asyncio.sleep(2)` between requests
- Use VPN/residential proxy if needed

### "Claude Vision returning empty"
- API key issue: verify it's correct
- Image encoding issue: check PNG validity
- Rate limiting: add delays between requests

## Using Results

### If Claude Vision Works Well (>80%)
```python
# In improved_captcha_solver.py
config = CaptchaConfig(use_vision=True)
solver = UnifiedAsyncCaptchaSolver(config)
# Use Vision for GDT CAPTCHAs
```

### If Both Vision and OCR Work
```python
# Use Vision for accuracy, OCR for speed
# Vision → OCR fallback → Commercial
```

### Integration with apiscan

Once validated:
```bash
# Use in apiscan with IPRoyal + Ollama
python3 apiscan.py --url https://api.gov.vn \
  --llm-backend ollama \
  --iproyal-username user \
  --iproyal-password pass
# Automatically handles CAPTCHAs with Vision + OCR
```

## Next Steps

1. **Download samples**: `--download-captchas 10`
2. **Check results**: `cat gdt_captcha_test_results.json`
3. **Verify accuracy**: Manually check a few images
4. **Deploy**: If >80% accuracy, use in production

---

## Reference

- Related: `test_claude_vision_captcha.py` (generic benchmark)
- Related: `CLAUDE_VISION_TESTING_GUIDE.md` (full guide)
- Related: `improved_captcha_solver.py` (actual solver)

---

## Notes

- GDT may have rate limiting on CAPTCHA generation
- Each request generates a new CAPTCHA
- CAPTCHAs are stored locally in `gdt_captcha_samples/`
- Results are JSON for automated analysis
- This is for authorized security testing only

---

## Command Reference

```bash
# Download 5 CAPTCHAs only
python3 test_gdt_captcha_live.py --download-captchas 5

# Test previously downloaded CAPTCHAs
python3 test_gdt_captcha_live.py --test-local

# Download and test in one go (10 CAPTCHAs)
python3 test_gdt_captcha_live.py --download-captchas 10 --test-local

# Help
python3 test_gdt_captcha_live.py --help
```

Ready to test! 🧪
