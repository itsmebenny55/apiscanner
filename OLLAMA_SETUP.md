# Ollama + Qwen 7B Setup Guide

## Quick Start (5 minutes)

### 1. Install Ollama

**macOS/Linux:**
```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Or download from: https://ollama.ai
```

**Windows/Docker:**
```bash
# Docker (if preferred)
docker run -d -p 11434:11434 ollama/ollama
```

### 2. Pull Qwen 7B Model

```bash
ollama pull qwen:7b
```

This downloads ~4.7GB (one time only, cached locally).

**Time:** 5-20 minutes depending on internet

### 3. Start Ollama Server

```bash
ollama serve
```

Runs on `http://localhost:11434` (background optional):
```bash
# Background (macOS)
brew services start ollama

# Background (Linux)
sudo systemctl start ollama

# Background (Docker)
docker run -d -p 11434:11434 ollama/ollama
```

### 4. Run apiscan with LLM Enabled

```bash
python3 apiscan.py --url https://api.example.com
```

**Auto-detection:** apiscan automatically detects Ollama and uses Qwen 7B for payload generation.

---

## How It Works

### Intelligent Backend Selection

apiscan now tries LLM backends in this order:

1. **Ollama (Local Qwen 7B)** ← Recommended
   - Zero cost
   - Offline capable
   - Vietnamese-aware
   - Fast (GPU: 50-100 tokens/sec)

2. **Claude API** (Fallback)
   - If `ANTHROPIC_API_KEY` set
   - Higher quality but requires API cost

3. **Static Seeds** (Final Fallback)
   - Works offline
   - Good baseline coverage
   - No external dependencies

### Config

**Default behavior:**
```python
config = ScanConfig(
    use_llm=True,           # Enable LLM fuzzing
    llm_backend="auto",     # Auto-select (Ollama→Claude→seeds)
    ollama_model="qwen:7b"  # Qwen 7B (can use qwen:14b for better quality)
)
```

**Environment variables:**
```bash
# Ollama configuration
export OLLAMA_URL="http://localhost:11434"  # Default

# Claude fallback (optional)
export ANTHROPIC_API_KEY="sk-..."
export ANTHROPIC_MODEL="claude-sonnet-4-5"
```

### Command Line

```bash
# Auto-detect Ollama
python3 apiscan.py --url https://api.example.com

# Force specific backend
python3 apiscan.py --url https://api.example.com --llm-backend ollama
python3 apiscan.py --url https://api.example.com --llm-backend claude
python3 apiscan.py --url https://api.example.com --llm-backend auto

# Disable LLM entirely (use static seeds)
python3 apiscan.py --url https://api.example.com --no-llm
```

---

## Qwen Model Selection

### Qwen 7B (Recommended) ⭐
- **Size:** 7GB model
- **VRAM:** 8GB GPU (4GB with quantization)
- **Speed:** ~50-100 tokens/sec on GPU
- **Quality:** Excellent for security payloads
- **Vietnamese:** Strong multilingual support
- **Install:** `ollama pull qwen:7b`

### Qwen 14B (Best Quality)
- **Size:** 14GB model
- **VRAM:** 16GB+ GPU recommended
- **Speed:** ~20-30 tokens/sec on GPU
- **Quality:** Best (but slower)
- **Use when:** You have GPU VRAM available
- **Install:** `ollama pull qwen:14b`

### Qwen 3B (Light & Fast)
- **Size:** 3GB model
- **VRAM:** 6GB GPU, runs on CPU
- **Speed:** Very fast (100+ tokens/sec)
- **Quality:** Good (85-90% of 7B)
- **Use when:** CPU-only or limited VRAM
- **Install:** `ollama pull qwen:3b`

### Qwen 1.8B (Ultra-Light)
- **Size:** 1.8GB
- **Speed:** Blazingly fast
- **Quality:** Fair for simple payloads
- **Use when:** Extreme resource constraints
- **Install:** `ollama pull qwen:1.8b`

### Other Models
```bash
ollama pull mistral          # General purpose, good quality
ollama pull neural-chat      # Instruction-following
ollama pull openchat         # Fast, decent quality
ollama pull phi              # Small, lightweight
```

---

## Performance Tips

### GPU Acceleration

Ollama auto-detects NVIDIA/AMD GPUs:

```bash
# Check GPU detection
ollama list

# Force GPU usage
CUDA_VISIBLE_DEVICES=0 ollama serve

# Check VRAM usage
nvidia-smi
```

**Performance by hardware:**
- **RTX 4090:** 200+ tokens/sec with Qwen 7B
- **RTX 3080:** 80-100 tokens/sec
- **M1/M2 Mac:** 50-70 tokens/sec
- **CPU-only:** 5-10 tokens/sec

### Reduce VRAM Usage

```bash
# Use quantized (smaller) version
ollama pull qwen:7b-q4_0   # Quantized, ~4GB
ollama pull qwen:3b        # Native small version

# Adjust context length (reduces VRAM)
export OLLAMA_NUM_CTX=512  # Default 2048
```

### Caching

Ollama caches:
- **Downloaded models:** `~/.ollama/models/`
- **In-memory:** Recent payloads (per category)

Clear cache if needed:
```bash
rm -rf ~/.ollama/models/    # Clear all models
ollama pull qwen:7b         # Re-download
```

---

## Troubleshooting

### "Connection refused" / "Ollama not available"

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve

# Check port
lsof -i :11434
```

### "Model not found"

```bash
# List available models
ollama list

# Pull the model
ollama pull qwen:7b

# Check download progress
ollama list
```

### Low VRAM / Out of Memory

```bash
# Use smaller model
ollama pull qwen:3b

# Or quantized version
ollama pull qwen:7b-q4_0

# Check VRAM
nvidia-smi
```

### Slow Payload Generation

```bash
# Check if using GPU
ollama list

# Verify GPU has memory
nvidia-smi

# Try smaller model
ollama pull qwen:3b

# Disable LLM fuzzing if too slow
python3 apiscan.py --url https://api.example.com --no-llm
```

---

## Advanced Configuration

### Custom Ollama Endpoint

```bash
# Use remote Ollama server
export OLLAMA_URL="http://ollama-server.internal:11434"
python3 apiscan.py --url https://api.example.com
```

### Multiple Models

```python
# Use different models for different runs
config = ScanConfig(
    ollama_model="qwen:7b"   # For thorough scans
    # or
    ollama_model="qwen:3b"   # For quick scans
)
```

### Hybrid Setup

```bash
# Ollama for fuzzing, Claude for analysis (if budget allows)
export ANTHROPIC_API_KEY="sk-..."
export OLLAMA_URL="http://localhost:11434"

# Auto-selects: Ollama for payloads, could use Claude for other analysis
python3 apiscan.py --url https://api.example.com
```

---

## Comparison: Ollama vs Claude API

| Aspect | Ollama (Qwen 7B) | Claude API |
|--------|------------------|-----------|
| **Cost** | Free (one-time download) | $$ per request |
| **Speed** | 50-100 tokens/sec | 100+ tokens/sec |
| **Quality** | Good (excellent for security) | Excellent |
| **Privacy** | Local (no external API) | Cloud-based |
| **Vietnamese** | Strong | Good |
| **Offline** | ✅ Yes | ❌ No |
| **Setup** | 5 minutes | Instant (if key available) |
| **Best For** | Local/offline work, long-term use | High quality, occasional use |

**Recommendation:** Use **Ollama locally** for regular testing, **Claude** for occasional high-quality analysis.

---

## Verification

Check everything is working:

```bash
# Test Ollama integration
python3 test_ollama_integration.py

# Should show:
# ✓ Ollama is running
# ✓ Available models: [...]
# ✓ OllamaPayloadGenerator created
# ✓ enabled: True
```

---

## Documentation

- **Main:** See `modernization_guide.md`
- **CAPTCHA:** See `improved_captcha_guide.md`
- **Integration:** See `INTEGRATION_SUMMARY.md`
- **Tests:** Run `test_ollama_integration.py`

---

## Support

**Issues?**
1. Check Ollama is running: `curl http://localhost:11434/api/tags`
2. Verify model is installed: `ollama list`
3. Check VRAM: `nvidia-smi` or `top`
4. Run: `python3 test_ollama_integration.py`

**Want to use Claude instead?**
```bash
export ANTHROPIC_API_KEY="sk-..."
python3 apiscan.py --url https://api.example.com --llm-backend claude
```

---

## Summary

✅ **Ollama + Qwen 7B = Free, offline, Vietnamese-aware payload generation**

- **Install:** `brew install ollama && ollama pull qwen:7b`
- **Start:** `ollama serve` (background)
- **Run:** `python3 apiscan.py --url https://api.example.com`
- **Done:** Auto-detects Ollama, uses Qwen 7B for fuzzing

No API keys needed. Works offline. Fast on GPU. Perfect for VN API testing.
