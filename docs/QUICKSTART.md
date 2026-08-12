# DeepSec 3-Minute Quick Start

> Security checkup for AI-generated code — see your first vulnerability in 30 seconds.

---

## 0. Which one do I pick?

| Your situation | Recommended path | Time |
|---|---|---|
| Just want to try it, no coding | **Download TUI (Windows/Linux)** | 1 min |
| VS Code user | **Install VS Code extension** | 2 min |
| CLI user | **pip install** | 2 min |
| Scan your own project | **pip install** (recommended) | 2 min |

> **Fastest path**: **download the TUI → run it → type `/shield scan <your-project>`** — results in 2 seconds.

---

## 1. Install (pick one)

### Option A: Download & run (fastest)

1. Open the [Releases page](https://github.com/Unclecheng-li/DeepSec/releases)
2. Download from the latest release:
   - **Windows** → `deepsec-tui-windows.exe`
   - **Linux** → `deepsec-tui-linux`
3. Double-click to run

### Option B: pip install CLI (recommended for devs)

```bash
# Requires Python 3.10+
pip install deepsec
```

> If PyPI hasn't synced yet, download `deepsec-0.2.0-py3-none-any.whl` from Releases and install directly:
>
> ```bash
> pip install deepsec-0.2.0-py3-none-any.whl
> ```

### Option C: VS Code extension

1. Download `deepsec-0.2.0.vsix` from Releases
2. VS Code Extensions panel → `...` → **Install from VSIX** → select the file
3. Open a project — AI-generated code gets flagged in real time

---

## 2. First scan: see vulnerabilities in 2 seconds

The repo ships with a deliberately vulnerable sample file, `demo/unsafe-ai-sample.ts`.

### CLI

```bash
cd <DeepSec project dir>
deepsec shield scan demo
```

Expected output (real run):

```
+-----------------------------------------------------------------------------+
| Severity | Location            | Rule                | Finding              |
|----------+---------------------+---------------------+----------------------|
| critical | ...\unsafe-ai-sample.ts:4 | hardcoded_secret_o… | OpenAI API key       |
|          |                     |                     | appears to be        |
|          |                     |                     | hardcoded.           |
| high     | ...\unsafe-ai-sample.ts:11 | sast_xss_inner_html | HTML is assigned     |
|          |                     |                     | directly to the DOM. |
+-----------------------------------------------------------------------------+
Scanned 1 file(s) in 10.8 ms; 2 finding(s).
```
One `critical` (hardcoded OpenAI API key) + one `high` (XSS via `.innerHTML`) — the two most common AI mistakes.

### TUI (terminal workbench)

```bash
deepsec tui
```

At the bottom command line, type:

```
/shield scan demo
```

The TUI streams scan progress and results in a three-panel layout (Workspace / Session transcript / Findings).

---

## 3. Scan your own project

```bash
# Scan entire project (L1 + L2, fully offline)
deepsec shield scan <your-project-path>

# Scan a directory
deepsec shield scan ./src

# SARIF report (CI-friendly)
deepsec shield scan . --format sarif --output deepsec.sarif

# Markdown report
deepsec shield scan . --format markdown --output shield.md
```

**What the three layers detect:**

| Layer | Detects | Speed | Method |
|---|---|---|---|
| **L1** | Hallucinated packages, hardcoded secrets, unsafe configs, AI pattern errors | < 50ms | Regex + entropy + seed directory |
| **L2** | SQL injection, XSS, SSRF, path traversal, command injection | < 2s | Tree-sitter AST taint tracking |
| **L3** | Missing auth/rate-limiting/validation, semantic issues | < 5s | LLM (DeepSeek/Claude/OpenAI/Ollama) |

> L1 + L2 are on by default and fully offline — **no API key needed**.
> L3 requires an LLM key (see below); skipping it doesn't affect basic usage.

---

## 4. (Optional) Enable L3 semantic analysis

```bash
# Configure LLM (13+ providers, DeepSeek example)
deepsec config set llm.provider deepseek
deepsec config set llm.api_key "sk-xxx"

# Or use env var
export DEEPSEC_LLM_API_KEY="sk-xxx"

# Scan with L3
deepsec shield scan ./src --layer l3
```

---

## 5. (Advanced) Spear authorized penetration testing

> Note: Only targets you **own or have written authorization** for. Everything else is rejected.

```bash
# 1. Add target to allow-list (in TUI: /scope add)
/scope add https://your-authorized-domain.com

# 2. Run penetration test (Recon → findings → report → PoC pipeline)
deepsec spear run https://your-authorized-domain.com --authorized ~/.deepsec/targets/scope.json

# 3. Recon phase only
deepsec spear recon https://your-authorized-domain.com --authorized ~/.deepsec/targets/scope.json
```

---

## FAQ

**Q: The Windows exe doesn't open?**
Try running it in a terminal: `.\deepsec-tui-windows.exe` and read the error.

**Q: `deepsec` command not found?**
Make sure Python 3.10+ is installed and pip's Scripts dir is on PATH (common on Windows). Reopen your terminal.

**Q: Does scanning send my code anywhere?**
No. L1/L2 are fully local and offline. Only explicit `--layer l3` calls your configured LLM, and secrets are redacted to `DEEPSEC_REDACTED_SECRET` before sending.

**Q: Too slow / too many false positives?**
Scan a single directory first (`deepsec shield scan ./src`), use `--format json` to see full rule names; rules live in `deepsec/shield/`. Open an issue or PR — contributions welcome.

---

## Next steps

- Docs: [Architecture](architecture.md) · [Shield Guide](shield-guide.md) · [Spear Guide](spear-guide.md)
- Bugs / feature requests: [Issues](https://github.com/Unclecheng-li/DeepSec/issues)
- Found it useful? Star the repo. Security folks welcome to contribute detection rules.

---

<div align="center">

**Make every line of AI-generated code accountable — in 3 minutes.**

</div>
