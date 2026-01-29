# DevSecOps Agent

[![DevSecOps Agent](https://github.com/raphael-najee-monteiro/DevSecOps-automation/actions/workflows/demo.yml/badge.svg)](https://github.com/raphael-najee-monteiro/DevSecOps-automation/actions/workflows/demo.yml)

**An AI-powered GitHub Action that automatically detects and fixes security vulnerabilities in your Python code.**

```
Push code  ──>  Scan for vulnerabilities  ──>  AI fixes issues  ──>  Auto-commit
```

---

## What It Does

When you push code or open a pull request, this agent:

1. **Scans** your Python files for security vulnerabilities
2. **Analyzes** issues using CWE (Common Weakness Enumeration) classifications
3. **Fixes** vulnerabilities using AI-powered code generation
4. **Commits** the fixes automatically with detailed descriptions

No manual intervention required. Security issues get fixed before they reach production.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GitHub Actions Workflow                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│   │   PUSH   │───>│   SCAN   │───>│   FIX    │───>│  COMMIT  │              │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│                         │              │               │                    │
│                         ▼              ▼               ▼                    │
│                   ┌──────────┐   ┌──────────┐   ┌──────────┐                │
│                   │ Semgrep  │   │   LLM    │   │   Git    │                │
│                   │ Patterns │   │  (AI)    │   │   Push   │                │
│                   │   CWE    │   │   CoT    │   │          │                │
│                   └──────────┘   └──────────┘   └──────────┘                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

On Push:        Scans code → Fixes vulnerabilities → Commits & pushes fixes
On PR:          Scans code → Fixes vulnerabilities → Comments findings on PR
```

---

## Quick Start

### 1. Get an LLM API Key

Get an API key from your preferred LLM provider:
- [Google AI Studio](https://aistudio.google.com/app/apikey) (Gemini)
- [OpenAI](https://platform.openai.com/api-keys)
- Or any compatible LLM API

### 2. Add Secret to Your Repository

Go to your repo **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

- Name: `LLM_API_KEY`
- Value: Your API key

### 3. Create the Workflow

Add this file to your project at `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Run DevSecOps Agent
        uses: raphael-najee-monteiro/DevSecOps-automation@v1
        with:
          llm_api_key: ${{ secrets.LLM_API_KEY }}
```

### 4. Push and Watch

Push any code. The agent will scan it, fix vulnerabilities, and commit the fixes automatically.

---

## Configuration

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `llm_api_key` | API key for LLM provider (**required**) | - |
| `path` | Directory or file to scan | `.` |
| `auto_fix` | Apply fixes automatically | `true` |
| `auto_commit` | Commit and push fixes | `true` |
| `python_version` | Python version | `3.11` |
| `fail_on_vulnerabilities` | Fail workflow if unfixed issues remain | `false` |

### Outputs

| Output | Description |
|--------|-------------|
| `vulnerabilities_found` | Number of issues detected |
| `fixes_applied` | Number of fixes applied |
| `files_modified` | List of modified files |
| `report_path` | Path to JSON report |

### Example: Scan Only (No Auto-Fix)

```yaml
- uses: raphael-najee-monteiro/DevSecOps-automation@v1
  with:
    llm_api_key: ${{ secrets.LLM_API_KEY }}
    auto_fix: 'false'
    auto_commit: 'false'
    fail_on_vulnerabilities: 'true'
```

### Example: Scan Specific Directory

```yaml
- uses: raphael-najee-monteiro/DevSecOps-automation@v1
  with:
    llm_api_key: ${{ secrets.LLM_API_KEY }}
    path: 'src/'
```

See [`example_workflows/`](example_workflows/) for more configurations.

---

## What Gets Detected & Fixed

| CWE | Vulnerability | Example |
|-----|---------------|---------|
| CWE-89 | SQL Injection | `f"SELECT * FROM users WHERE id = {user_id}"` |
| CWE-78 | Command Injection | `os.system(f"echo {user_input}")` |
| CWE-79 | Cross-Site Scripting (XSS) | Unescaped user input in HTML |
| CWE-327 | Weak Cryptography | Using MD5 or SHA1 for passwords |
| CWE-502 | Unsafe Deserialization | `pickle.loads(untrusted_data)` |
| CWE-798 | Hardcoded Credentials | `password = "admin123"` |
| CWE-95 | Code Injection | `eval(user_input)` |
| CWE-732 | Incorrect Permissions | `os.chmod(file, 0o777)` |

Plus 100+ additional security rules via Semgrep.

---

## How the AI Fixes Code

The agent uses a multi-step reasoning process:

```
1. DETECT      Pattern matching + Semgrep static analysis
                        ↓
2. CLASSIFY    Map to CWE category (SQL injection, XSS, etc.)
                        ↓
3. REASON      Chain-of-Thought analysis of the vulnerability
                        ↓
4. FIX         Generate secure code using CWE-specific templates
                        ↓
5. VALIDATE    Re-scan to verify the fix worked
```

### Example Fix

**Before (vulnerable):**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
```

**After (fixed by agent):**
```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
```

---

## Local Usage

You can also run the agent locally:

```bash
# Install
pip install -r requirements.txt

# Scan a directory
python -m src.agent.main src/

# Scan and fix
python -m src.agent.main src/ --fix

# Generate report
python -m src.agent.main src/ --fix --output report.json
```

---

## Architecture

```
src/
├── agent/
│   ├── main.py              # CLI entry point
│   ├── security_agent.py    # Core orchestration
│   └── prompts.py           # LLM prompt templates
├── tools/
│   ├── semgrep_analyzer.py  # Static analysis
│   └── cwe_database.py      # Vulnerability knowledge base
└── config.py                # Configuration
```

| Component | Technology | Purpose |
|-----------|------------|---------|
| Detection | Semgrep, Pattern Matching | Find vulnerabilities |
| Analysis | CWE Database | Classify and understand issues |
| Reasoning | LLM (AI) | Generate intelligent fixes |
| Integration | GitHub Actions | Automate the workflow |
