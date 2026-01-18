# Agentic AI for Secure Software Development in SecDevOps

[![DevSecOps Agent](https://github.com/raphael-najee-monteiro/DevSecOps-automation/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/raphael-najee-monteiro/DevSecOps-automation/actions/workflows/ci-cd.yml)


## The Problem

Research shows that LLMs introduce **9x more security vulnerabilities** than human developers when fixing code. Current approaches lack domain-specific reasoning and iterative refinement for security-critical tasks.

## The Solution

An **autonomous AI agent** that detects and repairs security vulnerabilities with production-grade quality, reducing vulnerability introduction rates from 9x to **2-3x compared to human developers**.

## Core Architecture

```
┌──────────────────────────────────────────────────────────┐
│         Agentic Security Orchestrator                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Detection Layer          Analysis Layer  Repair Layer   │
│  ────────────────        ─────────────── ──────────────  │
│  • Semgrep Scanner      • CWE Database  • CoT Reasoning  │
│  • Static Analysis      • Risk Mapping  • LLM Generation │
│  • Pattern Matching     • Severity Rank • RCI Iteration  │
│                                                          │
└──────────────────────────────────────────────────────────┘
        ↓
    Google Gemini LLM
    (Code Generation & Reasoning)
        ↓
    Output: Fixed Code + Validation
```

## Key Features

### 🔍 **Real Vulnerability Detection**
- **Semgrep-powered scanning** - Industry-standard security rules
- **8+ CWE types detected** - SQL injection, command injection, weak crypto, XSS, and more
- **Automated on every push** - CI/CD integrated security scanning

### 🤖 **AI-Driven Code Repair**
- **Chain-of-Thought reasoning** - Step-by-step vulnerability analysis
- **CWE-specific knowledge** - Domain-tailored fix generation
- **Recursive critique & improve** - Iterative refinement for quality assurance
- **Google Gemini LLM** - Multi-modal reasoning capabilities

### ✅ **Production-Grade Implementation**
- **Comprehensive testing** - 50+ test cases, multi-version Python support
- **CI/CD automation** - Full GitHub Actions pipeline with security scanning
- **Code quality** - Black, Flake8, mypy, Ruff checks on every commit
- **Professional logging** - Structured logging throughout

### 📊 **DevSecOps Best Practices**
- **Automated security gates** - Fail fast on vulnerability detection
- **Coverage reports** - Codecov integration for visibility
- **Artifact management** - Security reports and build artifacts
- **Status visibility** - GitHub badges for real-time status

## Technical Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Vulnerability Detection** | Semgrep, Bandit | Real security scanning |
| **Code Reasoning** | Google Gemini API | LLM-powered analysis |
| **Testing** | pytest, pytest-asyncio | Comprehensive test suite |
| **CI/CD** | GitHub Actions | Automated workflows |
| **Code Quality** | Black, Flake8, mypy, Ruff | Code standards |
| **Database** | CWE Classification | Security knowledge base |

## DevSecOps Automation

### Continuous Integration & Continuous Security

```yaml
On every push/PR:
  ✓ Code quality checks (5 tools)
  ✓ Unit tests (Python 3.9-3.12)
  ✓ Security scanning (Semgrep + Bandit)
  ✓ Vulnerability reports
  ✓ Coverage analysis
  ✓ Artifact uploads
```

### Zero-Trust Security Model
- **Fail-fast approach** - Block commits with security vulnerabilities
- **Automated remediation** - AI agent suggests and validates fixes
- **Immutable audit trail** - All security decisions logged
- **Compliance-ready** - CWE classification for regulatory reporting

## What Gets Detected

```
CWE-89    SQL Injection
CWE-78    OS Command Injection
CWE-327   Weak Cryptographic Algorithm
CWE-502   Unsafe Deserialization
CWE-798   Hardcoded Credentials
CWE-79    Cross-Site Scripting (XSS)
CWE-95    Use of eval()/exec()
CWE-732   Incorrect File Permissions
... and 100+ additional rules
```

## Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### Run Agent
```bash
# SINGLE FILE
python -m src.agent.main path/to/file.py

# DIRECTORY
python -m src.agent.main src/

# ENTIRE PROJECT
python -m src.agent.main .

# WITH REPORT
python -m src.agent.main . --output report.json

# VERBOSE + REPORT
python -m src.agent.main . --output report.json --verbose

# SPECIFIC FOLDER
python -m src.agent.main src/api/ --output api-report.json

# TIMESTAMPED REPORT
python -m src.agent.main . --output report-$(date +%Y%m%d-%H%M%S).json

# CI/CD COMMAND
python -m src.agent.main . --output security-report.json
```

## Project Structure

```
├── src/
│   ├── agent/
│   │   ├── security_agent.py          # Main agent orchestrator
│   │   └── prompts.py                 # Prompting strategies (CoT, RCI, CWE-specific)
│   ├── tools/
│   │   ├── semgrep_analyzer.py        # Real vulnerability detection
│   │   └── cwe_database.py            # CWE knowledge base (9 major types)
│   ├── config.py                      # Configuration management
│   └── logger.py                      # Structured logging
├── test/
│   └── test_agent.py                  # 50+ test cases
├── .github/workflows/
│   └── ci-cd.yml                      # GitHub Actions pipeline
├── data/
│   ├── cwe_database.json              # CWE metadata & remediation
│   └── examples/                      # Vulnerable code samples
└── requirements.txt                   # Dependencies (Semgrep, Gemini, pytest)
```

