# Vulnerable Examples

This folder contains intentionally vulnerable code for demonstrating the DevSecOps Agent.

## How It Works

```
1. Push triggers workflow
2. demo.py.template (vulnerable) → copied to → demo.py
3. Agent scans demo.py
4. Agent fixes vulnerabilities
5. Fixed demo.py is committed
6. Next push repeats the cycle
```

## Files

| File | Purpose |
|------|---------|
| `demo.py.template` | Source of truth - always contains vulnerable code |
| `demo.py` | Working file - gets fixed by the agent |

## Vulnerabilities Included

- **CWE-89**: SQL Injection
- **CWE-78**: Command Injection
- **CWE-327**: Weak Cryptography (MD5, SHA1)
- **CWE-502**: Unsafe Deserialization (pickle)
- **CWE-95**: Code Injection (eval, exec)

## Warning

**DO NOT use this code in production.** These examples exist solely to demonstrate the agent's capabilities.