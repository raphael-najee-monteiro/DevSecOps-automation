"""
Prompt templates for different vulnerability repair strategies.

Implements:
1. Chain-of-Thought (CoT) - Step-by-step reasoning
2. CWE-Specific Templates - Tailored guidance for each CWE
3. Recursive Critique & Improve (RCI) - Iterative refinement
"""

from typing import Dict, List, Optional


# ============================================================================
# CHAIN-OF-THOUGHT (CoT) PROMPTS
# ============================================================================

class CoTPrompts:
    """Chain-of-Thought prompting templates."""

    @staticmethod
    def analyze_vulnerability(code: str, vulnerability: Dict) -> str:
        """
        Prompt to analyze a vulnerability step-by-step.
        
        Args:
            code: Python code to analyze
            vulnerability: Vulnerability details from scanner
        
        Returns:
            Formatted prompt string
        """
        cwe_id = vulnerability.get("cwe_id", "UNKNOWN")
        severity = vulnerability.get("severity", "UNKNOWN")
        description = vulnerability.get("description", "")
        
        return f"""You are a security expert. Analyze this vulnerability step-by-step:

STEP 1: Identify the vulnerability type (CWE)
STEP 2: Explain why this code is vulnerable
STEP 3: Describe the security risk and potential impact
STEP 4: Propose a secure alternative implementation
STEP 5: Write the fixed code

---

VULNERABLE CODE:
```python
{code}
```

---

DETECTED VULNERABILITY:
- CWE ID: {cwe_id}
- Severity: {severity}
- Description: {description}

---

Please analyze this vulnerability step-by-step and provide the fixed code.
Ensure your fix:
1. Addresses the root cause of the vulnerability
2. Maintains the original functionality
3. Follows Python best practices
4. Includes comments explaining the security fix
"""

    @staticmethod
    def generate_fix_with_reasoning(code: str, vulnerability: Dict, cwe_context: str) -> str:
        """
        Prompt to generate a fix with detailed reasoning.
        
        Args:
            code: Vulnerable code
            vulnerability: Vulnerability info
            cwe_context: CWE documentation and guidance
        
        Returns:
            Formatted prompt string
        """
        return f"""You are a security expert specializing in vulnerability remediation.

TASK: Fix the security vulnerability in the code below.

VULNERABLE CODE:
```python
{code}
```

DETECTED ISSUE:
{vulnerability.get('description', '')}

CWE BACKGROUND:
{cwe_context}

INSTRUCTIONS:
1. Think step-by-step about what makes this code vulnerable
2. Identify all potential attack vectors
3. Propose a secure fix that eliminates the vulnerability
4. Verify the fix doesn't introduce new vulnerabilities
5. Provide the complete fixed code

Format your response as:
ANALYSIS: [explain the vulnerability and its impact]
SOLUTION: [explain the fix approach]
FIXED_CODE:
```python
[provide the secure code]
```
"""


# ============================================================================
# CWE-SPECIFIC TEMPLATES
# ============================================================================

class CWETemplates:
    """Templates tailored to specific CWE types."""

    # CWE-89: SQL Injection
    SQL_INJECTION = """
CWE-89: SQL Injection

VULNERABILITY: SQL Injection occurs when user input is directly concatenated
into SQL queries without proper escaping or parameterization.

COMMON PATTERNS:
- String concatenation: query = f"SELECT * FROM users WHERE id={user_id}"
- Format strings: query = "SELECT * FROM users WHERE username='" + username + "'"
- Old string formatting: query = "SELECT * FROM users WHERE email='%s'" % user_input

FIX STRATEGIES:
1. Use parameterized queries (prepared statements)
2. Use ORM frameworks (SQLAlchemy, Django ORM)
3. Input validation and whitelisting
4. Escape special characters properly

SECURE EXAMPLE:
```python
# Using parameterized query (CORRECT)
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

VULNERABLE PATTERN:
```python
# String concatenation (INCORRECT)
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```
"""

    # CWE-79: Cross-Site Scripting (XSS)
    CROSS_SITE_SCRIPTING = """
CWE-79: Cross-Site Scripting (XSS)

VULNERABILITY: XSS occurs when user input is rendered in HTML/JavaScript
without proper escaping or sanitization.

COMMON PATTERNS:
- Rendering user input directly in templates
- DOM manipulation with unsanitized data
- Using innerHTML with user content
- eval() with user input

FIX STRATEGIES:
1. HTML escape user input
2. Use template auto-escaping
3. Use Content Security Policy (CSP)
4. Whitelist allowed HTML tags
5. Use dedicated libraries (bleach, markupsafe)

SECURE EXAMPLE:
```python
from markupsafe import escape
html = f"<p>{escape(user_input)}</p>"
```

VULNERABLE PATTERN:
```python
html = f"<p>{user_input}</p>"  # Unescaped!
```
"""

    # CWE-78: OS Command Injection
    COMMAND_INJECTION = """
CWE-78: OS Command Injection

VULNERABILITY: Command injection occurs when user input is passed to OS
commands without proper escaping or sandboxing.

COMMON PATTERNS:
- os.system() with user input
- subprocess.call() with shell=True
- shell commands with string concatenation
- eval() or exec() with user input

FIX STRATEGIES:
1. Use subprocess with shell=False and list arguments
2. Use shlex.quote() for proper escaping
3. Input validation and whitelisting
4. Avoid os.system() and similar functions
5. Run with minimal privileges

SECURE EXAMPLE:
```python
import subprocess
subprocess.run(['ls', '-l', user_provided_directory], shell=False)
```

VULNERABLE PATTERN:
```python
import os
os.system(f"ls -l {user_directory}")  # Dangerous!
```
"""

    # CWE-732: Incorrect Permission Assignment
    PERMISSION_ASSIGNMENT = """
CWE-732: Incorrect Permission Assignment

VULNERABILITY: Files/directories created with overly permissive permissions,
allowing unauthorized access.

COMMON PATTERNS:
- Creating files without explicit permissions
- Default permissions that are too open
- World-readable sensitive files
- Temporary files in shared directories

FIX STRATEGIES:
1. Explicitly set file permissions using chmod/mode parameter
2. Use restrictive defaults (0o600 for files, 0o700 for directories)
3. Create temporary files in secure locations
4. Validate and enforce permissions on sensitive operations
5. Use umask() to set restrictive defaults

SECURE EXAMPLE:
```python
import os
# Create file with restrictive permissions (owner read/write only)
with open('secrets.txt', 'w', encoding='utf-8') as f:
    os.chmod('secrets.txt', 0o600)
    f.write(secret_data)
```

VULNERABLE PATTERN:
```python
with open('secrets.txt', 'w') as f:  # Default permissions!
    f.write(secret_data)
```
"""

    # CWE-327: Use of a Broken/Risky Cryptographic Algorithm
    WEAK_CRYPTO = """
CWE-327: Use of Broken or Risky Cryptographic Algorithm

VULNERABILITY: Using outdated or weak cryptographic algorithms that are
no longer considered secure against modern attacks.

COMMON PATTERNS:
- MD5 or SHA1 for password hashing
- DES or RC4 for encryption
- Hardcoded encryption keys
- No salt in password hashing
- Using random.random() for cryptography

FIX STRATEGIES:
1. Use bcrypt, scrypt, or argon2 for password hashing
2. Use AES-256 for encryption
3. Use cryptographically secure random (secrets, os.urandom)
4. Add salt to all password hashes
5. Keep cryptographic libraries updated

SECURE EXAMPLE:
```python
import bcrypt

# Hash password with bcrypt
password = b"user_password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

# Verify password
bcrypt.checkpw(password, hashed)
```

VULNERABLE PATTERN:
```python
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()  # WRONG!
```
"""

    @staticmethod
    def get_template(cwe_id: str) -> str:
        """
        Get template for specific CWE.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
        
        Returns:
            Template string or generic template if not found
        """
        templates = {
            "CWE-89": CWETemplates.SQL_INJECTION,
            "CWE-79": CWETemplates.CROSS_SITE_SCRIPTING,
            "CWE-78": CWETemplates.COMMAND_INJECTION,
            "CWE-732": CWETemplates.PERMISSION_ASSIGNMENT,
            "CWE-327": CWETemplates.WEAK_CRYPTO,
        }
        
        return templates.get(cwe_id, "")


# ============================================================================
# RECURSIVE CRITIQUE & IMPROVE (RCI) PROMPTS
# ============================================================================

class RCIPrompts:
    """Recursive Critique & Improve prompting templates."""

    @staticmethod
    def initial_fix(code: str, vulnerability: Dict) -> str:
        """
        Prompt to generate initial fix.
        
        Args:
            code: Vulnerable code
            vulnerability: Vulnerability details
        
        Returns:
            Formatted prompt string
        """
        return f"""Generate a security fix for the following vulnerable code.

VULNERABLE CODE:
```python
{code}
```

VULNERABILITY: {vulnerability.get('description', '')}

Provide the fixed code that eliminates this vulnerability:
```python
[FIXED CODE HERE]
```
"""

    @staticmethod
    def critique_fix(original_code: str, fixed_code: str, vulnerability: Dict) -> str:
        """
        Prompt to critique and improve a proposed fix.
        
        Args:
            original_code: Original vulnerable code
            fixed_code: Proposed fix
            vulnerability: Vulnerability details
        
        Returns:
            Formatted prompt string
        """
        return f"""Review this security fix and identify any issues.

ORIGINAL VULNERABLE CODE:
```python
{original_code}
```

PROPOSED FIX:
```python
{fixed_code}
```

VULNERABILITY TO ADDRESS: {vulnerability.get('description', '')}

Please analyze:
1. Does the fix address the vulnerability?
2. Are there any edge cases not handled?
3. Are there any new security issues introduced?
4. Does it maintain the original functionality?
5. What improvements could be made?

Format your response as:
ANALYSIS: [your critique]
IMPROVED_FIX:
```python
[improved code if needed, or say "No changes needed" if fix is good]
```
"""

    @staticmethod
    def iterative_improve(
        code: str,
        previous_fixes: List[str],
        vulnerability: Dict,
        iteration: int = 1,
    ) -> str:
        """
        Prompt for iterative improvement of fixes.
        
        Args:
            code: Original vulnerable code
            previous_fixes: List of previous fix attempts
            vulnerability: Vulnerability details
            iteration: Current iteration number
        
        Returns:
            Formatted prompt string
        """
        fixes_text = "\n".join(
            f"Attempt {i+1}:\n```python\n{fix}\n```\n"
            for i, fix in enumerate(previous_fixes)
        )
        
        return f"""This is iteration {iteration} of improving a security fix.

ORIGINAL CODE:
```python
{code}
```

VULNERABILITY: {vulnerability.get('description', '')}

PREVIOUS FIX ATTEMPTS:
{fixes_text}

Based on the previous attempts, provide an improved fix that:
1. Addresses the vulnerability completely
2. Handles edge cases
3. Maintains original functionality
4. Follows security best practices
5. Is clear and maintainable

IMPROVED FIX:
```python
[IMPROVED CODE HERE]
```

EXPLANATION: [Explain what changed and why]
"""


# ============================================================================
# GENERIC TEMPLATES
# ============================================================================

class GenericPrompts:
    """Generic prompts for general vulnerability analysis."""

    @staticmethod
    def scan_and_categorize(code: str) -> str:
        """
        Prompt to scan code and categorize vulnerabilities.
        
        Args:
            code: Code to analyze
        
        Returns:
            Formatted prompt string
        """
        return f"""Analyze this code for security vulnerabilities and categorize them.

CODE:
```python
{code}
```

For each vulnerability found:
1. Identify the CWE type
2. Describe the vulnerability
3. Explain the potential impact
4. Suggest a fix

Format as JSON with structure:
{{
    "vulnerabilities": [
        {{
            "cwe_id": "CWE-XXX",
            "severity": "HIGH|MEDIUM|LOW",
            "description": "...",
            "impact": "...",
            "suggested_fix": "..."
        }}
    ]
}}
"""

    @staticmethod
    def validate_fix(original_code: str, fixed_code: str) -> str:
        """
        Prompt to validate a security fix.
        
        Args:
            original_code: Original code
            fixed_code: Fixed code
        
        Returns:
            Formatted prompt string
        """
        return f"""Validate whether this security fix is correct and complete.

ORIGINAL CODE:
```python
{original_code}
```

FIXED CODE:
```python
{fixed_code}
```

Assess:
1. Does the fix address the vulnerability?
2. Are there any regression risks?
3. Does it maintain functionality?
4. Are there any new vulnerabilities?
5. Is the fix optimal?

Provide a validation result:
VERDICT: [VALID|NEEDS_IMPROVEMENT|INVALID]
REASONING: [explain your assessment]
CONFIDENCE: [HIGH|MEDIUM|LOW]
"""


def get_vulnerability_context(cwe_id: str) -> str:
    """
    Get CWE-specific context for a vulnerability.
    
    Args:
        cwe_id: CWE identifier
    
    Returns:
        Context string with CWE information
    """
    return CWETemplates.get_template(cwe_id)
