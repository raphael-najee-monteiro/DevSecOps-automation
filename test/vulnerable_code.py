"""
Test vulnerable code patterns for Semgrep detection.
Use this to verify Semgrep integration is working correctly.
"""

# ============================================================================
# CWE-89: SQL Injection
# ============================================================================

def vulnerable_sql_injection(username):
    """Vulnerable: Direct string interpolation in SQL query."""
    import sqlite3
    conn = sqlite3.connect('db.db')
    # VULNERABLE: User input directly in query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()


def secure_sql_injection(username):
    """Secure: Using parameterized queries."""
    import sqlite3
    conn = sqlite3.connect('db.db')
    # SECURE: Parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    return conn.execute(query, (username,)).fetchall()


# ============================================================================
# CWE-78: Command Injection
# ============================================================================

def vulnerable_command_injection(directory):
    """Vulnerable: OS command with user input."""
    import os
    # VULNERABLE: User input in shell command
    os.system(f"ls -la {directory}")


def secure_command_injection(directory):
    """Secure: Using subprocess without shell."""
    import subprocess
    # SECURE: No shell, arguments as list
    subprocess.run(['ls', '-la', directory], shell=False)


# ============================================================================
# CWE-327: Weak Cryptographic Algorithm
# ============================================================================

def vulnerable_weak_crypto(password):
    """Vulnerable: Using MD5 for password hashing."""
    import hashlib
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def secure_weak_crypto(password):
    """Secure: Using bcrypt for password hashing."""
    import bcrypt
    # SECURE: bcrypt with salt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


# ============================================================================
# CWE-502: Deserialization of Untrusted Data
# ============================================================================

def vulnerable_deserialization(data):
    """Vulnerable: Using pickle on untrusted data."""
    import pickle
    # VULNERABLE: Pickle can execute arbitrary code
    return pickle.loads(data)


def secure_deserialization(data):
    """Secure: Using JSON for untrusted data."""
    import json
    # SECURE: JSON is safe, no arbitrary code execution
    return json.loads(data)


# ============================================================================
# CWE-798: Hardcoded Secrets
# ============================================================================

def vulnerable_hardcoded_secrets():
    """Vulnerable: Credentials hardcoded in source."""
    # VULNERABLE: Hardcoded API key
    API_KEY = "sk-12345678abcdefghijklmnop"
    DATABASE_URL = "postgresql://user:password@localhost/db"
    return API_KEY, DATABASE_URL


def secure_hardcoded_secrets():
    """Secure: Using environment variables."""
    import os
    # SECURE: Credentials from environment
    API_KEY = os.getenv('API_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL')
    return API_KEY, DATABASE_URL


# ============================================================================
# CWE-79: Cross-Site Scripting
# ============================================================================

def vulnerable_xss(user_input):
    """Vulnerable: Rendering user input without escaping."""
    # VULNERABLE: User input directly in HTML
    return f"<html><body>{user_input}</body></html>"


def secure_xss(user_input):
    """Secure: HTML escaping."""
    from markupsafe import escape
    # SECURE: User input is escaped
    return f"<html><body>{escape(user_input)}</body></html>"


# ============================================================================
# CWE-95: Use of exec() and eval()
# ============================================================================

def vulnerable_eval(user_code):
    """Vulnerable: Using eval on user input."""
    # VULNERABLE: eval can execute arbitrary code
    return eval(user_code)


def secure_eval(user_code):
    """Secure: Use safe evaluation."""
    import ast
    # SECURE: Parse and validate, don't execute
    try:
        tree = ast.parse(user_code, mode='eval')
        return ast.literal_eval(tree.body)
    except (ValueError, SyntaxError):
        return None


# ============================================================================
# CWE-732: Incorrect Permission Assignment
# ============================================================================

def vulnerable_file_permissions(filename, content):
    """Vulnerable: Creating file with default permissions."""
    # VULNERABLE: Default permissions may be too permissive
    with open(filename, 'w') as f:
        f.write(content)


def secure_file_permissions(filename, content):
    """Secure: Explicit restrictive permissions."""
    import os
    # SECURE: Explicit permissions, owner only
    with open(filename, 'w') as f:
        f.write(content)
    os.chmod(filename, 0o600)  # owner read/write only


# ============================================================================
# Test execution
# ============================================================================

if __name__ == '__main__':
    print("Test vulnerable code patterns loaded.")
    print("\nRun Semgrep to detect vulnerabilities:")
    print("  semgrep --config p/security-audit test_vulnerable_code.py")
    print("\nExpected findings:")
    print("  - CWE-89: SQL Injection")
    print("  - CWE-78: Command Injection")
    print("  - CWE-327: Weak Crypto")
    print("  - CWE-502: Insecure Deserialization")
    print("  - CWE-798: Hardcoded Secrets")
    print("  - CWE-79: XSS")
    print("  - CWE-95: eval/exec")
    print("  - CWE-732: File Permissions")