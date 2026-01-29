"""
Vulnerable Code Demo - This file contains intentional security vulnerabilities.

The DevSecOps Agent will automatically detect and fix these vulnerabilities
when code is pushed to the repository.

DO NOT use this code in production - it exists only to demonstrate the agent.
"""

import sqlite3
import os
import hashlib
import pickle


# -----------------------------------------------------------------------------
# SQL Injection (CWE-89)
# -----------------------------------------------------------------------------

def get_user(username):
    """Fetch user from database - VULNERABLE to SQL injection."""
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()


def search_products(search_term):
    """Search products - VULNERABLE to SQL injection."""
    conn = sqlite3.connect('shop.db')
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    return conn.execute(query).fetchall()


# -----------------------------------------------------------------------------
# Command Injection (CWE-78)
# -----------------------------------------------------------------------------

def list_files(directory):
    """List files in directory - VULNERABLE to command injection."""
    os.system(f"ls -la {directory}")


def ping_host(hostname):
    """Ping a host - VULNERABLE to command injection."""
    os.system(f"ping -c 4 {hostname}")


# -----------------------------------------------------------------------------
# Weak Cryptography (CWE-327)
# -----------------------------------------------------------------------------

def hash_password(password):
    """Hash a password - VULNERABLE: using weak MD5."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    """Hash a token - VULNERABLE: using weak SHA1."""
    return hashlib.sha1(token.encode()).hexdigest()


# -----------------------------------------------------------------------------
# Unsafe Deserialization (CWE-502)
# -----------------------------------------------------------------------------

def load_session(session_data):
    """Load session data - VULNERABLE to arbitrary code execution."""
    return pickle.loads(session_data)


def load_config(config_bytes):
    """Load config - VULNERABLE to arbitrary code execution."""
    return pickle.loads(config_bytes)


# -----------------------------------------------------------------------------
# Code Injection (CWE-95)
# -----------------------------------------------------------------------------

def calculate(expression):
    """Calculate expression - VULNERABLE to code injection."""
    return eval(expression)


def run_user_code(code):
    """Run user code - VULNERABLE to code injection."""
    exec(code)