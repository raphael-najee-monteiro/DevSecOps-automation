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
import subprocess # Added import for subprocess
import bcrypt # Added import for bcrypt


# -----------------------------------------------------------------------------
# SQL Injection (CWE-89)
# -----------------------------------------------------------------------------

def get_user(username):
    """Fetch user from database - SECURE against SQL injection."""
    conn = sqlite3.connect('users.db')
    # FIX: Use parameterized query to prevent SQL injection.
    # The '?' acts as a placeholder for the username.
    # The actual username is passed as a tuple to conn.execute().
    query = "SELECT * FROM users WHERE username = ?"
    try:
        return conn.execute(query, (username,)).fetchone()
    finally:
        conn.close()


def search_products(search_term):
    """Search products - SECURE against SQL injection."""
    conn = sqlite3.connect('shop.db')
    # FIX: Use parameterized query to prevent SQL injection.
    # The '?' acts as a placeholder for the search term.
    # The actual search term, including wildcards, is passed as a tuple.
    query = "SELECT * FROM products WHERE name LIKE ?"
    try:
        return conn.execute(query, (f"%{search_term}%",)).fetchall()
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Command Injection (CWE-78)
# -----------------------------------------------------------------------------

def list_files(directory):
    """List files in directory - SECURE against command injection."""
    # FIX: Use subprocess.run with a list of arguments to prevent command injection.
    # 'shell=False' (default for list arguments) ensures user input is treated as data, not commands.
    # 'check=True' raises an exception if the command returns a non-zero exit code.
    try:
        subprocess.run(['ls', '-la', directory], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error listing files in {directory}: {e}")
    except FileNotFoundError:
        print(f"Error: 'ls' command not found. Is it in your PATH?")


def ping_host(hostname):
    """Ping a host - SECURE against command injection."""
    # FIX: Use subprocess.run with a list of arguments to prevent command injection.
    # 'shell=False' (default for list arguments) ensures user input is treated as data, not commands.
    # 'check=True' raises an an exception if the command returns a non-zero exit code.
    try:
        # Note: 'ping' command arguments might vary slightly across OS.
        # This example uses common Linux/macOS syntax.
        subprocess.run(['ping', '-c', '4', hostname], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error pinging {hostname}: {e}")
    except FileNotFoundError:
        print(f"Error: 'ping' command not found. Is it in your PATH?")


# -----------------------------------------------------------------------------
# Weak Cryptography (CWE-327)
# -----------------------------------------------------------------------------

def hash_password(password):
    """Hash a password - SECURE: using bcrypt for strong password hashing."""
    # FIX: Use bcrypt, a strong password hashing algorithm.
    # bcrypt automatically handles salting and is designed to be slow,
    # making brute-force attacks much harder.
    # password must be bytes, and the output is bytes, so decode to string.
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')


def hash_token(token):
    """Hash a token - SECURE: using SHA-256 for strong hashing."""
    # FIX: Use hashlib.sha256, a stronger cryptographic hash function,
    # instead of the deprecated SHA1.
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


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