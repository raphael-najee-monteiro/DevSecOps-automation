"""
CWE Database: Common Weakness Enumeration lookup and management.

Provides access to CWE information, descriptions, and remediation guidance.
"""

import json
from typing import Dict, Optional, List
from pathlib import Path

from src.logger import get_logger
from src.config import settings


logger = get_logger(__name__)


class CWEDatabase:
    """
    Database of CWE information.
    
    Provides CWE descriptions, examples, and remediation guidance.
    """

    def __init__(self):
        """Initialize CWE database."""
        self.cwes: Dict[str, Dict] = self._load_cwe_database()
        logger.info(f"Loaded {len(self.cwes)} CWE definitions")

    def _load_cwe_database(self) -> Dict[str, Dict]:
        """Load CWE database from JSON file."""
        db_path = settings.cwe_database_path
        
        if db_path.exists():
            try:
                with open(db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load CWE database: {e}")
        
        # Return built-in CWE definitions
        return self._get_default_cwes()

    def _get_default_cwes(self) -> Dict[str, Dict]:
        """Get default CWE definitions."""
        return {
            "CWE-89": {
                "name": "SQL Injection",
                "severity": "HIGH",
                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
                "weakness_abstraction": "Base",
                "languages": ["PHP", "Python", "Java", "C#", "JavaScript"],
                "remediation": [
                    "Use parameterized queries or prepared statements",
                    "Use ORM frameworks",
                    "Input validation and whitelist",
                    "Escape special characters",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/89.html",
            },
            "CWE-79": {
                "name": "Cross-site Scripting (XSS)",
                "severity": "HIGH",
                "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                "weakness_abstraction": "Base",
                "languages": ["JavaScript", "PHP", "Python", "HTML", "CSS"],
                "remediation": [
                    "HTML escape user input",
                    "Use template auto-escaping",
                    "Implement Content Security Policy (CSP)",
                    "Use HTML sanitization libraries",
                    "Whitelist allowed HTML tags",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/79.html",
            },
            "CWE-78": {
                "name": "OS Command Injection",
                "severity": "HIGH",
                "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "Bash", "Perl", "PHP", "Java"],
                "remediation": [
                    "Use subprocess with shell=False",
                    "Use shlex.quote() for escaping",
                    "Input validation and whitelist",
                    "Avoid os.system() and similar functions",
                    "Run with minimal privileges",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/78.html",
            },
            "CWE-327": {
                "name": "Use of a Broken or Risky Cryptographic Algorithm",
                "severity": "HIGH",
                "description": "The software uses a broken or risky cryptographic algorithm or protocol.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "Java", "C++", "C#", "JavaScript"],
                "remediation": [
                    "Use bcrypt, scrypt, or argon2 for password hashing",
                    "Use AES-256 for encryption",
                    "Use cryptographically secure random (secrets module)",
                    "Add salt to password hashes",
                    "Keep crypto libraries updated",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/327.html",
            },
            "CWE-732": {
                "name": "Incorrect Permission Assignment for Critical Resource",
                "severity": "MEDIUM",
                "description": "The software specifies permissions for a security-critical resource in a way that allows unintended actors to read or modify the resource.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "Java", "C", "Bash"],
                "remediation": [
                    "Explicitly set file permissions",
                    "Use restrictive default permissions",
                    "Create temporary files in secure locations",
                    "Use umask() to set restrictive defaults",
                    "Validate and enforce permissions",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/732.html",
            },
            "CWE-434": {
                "name": "Unrestricted Upload of File with Dangerous Type",
                "severity": "MEDIUM",
                "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the environment.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "PHP", "Java", "JavaScript"],
                "remediation": [
                    "Whitelist allowed file types",
                    "Check file content (magic bytes), not just extension",
                    "Store uploads outside web root",
                    "Validate file size limits",
                    "Use antivirus scanning",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/434.html",
            },
            "CWE-502": {
                "name": "Deserialization of Untrusted Data",
                "severity": "HIGH",
                "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "Java", "C#", "PHP", "Ruby"],
                "remediation": [
                    "Avoid deserializing untrusted data",
                    "Use safe serialization formats (JSON)",
                    "Implement strict validation",
                    "Use allowlists for object types",
                    "Keep libraries updated",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/502.html",
            },
            "CWE-22": {
                "name": "Improper Limitation of a Pathname to a Restricted Directory",
                "severity": "MEDIUM",
                "description": "The software uses external input to construct a pathname that should be restricted within a limited directory, but does not properly neutralize special elements that can resolve to a location that is outside of the restricted directory.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "PHP", "Java", "C", "JavaScript"],
                "remediation": [
                    "Input validation and canonicalization",
                    "Whitelist allowed directories",
                    "Use os.path.normpath() and check bounds",
                    "Avoid path traversal patterns (..)",
                    "Use safe path operations",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/22.html",
            },
            "CWE-352": {
                "name": "Cross-Site Request Forgery (CSRF)",
                "severity": "MEDIUM",
                "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
                "weakness_abstraction": "Base",
                "languages": ["Python", "PHP", "Java", "JavaScript"],
                "remediation": [
                    "Implement CSRF tokens",
                    "Use SameSite cookie attribute",
                    "Validate Referer header",
                    "Require POST for state-changing operations",
                    "Use anti-CSRF libraries",
                ],
                "cwe_reference": "https://cwe.mitre.org/data/definitions/352.html",
            },
        }

    def get_cwe(self, cwe_id: str) -> Optional[Dict]:
        """
        Get CWE information by ID.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
        
        Returns:
            CWE information dictionary or None if not found
        """
        return self.cwes.get(cwe_id)

    def get_description(self, cwe_id: str) -> str:
        """Get CWE description."""
        cwe = self.get_cwe(cwe_id)
        return cwe["description"] if cwe else "Unknown CWE"

    def get_remediation(self, cwe_id: str) -> List[str]:
        """Get remediation steps for a CWE."""
        cwe = self.get_cwe(cwe_id)
        return cwe["remediation"] if cwe else []

    def get_name(self, cwe_id: str) -> str:
        """Get CWE name."""
        cwe = self.get_cwe(cwe_id)
        return cwe["name"] if cwe else "Unknown"

    def get_severity(self, cwe_id: str) -> str:
        """Get CWE severity."""
        cwe = self.get_cwe(cwe_id)
        return cwe["severity"] if cwe else "UNKNOWN"

    def list_all_cwes(self) -> List[str]:
        """List all CWE IDs in database."""
        return sorted(self.cwes.keys())

    def search_by_name(self, name: str) -> List[str]:
        """Search CWEs by name pattern."""
        name_lower = name.lower()
        results = []
        
        for cwe_id, cwe_info in self.cwes.items():
            if name_lower in cwe_info.get("name", "").lower():
                results.append(cwe_id)
        
        return results

    def save_to_file(self, path: Optional[Path] = None) -> None:
        """
        Save CWE database to JSON file.
        
        Args:
            path: File path (uses default if not provided)
        """
        path = path or settings.cwe_database_path
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w") as f:
            json.dump(self.cwes, f, indent=2)
        
        logger.info(f"CWE database saved to {path}")
