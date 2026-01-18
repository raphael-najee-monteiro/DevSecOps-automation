"""
Semgrep-based static code analysis for vulnerability detection.

Integrates Semgrep for real security scanning instead of pattern matching.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

from src.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SemgrepFinding:
    """A security finding from Semgrep."""
    rule_id: str
    cwe_id: str
    severity: str
    message: str
    file_path: str
    line_number: int
    code: str


class SemgrepAnalyzer:
    """Real static analysis using Semgrep."""

    # Map Semgrep rule IDs to CWE IDs
    RULE_TO_CWE = {
        'python.django.security.sql-injection-dos': 'CWE-89',
        'python.lang.security.insecure-md5-usage': 'CWE-327',
        'python.lang.security.hardcoded-secret': 'CWE-798',
        'python.lang.security.insecure-deserialization': 'CWE-502',
        'python.lang.security.exec-used': 'CWE-95',
        'python.lang.security.insecure-hash-functions': 'CWE-327',
        'python.lang.security.injection.os': 'CWE-78',
        'python.lang.security.injection.sql': 'CWE-89',
        'python.lang.security.eval': 'CWE-95',
        'python.django.security.injection.sql': 'CWE-89',
        'python.flask.security.xss.manual-escape': 'CWE-79',
        'python.lang.security.dangerous-subprocess-use': 'CWE-78',
    }

    # Severity mapping
    SEVERITY_MAP = {
        'ERROR': 'HIGH',
        'WARNING': 'MEDIUM',
        'INFO': 'LOW',
    }

    def __init__(self, config: str = 'p/security-audit'):
        """
        Initialize Semgrep analyzer.

        Args:
            config: Semgrep configuration (default: security audit rules)
        """
        self.config = config
        self._verify_semgrep_installed()

    def _verify_semgrep_installed(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Semgrep found: {result.stdout.strip()}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Semgrep not installed. Install with: pip install semgrep")
            return False

    def analyze(self, code: str) -> List[SemgrepFinding]:
        """
        Analyze code for vulnerabilities using Semgrep.

        Args:
            code: Python code to analyze

        Returns:
            List of SemgrepFinding objects
        """
        findings = []

        try:
            # Write code to temporary file
            with tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.py',
                    delete=False,
                    dir='/tmp'
            ) as f:
                f.write(code)
                temp_file = f.name

            try:
                # Run Semgrep
                logger.debug(f"Running Semgrep on {temp_file}")
                result = subprocess.run(
                    [
                        'semgrep',
                        '--json',
                        '--config', self.config,
                        '--quiet',
                        temp_file
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode in [0, 1]:  # 0 = no findings, 1 = findings found
                    findings = self._parse_results(result.stdout)
                    logger.info(f"Found {len(findings)} vulnerabilities")
                else:
                    logger.warning(f"Semgrep error: {result.stderr}")

            finally:
                # Clean up temp file
                Path(temp_file).unlink(missing_ok=True)

        except subprocess.TimeoutExpired:
            logger.error("Semgrep analysis timed out")
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")

        return findings

    def _parse_results(self, json_output: str) -> List[SemgrepFinding]:
        """
        Parse Semgrep JSON output.

        Args:
            json_output: JSON output from Semgrep

        Returns:
            List of SemgrepFinding objects
        """
        findings = []

        try:
            data = json.loads(json_output)

            for result in data.get('results', []):
                rule_id = result.get('check_id', 'unknown')
                cwe_id = self.RULE_TO_CWE.get(rule_id, 'CWE-0')

                severity = self.SEVERITY_MAP.get(
                    result.get('extra', {}).get('severity', 'WARNING'),
                    'MEDIUM'
                )

                finding = SemgrepFinding(
                    rule_id=rule_id,
                    cwe_id=cwe_id,
                    severity=severity,
                    message=result.get('extra', {}).get('message', ''),
                    file_path=result.get('path', ''),
                    line_number=result.get('start', {}).get('line', 0),
                    code=result.get('extra', {}).get('snippet', '')
                )
                findings.append(finding)
                logger.debug(f"Found: {cwe_id} at line {finding.line_number}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")

        return findings

    def get_findings_as_dict(self, findings: List[SemgrepFinding]) -> Dict:
        """Convert findings to dictionary format."""
        return {
            'total': len(findings),
            'by_severity': self._group_by_severity(findings),
            'by_cwe': self._group_by_cwe(findings),
            'findings': [
                {
                    'rule_id': f.rule_id,
                    'cwe_id': f.cwe_id,
                    'severity': f.severity,
                    'message': f.message,
                    'line': f.line_number,
                }
                for f in findings
            ]
        }

    def _group_by_severity(self, findings: List[SemgrepFinding]) -> Dict[str, int]:
        """Group findings by severity."""
        groups = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            groups[finding.severity] = groups.get(finding.severity, 0) + 1
        return groups

    def _group_by_cwe(self, findings: List[SemgrepFinding]) -> Dict[str, int]:
        """Group findings by CWE."""
        groups = {}
        for finding in findings:
            cwe = finding.cwe_id
            groups[cwe] = groups.get(cwe, 0) + 1
        return groups


# Example usage
if __name__ == '__main__':
    analyzer = SemgrepAnalyzer()

    # Test vulnerable code
    test_code = '''
import sqlite3

def search_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
'''

    findings = analyzer.analyze(test_code)

    print("Findings:")
    for f in findings:
        print(f"  {f.cwe_id}: {f.message} (line {f.line_number})")

    print("\nSummary:")
    summary = analyzer.get_findings_as_dict(findings)
    print(json.dumps(summary, indent=2))