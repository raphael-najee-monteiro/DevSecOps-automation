"""
Updated Security Agent with Semgrep integration for real vulnerability detection.
"""

import json
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

from google import genai

from src.logger import get_logger
from src.config import settings
from src.agent.prompts import CoTPrompts, CWETemplates, RCIPrompts, GenericPrompts
from src.tools.cwe_database import CWEDatabase
from src.tools.semgrep_analyzer import SemgrepAnalyzer, SemgrepFinding


logger = get_logger(__name__)


@dataclass
class VulnerabilityFinding:
    """A detected vulnerability."""

    cwe_id: str
    severity: str
    description: str
    line_number: Optional[int] = None
    tool: str = "semgrep"
    confidence: float = 0.85
    raw_finding: Dict = field(default_factory=dict)


@dataclass
class SecurityAnalysisResult:
    """Result of security analysis on code."""

    vulnerable: bool
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class VulnerabilityFix:
    """A proposed fix for a vulnerability."""

    cwe_id: str
    fixed_code: str
    explanation: str
    confidence: float = 0.5
    validation_status: str = "pending"
    iterations: int = 1


@dataclass
class AgentResult:
    """Final result from the security agent."""

    input_code: str
    original_analysis: SecurityAnalysisResult
    fixes: List[VulnerabilityFix] = field(default_factory=list)
    final_analysis: Optional[SecurityAnalysisResult] = None
    success: bool = False
    message: str = ""
    processing_time: float = 0.0

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "input_code": self.input_code,
            "original_analysis": {
                "vulnerable": self.original_analysis.vulnerable,
                "findings": [
                    {
                        "cwe_id": f.cwe_id,
                        "severity": f.severity,
                        "description": f.description,
                        "line": f.line_number,
                    }
                    for f in self.original_analysis.findings
                ],
            },
            "fixes": [
                {
                    "cwe_id": f.cwe_id,
                    "fixed_code": f.fixed_code,
                    "explanation": f.explanation,
                    "confidence": f.confidence,
                    "iterations": f.iterations,
                }
                for f in self.fixes
            ],
            "success": self.success,
            "message": self.message,
            "processing_time": self.processing_time,
        }


class SecurityAgent:
    """
    AI agent for detecting and fixing security vulnerabilities.

    Now uses real Semgrep for vulnerability detection!
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the security agent.

        Args:
            api_key: Google Gemini API key
        """
        self.api_key = api_key or settings.gemini_api_key
        self.model = settings.gemini_model
        self.max_tokens = settings.gemini_max_tokens
        self.timeout = settings.agent_timeout
        self.max_iterations = settings.agent_max_iterations

        # Initialize real tools
        genai.configure(api_key=self.api_key)
        self.client = genai.GenerativeModel(self.model)
        self.cwe_db = CWEDatabase()
        self.semgrep = SemgrepAnalyzer(config='p/security-audit')

        logger.info(f"Security Agent initialized with model {self.model}")
        logger.info("Using Semgrep for real vulnerability detection")

    async def analyze_and_fix(self, code: str) -> AgentResult:
        """
        Main entry point: analyze code and attempt to fix vulnerabilities.

        Args:
            code: Python code to analyze

        Returns:
            AgentResult with findings and fixes
        """
        import time
        start_time = time.time()

        logger.info("Starting vulnerability analysis and remediation")

        try:
            # Step 1: Analyze with Semgrep
            analysis = await self._analyze_code(code)

            if not analysis.vulnerable:
                logger.info("No vulnerabilities detected")
                return AgentResult(
                    input_code=code,
                    original_analysis=analysis,
                    success=True,
                    message="Code is secure",
                    processing_time=time.time() - start_time,
                )

            logger.info(f"Found {len(analysis.findings)} vulnerabilities")

            # Step 2: Generate fixes for each finding
            fixes = []
            for finding in analysis.findings:
                fix = await self._generate_fix(code, finding)
                if fix:
                    fixes.append(fix)

            # Step 3: Apply fixes and re-analyze
            fixed_code = code
            if fixes:
                fixed_code = await self._apply_fixes(code, fixes)

            # Step 4: Validate fixes
            final_analysis = await self._analyze_code(fixed_code)

            success = not final_analysis.vulnerable
            message = f"Fixed {len(fixes)} vulnerabilities" if success else "Some vulnerabilities remain"

            return AgentResult(
                input_code=code,
                original_analysis=analysis,
                fixes=fixes,
                final_analysis=final_analysis,
                success=success,
                message=message,
                processing_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}")
            return AgentResult(
                input_code=code,
                original_analysis=SecurityAnalysisResult(vulnerable=False),
                success=False,
                message=f"Error: {str(e)}",
                processing_time=time.time() - start_time,
            )

    async def _analyze_code(self, code: str) -> SecurityAnalysisResult:
        """
        Analyze code for vulnerabilities using REAL Semgrep.

        Args:
            code: Code to analyze

        Returns:
            SecurityAnalysisResult with real findings
        """
        logger.debug("Analyzing code with Semgrep")

        # Use real Semgrep analysis
        semgrep_findings = self.semgrep.analyze(code)

        # Convert to VulnerabilityFinding objects
        findings = [
            VulnerabilityFinding(
                cwe_id=sf.cwe_id,
                severity=sf.severity,
                description=sf.message,
                line_number=sf.line_number,
                tool='semgrep',
                confidence=0.85,
                raw_finding={
                    'rule_id': sf.rule_id,
                    'code': sf.code,
                }
            )
            for sf in semgrep_findings
        ]

        return SecurityAnalysisResult(
            vulnerable=len(findings) > 0,
            findings=findings,
            raw_output="",
        )

    async def _generate_fix(
        self,
        code: str,
        finding: VulnerabilityFinding,
    ) -> Optional[VulnerabilityFix]:
        """
        Generate a fix for a specific vulnerability using LLM.

        Args:
            code: Original code
            finding: Vulnerability finding

        Returns:
            VulnerabilityFix or None
        """
        logger.info(f"Generating fix for {finding.cwe_id}")

        try:
            # Get CWE context
            cwe_context = CWETemplates.get_template(finding.cwe_id)

            # Use Chain-of-Thought for reasoning
            prompt = CoTPrompts.generate_fix_with_reasoning(
                code,
                {"description": finding.description},
                cwe_context,
            )

            # Call LLM
            logger.debug(f"Calling LLM for {finding.cwe_id}")
            response = self.client.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=self.max_tokens,
                    temperature=0.3,
                )
            )

            if not response or not response.text:
                logger.warning("Empty response from LLM")
                return None

            response_text = response.text
            logger.debug(f"LLM Response: {response_text[:200]}...")

            # Extract fixed code
            fixed_code = self._extract_code_from_response(response_text)

            if not fixed_code:
                logger.warning("Could not extract code from response")
                return None

            return VulnerabilityFix(
                cwe_id=finding.cwe_id,
                fixed_code=fixed_code,
                explanation=response_text,
                confidence=0.7,
                validation_status="pending",
                iterations=1,
            )

        except Exception as e:
            logger.error(f"Error generating fix: {str(e)}")
            return None

    async def _apply_fixes(self, code: str, fixes: List[VulnerabilityFix]) -> str:
        """
        Apply fixes to code.

        Args:
            code: Original code
            fixes: List of fixes to apply

        Returns:
            Fixed code
        """
        if not fixes:
            return code

        # For now, apply the first fix
        # In production, would merge multiple fixes intelligently
        return fixes[0].fixed_code

    def _extract_code_from_response(self, response: str) -> Optional[str]:
        """
        Extract Python code from LLM response.

        Args:
            response: Response text from LLM

        Returns:
            Extracted code or None
        """
        import re

        # Try Python code blocks first
        patterns = [
            r'```python\n(.*?)```',
            r'```Python\n(.*?)```',
            r'```\n(.*?)```',
        ]

        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                code = match.group(1).strip()
                if len(code) > 10:
                    logger.debug("Extracted code from code block")
                    return code

        return None

    async def validate_fix(self, original_code: str, fixed_code: str) -> bool:
        """
        Validate that a fix is correct.

        Args:
            original_code: Original code
            fixed_code: Fixed code

        Returns:
            True if valid
        """
        try:
            prompt = GenericPrompts.validate_fix(original_code, fixed_code)

            response = self.client.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=500,
                )
            )

            if not response or not response.text:
                return False

            return "VALID" in response.text.upper()

        except Exception as e:
            logger.error(f"Error validating fix: {e}")
            return False


async def main():
    """Example usage of the security agent with Semgrep."""

    # Example vulnerable code
    vulnerable_code = """
import sqlite3

def search_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
"""

    agent = SecurityAgent()
    result = await agent.analyze_and_fix(vulnerable_code)

    print("=" * 80)
    print("SECURITY AGENT RESULT (WITH SEMGREP)")
    print("=" * 80)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())