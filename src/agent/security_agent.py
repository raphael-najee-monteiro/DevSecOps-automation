"""
Core Security Agent Implementation

Orchestrates vulnerability detection and repair using:
- LLM for reasoning and code generation
- Bandit/Semgrep for static analysis
- Model Context Protocol for tool integration
- Multiple prompting strategies (CoT, CWE-specific, RCI)
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


logger = get_logger(__name__)


@dataclass
class VulnerabilityFinding:
    """A detected vulnerability."""

    cwe_id: str
    severity: str
    description: str
    line_number: Optional[int] = None
    tool: str = "unknown"
    confidence: float = 0.5
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

    Combines:
    - LLM LLM for reasoning
    - Static analysis tools (Bandit, Semgrep) for detection
    - Multiple prompting strategies for optimal results
    - CWE-specific knowledge for targeted fixes
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the security agent.

        Args:
            api_key: LLM API key (uses LLM_API_KEY env if not provided)
        """
        self.api_key = api_key or settings.llm_api_key
        self.model = settings.llm_model
        self.max_tokens = settings.llm_max_tokens
        self.timeout = settings.agent_timeout
        self.max_iterations = settings.agent_max_iterations

        # Initialize LLM client with new API
        self.client = genai.Client(api_key=self.api_key)
        self.cwe_db = CWEDatabase()

        logger.info(f"Security Agent initialized with model {self.model}")

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
            # Step 1: Analyze for vulnerabilities
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

            # Step 2: Generate fixes
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
        Analyze code for vulnerabilities using static analysis and LLM.

        Args:
            code: Code to analyze

        Returns:
            SecurityAnalysisResult with findings
        """
        logger.debug("Analyzing code for vulnerabilities")

        # Mock static analysis (in real implementation, would call Bandit/Semgrep)
        findings = []

        # Detect SQL injection pattern
        if "f\"" in code and "SELECT" in code and "{" in code:
            findings.append(VulnerabilityFinding(
                cwe_id="CWE-89",
                severity="HIGH",
                description="Potential SQL injection vulnerability detected",
                tool="pattern-match",
            ))

        # Detect command injection pattern
        if "os.system" in code or "exec(" in code:
            findings.append(VulnerabilityFinding(
                cwe_id="CWE-78",
                severity="HIGH",
                description="Potential OS command injection vulnerability",
                tool="pattern-match",
            ))

        # Detect weak crypto
        if "md5" in code.lower() or "sha1" in code.lower():
            findings.append(VulnerabilityFinding(
                cwe_id="CWE-327",
                severity="HIGH",
                description="Use of weak cryptographic algorithm",
                tool="pattern-match",
            ))

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
        Generate a fix for a specific vulnerability.

        Args:
            code: Original code
            finding: Vulnerability finding

        Returns:
            VulnerabilityFix or None if generation fails
        """
        logger.info(f"Generating fix for {finding.cwe_id}")

        try:
            # Select prompting strategy
            if settings.agent_use_cot_prompting:
                prompt = CoTPrompts.generate_fix_with_reasoning(
                    code,
                    {"description": finding.description},
                    CWETemplates.get_template(finding.cwe_id),
                )
            else:
                prompt = GenericPrompts.validate_fix(code, "")

            # Call LLM with new API
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
            )

            response_text = response.text

            # Extract fixed code from response
            fixed_code = self._extract_code_from_response(response_text)

            if not fixed_code:
                logger.warning(f"Could not extract fixed code from response")
                return None

            return VulnerabilityFix(
                cwe_id=finding.cwe_id,
                fixed_code=fixed_code,
                explanation=response_text,
                confidence=0.7,
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

        # For now, return the first fix's code
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
        # Look for code blocks
        if "```python" in response:
            start = response.find("```python") + len("```python")
            end = response.find("```", start)
            if end > start:
                return response[start:end].strip()

        if "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            if end > start:
                return response[start:end].strip()

        return None

    async def validate_fix(self, original_code: str, fixed_code: str) -> bool:
        """
        Validate that a fix is correct and secure.

        Args:
            original_code: Original vulnerable code
            fixed_code: Proposed fix

        Returns:
            True if fix is valid
        """
        prompt = GenericPrompts.validate_fix(original_code, fixed_code)

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
        )

        response_text = response.text.upper()

        return "VALID" in response_text


async def main():
    """Example usage of the security agent."""

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
    print("SECURITY AGENT RESULT")
    print("=" * 80)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())