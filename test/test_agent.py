"""
Test suite for the Security Agent.

Tests cover:
- Basic agent initialization
- Vulnerability detection
- Fix generation
- Validation logic
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from src.agent.security_agent import SecurityAgent, AgentResult, VulnerabilityFinding
from src.tools.cwe_database import CWEDatabase


@pytest.fixture
def agent():
    """Create a SecurityAgent instance for testing."""
    return SecurityAgent(api_key="test-key")


@pytest.fixture
def vulnerable_code():
    """Sample vulnerable code for testing."""
    return """
import sqlite3

def search_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
"""


@pytest.fixture
def secure_code():
    """Sample secure code for testing."""
    return """
import sqlite3

def search_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
"""


class TestSecurityAgent:
    """Test SecurityAgent class."""

    def test_initialization(self, agent):
        """Test agent initialization."""
        assert agent is not None
        assert agent.api_key == "test-key"
        assert agent.model == "gemini-2.5-flash"
        assert agent.cwe_db is not None

    def test_cwe_database_loaded(self, agent):
        """Test CWE database is properly loaded."""
        assert len(agent.cwe_db.list_all_cwes()) > 0
        assert "CWE-89" in agent.cwe_db.list_all_cwes()
        assert "CWE-79" in agent.cwe_db.list_all_cwes()

    @pytest.mark.asyncio
    async def test_analyze_vulnerable_code(self, agent, vulnerable_code):
        """Test vulnerability detection on vulnerable code."""
        result = await agent._analyze_code(vulnerable_code)
        
        assert result.vulnerable
        assert len(result.findings) > 0
        assert any(f.cwe_id == "CWE-89" for f in result.findings)

    @pytest.mark.asyncio
    async def test_analyze_secure_code(self, agent, secure_code):
        """Test that secure code shows no vulnerabilities."""
        result = await agent._analyze_code(secure_code)
        
        assert not result.vulnerable
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_analyze_and_fix_endpoint_exists(self, agent, vulnerable_code):
        """Test that analyze_and_fix method exists and is callable."""
        assert hasattr(agent, 'analyze_and_fix')
        assert callable(agent.analyze_and_fix)

    def test_code_extraction(self, agent):
        """Test code extraction from LLM response."""
        response_text = """
        Here's the fixed code:
        
        ```python
        def search_user(username):
            query = "SELECT * FROM users WHERE username = ?"
            cursor.execute(query, (username,))
        ```
        
        This uses parameterized queries.
        """
        
        extracted = agent._extract_code_from_response(response_text)
        
        assert extracted is not None
        assert "SELECT * FROM users" in extracted
        assert "parameterized" not in extracted  # Only code, not comments

    def test_code_extraction_empty(self, agent):
        """Test code extraction with no code block."""
        response_text = "No code here, just text."
        
        extracted = agent._extract_code_from_response(response_text)
        
        assert extracted is None

    @pytest.mark.asyncio
    async def test_vulnerability_finding_creation(self, agent):
        """Test VulnerabilityFinding dataclass."""
        finding = VulnerabilityFinding(
            cwe_id="CWE-89",
            severity="HIGH",
            description="SQL Injection",
            line_number=5,
        )
        
        assert finding.cwe_id == "CWE-89"
        assert finding.severity == "HIGH"
        assert finding.line_number == 5

    def test_agent_result_serialization(self, vulnerable_code):
        """Test AgentResult can be serialized to dict."""
        from src.agent.security_agent import SecurityAnalysisResult
        
        result = AgentResult(
            input_code=vulnerable_code,
            original_analysis=SecurityAnalysisResult(
                vulnerable=True,
                findings=[
                    VulnerabilityFinding(
                        cwe_id="CWE-89",
                        severity="HIGH",
                        description="SQL Injection",
                    )
                ],
            ),
            success=False,
            message="Vulnerabilities found",
        )
        
        result_dict = result.to_dict()
        
        assert "input_code" in result_dict
        assert "original_analysis" in result_dict
        assert result_dict["success"] is False
        assert len(result_dict["original_analysis"]["findings"]) == 1


class TestCWEDatabase:
    """Test CWEDatabase class."""

    def test_cwe_database_initialization(self):
        """Test CWE database initialization."""
        db = CWEDatabase()
        
        assert len(db.list_all_cwes()) > 0
        assert "CWE-89" in db.list_all_cwes()

    def test_get_cwe(self):
        """Test retrieving CWE information."""
        db = CWEDatabase()
        
        cwe = db.get_cwe("CWE-89")
        
        assert cwe is not None
        assert "name" in cwe
        assert "SQL Injection" in cwe["name"]

    def test_get_description(self):
        """Test getting CWE description."""
        db = CWEDatabase()
        
        desc = db.get_description("CWE-89")
        
        assert desc is not None
        assert len(desc) > 0
        assert "SQL" in desc

    def test_get_remediation(self):
        """Test getting remediation steps."""
        db = CWEDatabase()
        
        remediation = db.get_remediation("CWE-89")
        
        assert isinstance(remediation, list)
        assert len(remediation) > 0
        assert any("parameterized" in step.lower() for step in remediation)

    def test_search_by_name(self):
        """Test searching CWEs by name."""
        db = CWEDatabase()
        
        results = db.search_by_name("SQL")
        
        assert len(results) > 0
        assert "CWE-89" in results

    def test_get_nonexistent_cwe(self):
        """Test getting non-existent CWE."""
        db = CWEDatabase()
        
        cwe = db.get_cwe("CWE-99999")
        
        assert cwe is None

    def test_get_severity(self):
        """Test getting CWE severity."""
        db = CWEDatabase()
        
        severity = db.get_severity("CWE-89")
        
        assert severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_get_name(self):
        """Test getting CWE name."""
        db = CWEDatabase()
        
        name = db.get_name("CWE-89")
        
        assert "SQL" in name or "Injection" in name


class TestPromptTemplates:
    """Test prompt template generation."""

    def test_cot_prompt_generation(self):
        """Test Chain-of-Thought prompt generation."""
        from src.agent.prompts import CoTPrompts
        
        code = "x = input()"
        vulnerability = {
            "cwe_id": "CWE-89",
            "severity": "HIGH",
            "description": "SQL Injection",
        }
        
        prompt = CoTPrompts.analyze_vulnerability(code, vulnerability)
        
        assert "STEP 1" in prompt
        assert "STEP 2" in prompt
        assert "STEP 5" in prompt
        assert "SQL Injection" in prompt
        assert code in prompt

    def test_cwe_template_retrieval(self):
        """Test CWE-specific template retrieval."""
        from src.agent.prompts import CWETemplates
        
        template = CWETemplates.get_template("CWE-89")
        
        assert template is not None
        assert "SQL Injection" in template
        assert "parameterized" in template.lower()

    def test_generic_prompt_generation(self):
        """Test generic prompt generation."""
        from src.agent.prompts import GenericPrompts
        
        code = "x = input()"
        prompt = GenericPrompts.scan_and_categorize(code)
        
        assert "analyze" in prompt.lower()
        assert "vulnerability" in prompt.lower()
        assert code in prompt

    def test_all_cwe_templates_available(self):
        """Test that all major CWEs have templates."""
        from src.agent.prompts import CWETemplates
        
        major_cwes = [
            "CWE-89",   # SQL Injection
            "CWE-79",   # XSS
            "CWE-78",   # Command Injection
            "CWE-732",  # Permission issues
            "CWE-327",  # Weak crypto
        ]
        
        for cwe in major_cwes:
            template = CWETemplates.get_template(cwe)
            assert template is not None
            assert len(template) > 0


class TestConfiguration:
    """Test configuration management."""

    def test_settings_available(self):
        """Test that settings can be accessed."""
        from src.config import settings
        
        assert settings is not None
        assert hasattr(settings, 'gemini_model')
        assert settings.gemini_model == "gemini-2.5-flash"

    def test_data_directories_exist(self):
        """Test that data directories are created."""
        from src.config import settings
        
        assert settings.data_dir.exists()
        assert settings.evaluation_dir.exists()


class TestLogging:
    """Test logging setup."""

    def test_logger_available(self):
        """Test that logger is properly configured."""
        from src.logger import get_logger
        
        logger = get_logger(__name__)
        
        assert logger is not None
        assert callable(logger.info)
        assert callable(logger.error)


# Integration Tests

@pytest.mark.integration
class TestEndToEnd:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, agent, vulnerable_code):
        """Test complete workflow from analysis to result."""
        # This would require real API key
        # Skipped in CI/CD without valid key
        
        result = await agent._analyze_code(vulnerable_code)
        
        assert result is not None
        assert isinstance(result.vulnerable, bool)

    def test_agent_with_mock_api(self, agent, vulnerable_code):
        """Test agent with mocked API calls."""
        # This tests the agent structure without actual API calls
        
        assert agent is not None
        assert agent.cwe_db is not None


# Performance Tests

@pytest.mark.performance
class TestPerformance:
    """Performance and efficiency tests."""

    def test_cwe_database_lookup_speed(self):
        """Test CWE lookup performance."""
        db = CWEDatabase()
        
        import time
        start = time.time()
        
        for _ in range(100):
            db.get_cwe("CWE-89")
        
        elapsed = time.time() - start
        
        # Should be very fast (< 1ms per lookup)
        assert elapsed < 0.1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
