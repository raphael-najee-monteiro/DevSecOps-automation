"""
Configuration management for the DevSecOps Agent project.

Handles all configuration through environment variables and config files.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables."""

    # API Configuration
    gemini_api_key: str = "" # get from .env
    gemini_model: str = "gemini-2.5-flash"
    gemini_max_tokens: int = 4096

    # Agent Configuration
    agent_timeout: int = 300  # seconds
    agent_max_iterations: int = 5
    agent_use_cot_prompting: bool = True
    agent_use_cwe_templates: bool = True
    agent_use_rci: bool = True

    # Tool Configuration
    bandit_severity_level: str = "medium"  # low, medium, high
    semgrep_config: str = "p/security-audit"
    enable_code_analysis: bool = True

    # Evaluation Configuration
    evaluation_dataset: str = "securityeval"  # securityeval, swe_bench, custom
    evaluation_batch_size: int = 10
    evaluation_num_samples: Optional[int] = None  # None = use all samples
    evaluation_save_results: bool = True

    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    log_to_console: bool = True

    # File Paths
    project_root: Path = Path(__file__).parent.parent.parent
    data_dir: Path = project_root / "data"
    evaluation_dir: Path = project_root / "evaluation"
    results_dir: Path = evaluation_dir / "reports"
    cwe_database_path: Path = data_dir / "cwe_database.json"
    cwe_templates_path: Path = data_dir / "cwe_templates.json"

    # Feature Flags
    enable_mcp_servers: bool = True
    enable_caching: bool = True
    enable_parallel_processing: bool = False

    class Config:
        """Pydantic config."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get global settings instance."""
    return settings


def validate_settings() -> bool:
    """Validate critical settings are configured."""
    if not settings.anthropic_api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
    
    if not settings.data_dir.exists():
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    
    if not settings.evaluation_dir.exists():
        settings.evaluation_dir.mkdir(parents=True, exist_ok=True)
    
    return True


def print_settings() -> None:
    """Print current settings (excluding sensitive data)."""
    print("\n" + "=" * 60)
    print("DEVSECOPS AGENT - CONFIGURATION")
    print("=" * 60)
    
    config_dict = settings.model_dump()
    sensitive_keys = {"anthropic_api_key"}
    
    for key, value in sorted(config_dict.items()):
        if key in sensitive_keys:
            value = "***" if value else "NOT SET"
        print(f"{key:<30} {str(value):<30}")
    
    print("=" * 60 + "\n")


# Create necessary directories on module import
def _initialize_paths():
    """Initialize directory structure."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.evaluation_dir.mkdir(parents=True, exist_ok=True)
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "examples").mkdir(parents=True, exist_ok=True)


_initialize_paths()
