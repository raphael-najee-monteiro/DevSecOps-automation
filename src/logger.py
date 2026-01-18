"""
Logging utilities for the DevSecOps Agent project.

Provides structured logging throughout the application.
"""

import sys
from pathlib import Path
from typing import Optional
from loguru import logger as _logger

from src.config import settings


def setup_logger(
    name: Optional[str] = None,
    level: str = "INFO",
    log_file: Optional[Path] = None,
    console: bool = True,
) -> None:
    """
    Setup logger configuration.
    
    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging
        console: Whether to log to console
    """
    # Remove default handler
    _logger.remove()
    
    # Add console handler
    if console:
        _logger.add(
            sys.stdout,
            format="<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level=level,
            colorize=True,
        )
    
    # Add file handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        _logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level=level,
            rotation="500 MB",
            retention="7 days",
        )


def get_logger(name: str = __name__):
    """
    Get logger instance for a module.
    
    Args:
        name: Module name (typically __name__)
    
    Returns:
        Configured logger instance
    """
    return _logger.bind(name=name)


# Initialize logger with settings
def _initialize_logger():
    """Initialize logger with project settings."""
    setup_logger(
        level=settings.log_level,
        log_file=settings.log_file,
        console=settings.log_to_console,
    )


# Initialize on import
_initialize_logger()

# Export logger instance
logger = _logger
