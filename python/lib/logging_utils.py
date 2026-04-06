"""
Logging utilities for ConfigManBearPig Python collector.

Translated from PowerShell Write-LogMessage function.
Provides colored console output and file logging with timestamp/level formatting
matching the PowerShell version's output format exactly.
"""

import logging
import sys
from datetime import datetime
from typing import Optional

# ANSI color codes matching PowerShell ForegroundColor
_COLORS = {
    "Info": "\033[0m",        # Default/White
    "Success": "\033[32m",    # Green
    "Warning": "\033[33m",    # Yellow
    "Error": "\033[31m",      # Red
    "Verbose": "\033[36m",    # Cyan
}
_RESET = "\033[0m"

# Level width padding to match PowerShell output exactly
_LEVEL_WIDTH = 7  # "Warning" is the longest at 7 chars


class ColoredFormatter(logging.Formatter):
    """Formatter that adds color codes and matches PowerShell log format."""

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        # Map Python logging levels to our custom level names
        level_name = getattr(record, "custom_level", None)
        if level_name is None:
            if record.levelno >= logging.ERROR:
                level_name = "Error"
            elif record.levelno >= logging.WARNING:
                level_name = "Warning"
            elif record.levelno >= logging.INFO:
                level_name = "Info"
            else:
                level_name = "Verbose"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        padding = " " * (_LEVEL_WIDTH - len(level_name))

        if self.use_color and sys.stdout.isatty():
            color = _COLORS.get(level_name, _COLORS["Info"])
            return f"{timestamp} [{color}{level_name}{_RESET}]{padding} {record.getMessage()}"
        else:
            return f"{timestamp} [{level_name}]{padding} {record.getMessage()}"


class FileFormatter(logging.Formatter):
    """Formatter for file output (no colors)."""

    def format(self, record: logging.LogRecord) -> str:
        level_name = getattr(record, "custom_level", None)
        if level_name is None:
            if record.levelno >= logging.ERROR:
                level_name = "Error"
            elif record.levelno >= logging.WARNING:
                level_name = "Warning"
            elif record.levelno >= logging.INFO:
                level_name = "Info"
            else:
                level_name = "Verbose"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        padding = " " * (_LEVEL_WIDTH - len(level_name))
        return f"{timestamp} [{level_name}]{padding} {record.getMessage()}"


def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    """
    Set up logging with console and optional file output.

    Args:
        log_file: Path to log file (None for console only)
        verbose: Enable verbose/debug level logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("ConfigManBearPig")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(ColoredFormatter(use_color=True))
    logger.addHandler(console_handler)

    # File handler (no colors)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileFormatter())
        logger.addHandler(file_handler)

    return logger


def log_message(logger: logging.Logger, level: str, message: str) -> None:
    """
    Log a message at the specified level, matching PowerShell Write-LogMessage.

    Args:
        logger: Logger instance
        level: One of "Info", "Success", "Warning", "Error", "Verbose"
        message: Message to log
    """
    # Map our custom levels to Python logging levels
    level_map = {
        "Info": logging.INFO,
        "Success": logging.INFO,
        "Warning": logging.WARNING,
        "Error": logging.ERROR,
        "Verbose": logging.DEBUG,
    }

    py_level = level_map.get(level, logging.INFO)
    # Attach custom level name for the formatter
    extra = {"custom_level": level}
    logger.log(py_level, message, extra=extra)
