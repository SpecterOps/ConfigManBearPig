"""
Logging utilities for ConfigManBearPig Python collector.

Translated from PowerShell Write-LogMessage function.
Provides colored console output and file logging with timestamp/level formatting
matching the PowerShell version's output format exactly.
"""

import contextvars
import logging
import sys
import threading
from datetime import datetime, timezone
from typing import Optional

# ANSI color codes matching PowerShell ForegroundColor
_COLORS = {
    "INFO": "\033[0m",        # Default/White
    "SUCCESS": "\033[32m",    # Green
    "WARNING": "\033[33m",    # Yellow
    "ERROR": "\033[31m",      # Red
    "VERBOSE": "\033[36m",    # Cyan
}
_RESET = "\033[0m"

# Level width padding — "VERBOSE" and "WARNING" are the longest at 7 chars
_LEVEL_WIDTH = 7

# ---------------------------------------------------------------------------
# Per-target context and coloring
# ---------------------------------------------------------------------------

_current_target: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_current_target", default=None,
)
_current_phase: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_current_phase", default=None,
)

# Palette of distinct ANSI colors assigned round-robin to targets
_TARGET_PALETTE = [
    "\033[34m",   # Blue
    "\033[35m",   # Magenta
    "\033[92m",   # Bright Green
    "\033[93m",   # Bright Yellow
    "\033[94m",   # Bright Blue
    "\033[95m",   # Bright Magenta
    "\033[96m",   # Bright Cyan
    "\033[91m",   # Bright Red
    "\033[33m",   # Yellow
    "\033[36m",   # Cyan
    "\033[32m",   # Green
    "\033[31m",   # Red
]
_target_color_map: dict[str, str] = {}
_target_color_lock = threading.Lock()


def set_target_context(target: Optional[str]) -> contextvars.Token:
    """Set the current enumeration target for log formatting."""
    return _current_target.set(target)


def set_phase_context(phase: Optional[str]) -> contextvars.Token:
    """Set the current collection phase for log formatting."""
    return _current_phase.set(phase)


def _get_target_color(target: str) -> str:
    """Return a stable ANSI color code for *target*, assigning one on first sight."""
    with _target_color_lock:
        color = _target_color_map.get(target)
        if color is None:
            color = _TARGET_PALETTE[len(_target_color_map) % len(_TARGET_PALETTE)]
            _target_color_map[target] = color
        return color


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
                level_name = "ERROR"
            elif record.levelno >= logging.WARNING:
                level_name = "WARNING"
            elif record.levelno >= logging.INFO:
                level_name = "INFO"
            else:
                level_name = "VERBOSE"
        else:
            level_name = level_name.upper()

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        padding = " " * (_LEVEL_WIDTH - len(level_name))

        target = _current_target.get(None)
        phase = _current_phase.get(None)
        if target:
            phase_part = f"[{phase}]" if phase else ""
            if self.use_color and sys.stdout.isatty():
                tcolor = _get_target_color(target)
                target_part = f" {tcolor}[{target}]{phase_part}{_RESET}"
            else:
                target_part = f" [{target}]{phase_part}"
        else:
            target_part = ""

        if self.use_color and sys.stdout.isatty():
            color = _COLORS.get(level_name, _COLORS["INFO"])
            return f"{color}{level_name}{_RESET}{padding} {timestamp}{target_part} {record.getMessage()}"
        else:
            return f"{level_name}{padding} {timestamp}{target_part} {record.getMessage()}"


class FileFormatter(logging.Formatter):
    """Formatter for file output (no colors)."""

    def format(self, record: logging.LogRecord) -> str:
        level_name = getattr(record, "custom_level", None)
        if level_name is None:
            if record.levelno >= logging.ERROR:
                level_name = "ERROR"
            elif record.levelno >= logging.WARNING:
                level_name = "WARNING"
            elif record.levelno >= logging.INFO:
                level_name = "INFO"
            else:
                level_name = "VERBOSE"
        else:
            level_name = level_name.upper()

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        padding = " " * (_LEVEL_WIDTH - len(level_name))

        target = _current_target.get(None)
        phase = _current_phase.get(None)
        if target:
            phase_part = f"[{phase}]" if phase else ""
            target_part = f" [{target}]{phase_part}"
        else:
            target_part = ""
        return f"{level_name}{padding} {timestamp}{target_part} {record.getMessage()}"


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
