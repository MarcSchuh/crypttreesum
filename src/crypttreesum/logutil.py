"""Logging helpers for crypttreesum."""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "crypttreesum"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a package logger (child of ``crypttreesum``)."""
    if name is None or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def configure_logging(*, verbosity: int = 0, quiet: bool = False) -> None:
    """Configure package logging to stderr.

    Levels:
    - quiet: WARNING
    - default: INFO (progress)
    - verbosity >= 1: DEBUG
    """
    if quiet:
        level = logging.WARNING
    elif verbosity >= 1:
        level = logging.DEBUG
    else:
        level = logging.INFO

    root = logging.getLogger(LOGGER_NAME)
    root.handlers.clear()
    root.setLevel(level)
    root.propagate = False

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root.addHandler(handler)
