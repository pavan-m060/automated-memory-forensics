"""Shared utilities for validation, logging, and output persistence."""

from __future__ import annotations

import json
import logging
import platform
import sys
from pathlib import Path
from typing import Any


COMMON_MEMORY_EXTENSIONS = {".raw", ".mem", ".dmp", ".vmem", ".bin"}


class AnalysisError(Exception):
    """Expected analysis error that should be shown without a traceback."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def configure_logging() -> None:
    """Configures simple forensic-analysis logging."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, OSError):
        pass

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
        stream=sys.stdout,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Returns a module logger."""
    return logging.getLogger(name)


def validate_memory_file(path: Path) -> list[str]:
    """Validates basic filesystem properties for a memory image.

    Returns non-fatal warnings. Raises AnalysisError for conditions that make
    analysis impossible.
    """
    warnings: list[str] = []

    try:
        candidate = path.expanduser()
    except RuntimeError as exc:
        raise AnalysisError(f"Invalid memory image path: {path}") from exc

    if not candidate.exists():
        raise AnalysisError(f"Memory image does not exist: {path}", exit_code=2)
    if not candidate.is_file():
        raise AnalysisError(f"Memory image path is not a file: {path}", exit_code=2)

    try:
        with candidate.open("rb") as handle:
            handle.read(1)
    except PermissionError as exc:
        raise AnalysisError(f"Memory image is not readable: {path}", exit_code=13) from exc
    except OSError as exc:
        raise AnalysisError(f"Memory image could not be read: {path} ({exc})") from exc

    try:
        size = candidate.stat().st_size
    except OSError as exc:
        raise AnalysisError(f"Could not inspect memory image size: {path} ({exc})") from exc

    if size <= 0:
        raise AnalysisError(f"Memory image is empty: {path}", exit_code=2)

    if candidate.suffix.lower() and candidate.suffix.lower() not in COMMON_MEMORY_EXTENSIONS:
        warnings.append(
            f"Unusual memory image extension '{candidate.suffix}'. "
            "Continuing because content validation is more important than the name."
        )
    elif not candidate.suffix:
        warnings.append(
            "Memory image has no file extension. Continuing because content validation "
            "is more important than the name."
        )

    return warnings


def display_path(path: Path) -> str:
    """Returns a portable path for reports when possible."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name
    except OSError:
        return path.as_posix()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculates the SHA-256 digest for an input file."""
    import hashlib

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AnalysisError(f"Could not hash memory image {path}: {exc}") from exc
    return digest.hexdigest()


def build_provenance(
    *,
    memory_path: Path | None,
    volatility_version: str | None,
    enabled_analyzers: list[str],
    disabled_analyzers: list[str],
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Builds reproducibility metadata for final reports."""
    file_metadata: dict[str, Any] = {
        "memory_image": None,
        "filename": None,
        "size_bytes": None,
        "sha256": None,
    }

    if memory_path is not None and memory_path.exists() and memory_path.is_file():
        file_metadata = {
            "memory_image": display_path(memory_path),
            "filename": memory_path.name,
            "size_bytes": memory_path.stat().st_size,
            "sha256": sha256_file(memory_path),
        }

    return {
        **file_metadata,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "volatility_version": volatility_version,
        "enabled_analyzers": enabled_analyzers,
        "disabled_analyzers": disabled_analyzers,
        "warnings": warnings or [],
        "errors": errors or [],
    }


def save_json_report(path: Path, payload: dict[str, Any]) -> None:
    """Saves a readable JSON report."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
            handle.write("\n")
    except (TypeError, OSError) as exc:
        raise AnalysisError(f"Could not save JSON output to {path}: {exc}") from exc


def save_text_report(path: Path, content: str) -> None:
    """Saves raw Volatility process output."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"Could not save raw Volatility output to {path}: {exc}") from exc
