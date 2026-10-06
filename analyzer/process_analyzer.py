"""Process normalization and baseline report assembly."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.utils import display_path


class ProcessAnalyzer:
    """Normalizes Volatility process rows for downstream forensic analysis."""

    def normalize_process(
        self, row: dict[str, Any], source: str | None = None
    ) -> dict[str, Any]:
        """Converts a Volatility process row into the project's stable schema."""
        normalized = {
            "pid": self._to_int(row.get("PID") or row.get("Pid") or row.get("pid")),
            "ppid": self._to_int(row.get("PPID") or row.get("InheritedFromUniqueProcessId") or row.get("ppid")),
            "name": self._to_str(row.get("ImageFileName") or row.get("Name") or row.get("Process") or row.get("name")),
            "create_time": self._to_str(row.get("CreateTime") or row.get("Create Time") or row.get("create_time")),
            "virtual_address": self._to_str(row.get("Offset(V)") or row.get("Offset") or row.get("virtual_address")),
            "dtb": self._to_str(row.get("DTB") or row.get("DirectoryTableBase") or row.get("dtb")),
            "source": source or self._to_str(row.get("source") or row.get("Source")),
            "additional_metadata": {},
        }

        mapped_keys = {
            "PID",
            "Pid",
            "pid",
            "PPID",
            "InheritedFromUniqueProcessId",
            "ppid",
            "ImageFileName",
            "Name",
            "Process",
            "name",
            "CreateTime",
            "Create Time",
            "create_time",
            "Offset(V)",
            "Offset",
            "virtual_address",
            "DTB",
            "DirectoryTableBase",
            "dtb",
            "source",
            "Source",
        }

        normalized["additional_metadata"] = {
            str(key): self._to_str(value)
            for key, value in row.items()
            if key not in mapped_keys and value not in (None, "")
        }
        return normalized

    def normalize_processes(
        self, rows: list[dict[str, Any]], source: str | None = None
    ) -> list[dict[str, Any]]:
        """Normalizes a list of Volatility process rows."""
        return [self.normalize_process(row, source=source) for row in rows]

    def build_report(
        self,
        memory_path: Path,
        processes: list[dict[str, Any]],
        volatility_version: str,
    ) -> dict[str, Any]:
        """Builds the structured JSON report."""
        return {
            "analysis": {
                "memory_image": display_path(memory_path),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "volatility_version": volatility_version,
                "analysis_type": "baseline_process_enumeration",
            },
            "processes": processes,
        }

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _to_str(value: Any) -> str | None:
        if value in (None, ""):
            return None
        return str(value)
