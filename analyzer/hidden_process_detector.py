"""Cross-view hidden process detection using pslist and psscan results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.utils import display_path


class HiddenProcessDetector:
    """Compares independent process views to identify suspicious candidates."""

    NORMAL = "NORMAL"
    PSLIST_ONLY = "PSLIST_ONLY"
    PSSCAN_ONLY = "PSSCAN_ONLY"

    def analyze(
        self,
        pslist_processes: list[dict[str, Any]],
        psscan_processes: list[dict[str, Any]],
        memory_path: Path | str,
    ) -> dict[str, Any]:
        """Builds the hidden-process analysis report."""
        pslist_index = self._deduplicate_by_pid(pslist_processes)
        psscan_index = self._deduplicate_by_pid(psscan_processes)
        classifications = self.classify_processes(pslist_index, psscan_index)
        findings = [
            self._build_hidden_process_finding(item)
            for item in classifications
            if item["classification"] == self.PSSCAN_ONLY
        ]

        return {
            "analysis": {
                "memory_image": display_path(Path(memory_path)),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "method": "pslist_vs_psscan",
            },
            "summary": {
                "pslist_count": len(pslist_index),
                "psscan_count": len(psscan_index),
                "normal_count": self._count_classification(classifications, self.NORMAL),
                "pslist_only_count": self._count_classification(classifications, self.PSLIST_ONLY),
                "psscan_only_count": self._count_classification(classifications, self.PSSCAN_ONLY),
                "potential_hidden_count": len(findings),
            },
            "classifications": classifications,
            "findings": findings,
        }

    def classify_processes(
        self,
        pslist_index: dict[int, dict[str, Any]],
        psscan_index: dict[int, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Classifies each PID according to cross-view presence."""
        classifications: list[dict[str, Any]] = []

        for pid in sorted(set(pslist_index) | set(psscan_index)):
            pslist_process = pslist_index.get(pid)
            psscan_process = psscan_index.get(pid)
            process = psscan_process or pslist_process or {}

            if pslist_process and psscan_process:
                classification = self.NORMAL
            elif psscan_process:
                classification = self.PSSCAN_ONLY
            else:
                classification = self.PSLIST_ONLY

            classifications.append(
                {
                    "pid": pid,
                    "ppid": process.get("ppid"),
                    "name": process.get("name"),
                    "create_time": process.get("create_time"),
                    "classification": classification,
                    "evidence": {
                        "pslist_present": pslist_process is not None,
                        "psscan_present": psscan_process is not None,
                    },
                    "views": {
                        "pslist": pslist_process,
                        "psscan": psscan_process,
                    },
                }
            )

        return classifications

    def _deduplicate_by_pid(
        self, processes: list[dict[str, Any]]
    ) -> dict[int, dict[str, Any]]:
        """Deduplicates process records by PID while preserving duplicate evidence."""
        index: dict[int, dict[str, Any]] = {}

        for process in processes:
            pid = process.get("pid")
            if not isinstance(pid, int):
                continue

            if pid not in index:
                record = dict(process)
                record["duplicate_records"] = []
                index[pid] = record
                continue

            index[pid]["duplicate_records"].append(process)

        return index

    def _build_hidden_process_finding(
        self, classification: dict[str, Any]
    ) -> dict[str, Any]:
        """Builds an explainable finding for a psscan-only process."""
        return {
            "pid": classification["pid"],
            "ppid": classification.get("ppid"),
            "name": classification.get("name"),
            "create_time": classification.get("create_time"),
            "classification": self.PSSCAN_ONLY,
            "finding_type": "potential_hidden_process",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "evidence": classification["evidence"],
            "source_view": "psscan",
            "missing_from_view": "pslist",
            "explanation": (
                "The process structure was discovered by memory scanning but was "
                "not returned by normal active-process enumeration. This is a "
                "potential hidden/unlinked process indicator, but it can also be "
                "caused by terminated processes, stale memory structures, parser "
                "limitations, or incomplete memory capture."
            ),
        }

    @staticmethod
    def _count_classification(
        classifications: list[dict[str, Any]], classification: str
    ) -> int:
        return sum(1 for item in classifications if item["classification"] == classification)
