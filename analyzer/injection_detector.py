"""Explainable process-injection indicator correlation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.utils import display_path


INJECTION_INDICATOR_WEIGHTS = {
    "malfind_region": 30,
    "executable_writable_memory": 25,
    "executable_private_memory": 20,
    "unbacked_executable_memory": 20,
    "suspicious_vad": 15,
    "corroborating_evidence": 10,
}


class InjectionDetector:
    """Correlates memory indicators into process-level injection findings."""

    def analyze(
        self,
        malfind_records: list[dict[str, Any]],
        memory_path: Path | str,
        vad_records: list[dict[str, Any]] | None = None,
        memmap_records: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Builds a structured process-injection report."""
        regions = [
            region
            for region in (self.normalize_malfind_record(record) for record in malfind_records)
            if region is not None
        ]
        vad_records = vad_records or []
        memmap_records = memmap_records or []
        findings = self._build_process_findings(regions, vad_records, memmap_records)

        return {
            "analysis": {
                "memory_image": display_path(Path(memory_path)),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "method": "malfind + VAD + memory mapping correlation",
                "scoring_note": (
                    "Scores are explainable heuristics, not probabilities or proof "
                    "of malicious activity."
                ),
            },
            "summary": {
                "processes_analyzed": len({region["pid"] for region in regions}),
                "suspicious_processes": len(findings),
                "suspicious_regions": len(regions),
                "potential_injection_findings": len(findings),
            },
            "findings": findings,
        }

    def normalize_malfind_record(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Normalizes one Volatility malfind row into a memory-region record."""
        pid = self._to_int(record.get("PID") or record.get("Pid") or record.get("pid"))
        if pid is None:
            return None

        protection = self._to_str(record.get("Protection") or record.get("protection"))
        private_memory = self._to_bool(
            record.get("PrivateMemory")
            or record.get("Private Memory")
            or record.get("private_memory")
        )
        backing_file = self._clean_optional_string(
            record.get("File") or record.get("MappedFile") or record.get("backing_file")
        )
        executable = self._is_executable(protection)
        writable = self._is_writable(protection)

        return {
            "pid": pid,
            "process_name": self._to_str(
                record.get("Process")
                or record.get("ImageFileName")
                or record.get("Name")
                or record.get("process_name")
            ),
            "virtual_address": self._to_str(
                record.get("Start VPN")
                or record.get("Start")
                or record.get("Virtual")
                or record.get("virtual_address")
            ),
            "end_address": self._to_str(record.get("End VPN") or record.get("End")),
            "protection": protection,
            "private_memory": private_memory,
            "executable": executable,
            "writable": writable,
            "memory_type": self._classify_memory_type(private_memory, backing_file),
            "backing_file": backing_file,
            "tag": self._to_str(record.get("Tag") or record.get("tag")),
            "commit_charge": self._to_str(record.get("CommitCharge")),
            "notes": self._to_str(record.get("Notes")),
            "hexdump": self._to_str(record.get("Hexdump")),
            "disassembly": self._to_str(record.get("Disasm")),
            "source": "malfind",
        }

    def score_indicators(self, indicators: list[dict[str, Any]]) -> int:
        """Calculates a capped heuristic score from deduplicated indicators."""
        total = 0
        seen: set[tuple[Any, Any, Any]] = set()

        for indicator in indicators:
            key = (
                indicator.get("type"),
                indicator.get("evidence", {}).get("virtual_address"),
                indicator.get("evidence", {}).get("protection"),
                indicator.get("evidence", {}).get("source"),
            )
            if key in seen:
                continue
            seen.add(key)
            total += int(indicator.get("weight", 0))

        return min(total, 100)

    @staticmethod
    def severity_for_score(score: int) -> str:
        """Maps a heuristic score to a severity label."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def confidence_for_indicators(indicators: list[dict[str, Any]]) -> str:
        """Maps independent indicator count to an explainable confidence label."""
        independent_types = {indicator["type"] for indicator in indicators}
        if len(independent_types) >= 3:
            return "HIGH"
        if len(independent_types) == 2:
            return "MEDIUM"
        return "LOW"

    def _build_process_findings(
        self,
        regions: list[dict[str, Any]],
        vad_records: list[dict[str, Any]],
        memmap_records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped: dict[int, list[dict[str, Any]]] = {}
        for region in regions:
            grouped.setdefault(region["pid"], []).append(region)

        findings: list[dict[str, Any]] = []
        for pid in sorted(grouped):
            process_regions = grouped[pid]
            indicators = self._deduplicate_indicators(
                [
                    indicator
                    for region in process_regions
                    for indicator in self._indicators_for_region(region)
                ]
            )
            indicators.extend(
                self._corroborating_indicators(pid, process_regions, vad_records, memmap_records)
            )
            indicators = self._deduplicate_indicators(indicators)

            if not self._has_meaningful_injection_evidence(indicators):
                continue

            score = self.score_indicators(indicators)
            process_name = next(
                (region.get("process_name") for region in process_regions if region.get("process_name")),
                None,
            )
            findings.append(
                {
                    "pid": pid,
                    "process_name": process_name,
                    "finding_type": "potential_process_injection",
                    "severity": self.severity_for_score(score),
                    "confidence": self.confidence_for_indicators(indicators),
                    "score": score,
                    "indicator_count": len(indicators),
                    "indicators": indicators,
                    "memory_regions": process_regions,
                    "explanation": (
                        "One or more suspicious process memory regions were identified "
                        "and correlated at the process level. These indicators can be "
                        "associated with process injection, but they can also appear in "
                        "legitimate JIT-generated code, unpacked code, or runtime-created "
                        "memory and require contextual forensic review."
                    ),
                    "limitations": [
                        "The indicators are suspicious but do not independently prove malicious injection.",
                        "Absence of findings does not guarantee absence of process injection.",
                    ],
                }
            )

        return findings

    def _indicators_for_region(self, region: dict[str, Any]) -> list[dict[str, Any]]:
        indicators = [
            self._indicator(
                "malfind_region",
                "Volatility malfind reported a suspicious process memory region.",
                {
                    "virtual_address": region.get("virtual_address"),
                    "end_address": region.get("end_address"),
                    "protection": region.get("protection"),
                    "source": "malfind",
                },
            )
        ]

        if region.get("executable") and region.get("writable"):
            indicators.append(
                self._indicator(
                    "executable_writable_memory",
                    "Memory region has executable and writable protection.",
                    {
                        "virtual_address": region.get("virtual_address"),
                        "protection": region.get("protection"),
                    },
                )
            )

        if region.get("executable") and region.get("private_memory") is True:
            indicators.append(
                self._indicator(
                    "executable_private_memory",
                    "Executable memory region is marked as private memory.",
                    {
                        "virtual_address": region.get("virtual_address"),
                        "private_memory": region.get("private_memory"),
                    },
                )
            )

        if region.get("executable") and not region.get("backing_file"):
            indicators.append(
                self._indicator(
                    "unbacked_executable_memory",
                    "Executable memory region has no obvious file backing in available evidence.",
                    {
                        "virtual_address": region.get("virtual_address"),
                        "memory_type": region.get("memory_type"),
                    },
                )
            )

        if region.get("tag") or region.get("notes"):
            indicators.append(
                self._indicator(
                    "suspicious_vad",
                    "VAD metadata or malfind notes provide additional suspicious context.",
                    {
                        "virtual_address": region.get("virtual_address"),
                        "tag": region.get("tag"),
                        "notes": region.get("notes"),
                    },
                )
            )

        return indicators

    def _corroborating_indicators(
        self,
        pid: int,
        regions: list[dict[str, Any]],
        vad_records: list[dict[str, Any]],
        memmap_records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        indicators: list[dict[str, Any]] = []
        region_addresses = {region.get("virtual_address") for region in regions}

        matching_vads = [
            record
            for record in vad_records
            if self._to_int(record.get("PID") or record.get("pid")) == pid
            and (
                record.get("Start VPN") in region_addresses
                or record.get("Virtual") in region_addresses
                or not region_addresses
            )
        ]
        if matching_vads:
            indicators.append(
                self._indicator(
                    "corroborating_evidence",
                    "VAD information was available for the same process or memory range.",
                    {"source": "vadinfo", "matching_records": len(matching_vads)},
                )
            )

        matching_memmaps = [
            record
            for record in memmap_records
            if (
                self._to_int(record.get("PID") or record.get("pid")) == pid
                and self._to_int(
                    record.get("Virtual")
                    or record.get("virtual_address")
            ) in {
                self._to_int(address)
                for address in region_addresses
                if address is not None
            }
        )
    ]
        if matching_memmaps:
            indicators.append(
                self._indicator(
                    "corroborating_evidence",
                    "Memory mapping information was available for the same process or range.",
                    {"source": "memmap", "matching_records": len(matching_memmaps)},
                )
            )

        return indicators

    def _indicator(
        self, indicator_type: str, description: str, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "type": indicator_type,
            "description": description,
            "evidence": {key: value for key, value in evidence.items() if value not in (None, "")},
            "weight": INJECTION_INDICATOR_WEIGHTS[indicator_type],
        }

    @staticmethod
    def _deduplicate_indicators(
        indicators: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        unique: list[dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any]] = set()
        for indicator in indicators:
            evidence = indicator.get("evidence", {})
            key = (
                indicator.get("type"),
                evidence.get("virtual_address"),
                evidence.get("source"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(indicator)
        return unique

    @staticmethod
    def _has_meaningful_injection_evidence(indicators: list[dict[str, Any]]) -> bool:
        return any(indicator["type"] == "malfind_region" for indicator in indicators)

    @staticmethod
    def _classify_memory_type(
        private_memory: bool | None, backing_file: str | None
    ) -> str:
        if private_memory is True:
            return "private"
        if backing_file:
            return "file_backed"
        return "unknown"

    @staticmethod
    def _is_executable(protection: str | None) -> bool:
        return bool(protection and "EXECUTE" in protection.upper())

    @staticmethod
    def _is_writable(protection: str | None) -> bool:
        return bool(protection and ("WRITE" in protection.upper() or "WRITECOPY" in protection.upper()))

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _to_bool(value: Any) -> bool | None:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        text = str(value).strip().lower()
        if text in {"1", "true", "yes"}:
            return True
        if text in {"0", "false", "no"}:
            return False
        return None

    @staticmethod
    def _to_str(value: Any) -> str | None:
        if value in (None, ""):
            return None
        return str(value)

    def _clean_optional_string(self, value: Any) -> str | None:
        text = self._to_str(value)
        if text is None:
            return None
        if text.strip().lower() in {"n/a", "disabled", "not applicable"}:
            return None
        return text
