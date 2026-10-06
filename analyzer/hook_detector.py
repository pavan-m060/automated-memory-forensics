"""Hook-related evidence normalization and explainable anomaly detection."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.utils import display_path


HOOK_INDICATOR_WEIGHTS = {
    "unresolved_kernel_callback": 25,
    "unresolved_ssdt_entry": 30,
    "etw_patch_indicator": 35,
    "direct_syscall_indicator": 30,
    "indirect_syscall_indicator": 35,
    "ntdll_stub_variation": 25,
    "supporting_injection_evidence": 20,
    "supporting_dll_evidence": 15,
}


class HookDetector:
    """Builds hook-related findings from available Volatility plugin evidence."""

    def analyze(
        self,
        evidence_by_source: dict[str, list[dict[str, Any]]],
        memory_path: Path | str,
        injection_report: dict[str, Any] | None = None,
        dll_report: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Normalizes available hook-related records and builds findings."""
        records = self.normalize_records(evidence_by_source)
        findings = self._build_findings(records, injection_report, dll_report)

        return {
            "analysis": {
                "memory_image": display_path(Path(memory_path)),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "analysis_type": "hook_related_detection",
                "method": (
                    "callbacks + ssdt + ETW patch + system-call evasion indicators"
                ),
                "limitations": [
                    "windows.malware.apihooks is not available in this environment.",
                    "Findings are hook-related indicators and do not independently prove API hooking.",
                ],
            },
            "summary": {
                "sources_analyzed": sorted(evidence_by_source),
                "records_analyzed": len(records),
                "hook_related_findings": len(findings),
            },
            "records": records,
            "findings": findings,
        }

    def normalize_records(
        self, evidence_by_source: dict[str, list[dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """Normalizes plugin-specific rows into a shared hook-evidence shape."""
        records: list[dict[str, Any]] = []
        for source, rows in evidence_by_source.items():
            for row in rows:
                normalized = self.normalize_record(row, source)
                if normalized is not None:
                    records.append(normalized)
        return records

    def normalize_record(
        self, record: dict[str, Any], source: str
    ) -> dict[str, Any] | None:
        """Normalizes one row from a hook-related Volatility plugin."""
        normalizers = {
            "callbacks": self._normalize_callback,
            "ssdt": self._normalize_ssdt,
            "etwpatch": self._normalize_etwpatch,
            "direct_system_calls": self._normalize_syscall_indicator,
            "indirect_system_calls": self._normalize_syscall_indicator,
            "unhooked_system_calls": self._normalize_unhooked_syscall,
        }
        normalizer = normalizers.get(source)
        if normalizer is None:
            return None
        return normalizer(record, source)

    def score_indicators(self, indicators: list[dict[str, Any]]) -> int:
        """Calculates a capped hook-related anomaly score."""
        total = 0
        seen: set[tuple[Any, Any, Any, Any]] = set()
        for indicator in indicators:
            evidence = indicator.get("evidence", {})
            key = (
                indicator.get("type"),
                evidence.get("source"),
                evidence.get("address"),
                evidence.get("function"),
            )
            if key in seen:
                continue
            seen.add(key)
            total += int(indicator.get("weight", 0))
        return min(total, 100)

    @staticmethod
    def severity_for_score(score: int) -> str:
        """Maps a hook-related score to severity."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def confidence_for_indicators(indicators: list[dict[str, Any]]) -> str:
        """Maps independent indicator types to confidence."""
        independent_types = {indicator["type"] for indicator in indicators}
        if len(independent_types) >= 3:
            return "HIGH"
        if len(independent_types) == 2:
            return "MEDIUM"
        return "LOW"

    def _build_findings(
        self,
        records: list[dict[str, Any]],
        injection_report: dict[str, Any] | None,
        dll_report: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for record in records:
            indicators = self._deduplicate_indicators(
                self._indicators_for_record(record)
                + self._correlation_indicators(record, injection_report, dll_report)
            )
            if not indicators:
                continue

            score = self.score_indicators(indicators)
            findings.append(
                {
                    "pid": record.get("pid"),
                    "process_name": record.get("process_name"),
                    "type": "potential_hook_related_anomaly",
                    "severity": self.severity_for_score(score),
                    "confidence": self.confidence_for_indicators(indicators),
                    "score": score,
                    "source_plugin": record.get("source"),
                    "evidence": [record],
                    "indicators": indicators,
                    "explanation": (
                        "Available Volatility evidence shows a hook-related or "
                        "control-flow anomaly indicator. This is not a standalone "
                        "confirmation of API hooking and requires contextual review."
                    ),
                }
            )
        return findings

    def _indicators_for_record(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        source = record.get("source")
        indicators: list[dict[str, Any]] = []

        if source == "callbacks" and not record.get("owning_module"):
            indicators.append(
                self._indicator(
                    "unresolved_kernel_callback",
                    "Kernel callback address could not be resolved to a loaded module.",
                    record,
                )
            )
        elif source == "ssdt" and not record.get("owning_module"):
            indicators.append(
                self._indicator(
                    "unresolved_ssdt_entry",
                    "SSDT entry could not be resolved to a loaded kernel module.",
                    record,
                )
            )
        elif source == "etwpatch":
            indicators.append(
                self._indicator(
                    "etw_patch_indicator",
                    "ETW-related function starts with an opcode associated with patching or redirection.",
                    record,
                )
            )
        elif source == "direct_system_calls":
            indicators.append(
                self._indicator(
                    "direct_syscall_indicator",
                    "Potential direct system-call invocation was identified outside expected syscall DLLs.",
                    record,
                )
            )
        elif source == "indirect_system_calls":
            indicators.append(
                self._indicator(
                    "indirect_syscall_indicator",
                    "Potential indirect system-call invocation was identified.",
                    record,
                )
            )
        elif source == "unhooked_system_calls" and record.get("distinct_implementations"):
            indicators.append(
                self._indicator(
                    "ntdll_stub_variation",
                    "System-call stub implementation differs across processes.",
                    record,
                )
            )

        return indicators

    def _correlation_indicators(
        self,
        record: dict[str, Any],
        injection_report: dict[str, Any] | None,
        dll_report: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        indicators: list[dict[str, Any]] = []
        pid = record.get("pid")
        address = str(record.get("address") or record.get("target_address") or "").lower()

        if injection_report:
            for finding in injection_report.get("findings", []):
                if pid is not None and finding.get("pid") != pid:
                    continue
                for region in finding.get("memory_regions", []):
                    region_address = str(region.get("virtual_address") or "").lower()
                    if address and region_address and address == region_address:
                        indicators.append(
                            self._indicator(
                                "supporting_injection_evidence",
                                "Hook-related address correlates with suspicious memory evidence.",
                                {"source": "injection_findings", "address": address, "pid": pid},
                            )
                        )

        if dll_report:
            module = str(record.get("owning_module") or record.get("module") or "").lower()
            for finding in dll_report.get("findings", []):
                module_name = str(finding.get("module_name") or "").lower()
                if module and module_name and module in module_name:
                    indicators.append(
                        self._indicator(
                            "supporting_dll_evidence",
                            "Hook-related module correlates with a suspicious DLL/module finding.",
                            {"source": "dll_findings", "module": module_name},
                        )
                    )

        return indicators

    def _normalize_callback(
        self, record: dict[str, Any], source: str
    ) -> dict[str, Any] | None:
        return {
            "source": source,
            "callback_type": self._clean(record.get("Type")),
            "address": self._clean(record.get("Callback")),
            "owning_module": self._clean(record.get("Module")),
            "symbol": self._clean(record.get("Symbol")),
            "detail": self._clean(record.get("Detail")),
            "raw_evidence": record,
        }

    def _normalize_ssdt(self, record: dict[str, Any], source: str) -> dict[str, Any] | None:
        return {
            "source": source,
            "index": self._to_int(record.get("Index")),
            "address": self._clean(record.get("Address")),
            "owning_module": self._clean(record.get("Module")),
            "symbol": self._clean(record.get("Symbol")),
            "raw_evidence": record,
        }

    def _normalize_etwpatch(
        self, record: dict[str, Any], source: str
    ) -> dict[str, Any] | None:
        pid = self._to_int(record.get("PID") or record.get("Pid"))
        if pid is None:
            return None
        return {
            "source": source,
            "pid": pid,
            "process_name": self._clean(record.get("Process")),
            "module": self._clean(record.get("DLL")),
            "function": self._clean(record.get("Function")),
            "address": self._clean(record.get("Offset")),
            "opcode": self._clean(record.get("Opcode")),
            "raw_evidence": record,
        }

    def _normalize_syscall_indicator(
        self, record: dict[str, Any], source: str
    ) -> dict[str, Any] | None:
        pid = self._to_int(record.get("PID") or record.get("Pid"))
        if pid is None:
            return None
        return {
            "source": source,
            "pid": pid,
            "process_name": self._clean(record.get("Process")),
            "range": self._clean(record.get("Range")),
            "address": self._clean(record.get("Address")),
            "disassembly": self._clean(record.get("Disasm")),
            "raw_evidence": record,
        }

    def _normalize_unhooked_syscall(
        self, record: dict[str, Any], source: str
    ) -> dict[str, Any] | None:
        function = self._clean(record.get("Function"))
        if not function:
            return None
        distinct = self._clean(record.get("Distinct Implementations"))
        return {
            "source": source,
            "function": function,
            "distinct_implementations": distinct,
            "total_implementations": self._to_int(record.get("Total Implementations")),
            "raw_evidence": record,
        }

    def _indicator(
        self, indicator_type: str, description: str, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        keys = (
            "source",
            "pid",
            "process_name",
            "address",
            "target_address",
            "owning_module",
            "module",
            "symbol",
            "function",
            "callback_type",
            "opcode",
        )
        return {
            "type": indicator_type,
            "description": description,
            "evidence": {
                key: evidence.get(key)
                for key in keys
                if evidence.get(key) not in (None, "")
            },
            "weight": HOOK_INDICATOR_WEIGHTS[indicator_type],
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
                evidence.get("source"),
                evidence.get("address") or evidence.get("function"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(indicator)
        return unique

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _clean(value: Any) -> str | None:
        if value in (None, ""):
            return None
        text = str(value).strip()
        if text.lower() in {"n/a", "not applicable", "unreadable", "disabled"}:
            return None
        return text
