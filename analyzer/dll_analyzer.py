"""DLL/module enumeration normalization and contextual analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PureWindowsPath, Path
from typing import Any

from analyzer.utils import display_path


DLL_INDICATOR_WEIGHTS = {
    "suspicious_module_path": 25,
    "unresolved_module_path": 10,
    "unusual_module_characteristics": 15,
    "module_memory_inconsistency": 20,
    "supporting_suspicious_executable_memory": 25,
    "additional_corroborating_evidence": 10,
}


class DLLAnalyzer:
    """Analyzes loaded modules without treating anomalies as proof of malware."""

    USER_LOCATION_MARKERS = (
        "\\users\\",
        "\\appdata\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\temp\\",
        "\\tmp\\",
        "\\public\\",
        "\\programdata\\",
    )
    SYSTEM_LOCATION_MARKERS = (
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
    )
    APPLICATION_LOCATION_MARKERS = (
        "\\program files\\",
        "\\program files (x86)\\",
    )
    COMMON_MODULE_EXTENSIONS = {".dll", ".exe", ".sys", ".ocx", ".cpl", ".drv"}

    def analyze(
        self,
        dll_records: list[dict[str, Any]],
        memory_path: Path | str,
        injection_report: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Builds module inventory and suspicious DLL/module findings."""
        modules = self._deduplicate_modules(
            [
                module
                for module in (self.normalize_module(record) for record in dll_records)
                if module is not None
            ]
        )
        grouped = self.group_by_process(modules)
        findings = self._build_findings(modules, injection_report)

        return {
            "analysis": {
                "memory_image": display_path(Path(memory_path)),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "method": "DLL/module enumeration and contextual analysis",
                "scoring_note": "DLL anomaly scores are heuristics, not malware probabilities.",
            },
            "summary": {
                "processes_analyzed": len(grouped),
                "total_modules": len(modules),
                "suspicious_modules": len(findings),
            },
            "processes": grouped,
            "findings": findings,
        }

    def build_inventory_report(
        self,
        dll_records: list[dict[str, Any]],
        memory_path: Path | str,
    ) -> dict[str, Any]:
        """Builds the standalone normalized module inventory report."""
        modules = self._deduplicate_modules(
            [
                module
                for module in (self.normalize_module(record) for record in dll_records)
                if module is not None
            ]
        )
        return {
            "analysis": {
                "memory_image": display_path(Path(memory_path)),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
            },
            "processes": self.group_by_process(modules),
        }

    def normalize_module(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Normalizes one Volatility dlllist row."""
        pid = self._to_int(record.get("PID") or record.get("Pid") or record.get("pid"))
        if pid is None:
            return None

        path = self._clean_optional_string(record.get("Path") or record.get("path"))
        module_name = self._clean_optional_string(
            record.get("Name")
            or record.get("BaseDllName")
            or record.get("Module")
            or record.get("module_name")
        )
        if module_name is None and path:
            module_name = PureWindowsPath(path).name

        return {
            "pid": pid,
            "process_name": self._clean_optional_string(
                record.get("Process") or record.get("ImageFileName") or record.get("process_name")
            ),
            "module_name": module_name,
            "base_address": self._clean_optional_string(
                record.get("Base") or record.get("DllBase") or record.get("base_address")
            ),
            "size": self._to_int(record.get("Size") or record.get("SizeOfImage") or record.get("size")),
            "path": path,
            "load_count": self._clean_optional_string(record.get("LoadCount")),
            "load_time": self._clean_optional_string(record.get("LoadTime")),
            "source": "dlllist",
        }

    def group_by_process(self, modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Groups normalized module records by PID."""
        grouped: dict[int, dict[str, Any]] = {}
        for module in modules:
            pid = module["pid"]
            process = grouped.setdefault(
                pid,
                {
                    "pid": pid,
                    "process_name": module.get("process_name"),
                    "modules": [],
                },
            )
            if not process.get("process_name") and module.get("process_name"):
                process["process_name"] = module.get("process_name")
            process["modules"].append(
                {
                    "name": module.get("module_name"),
                    "base_address": module.get("base_address"),
                    "size": module.get("size"),
                    "path": module.get("path"),
                }
            )

        return [grouped[pid] for pid in sorted(grouped)]

    def classify_path(self, path: str | None) -> str:
        """Classifies module path context for explainable analysis."""
        if not path:
            return "unresolved"

        normalized = path.replace("/", "\\").lower()
        while "\\\\" in normalized:
            normalized = normalized.replace("\\\\", "\\")
        if any(marker in normalized for marker in self.SYSTEM_LOCATION_MARKERS):
            return "windows_system"
        if any(marker in normalized for marker in self.APPLICATION_LOCATION_MARKERS):
            return "application"
        if any(marker in normalized for marker in self.USER_LOCATION_MARKERS):
            return "user_writable_or_unusual"
        if "\\" not in normalized:
            return "unresolved"
        return "unknown"

    def score_indicators(self, indicators: list[dict[str, Any]]) -> int:
        """Calculates a capped DLL anomaly score."""
        total = 0
        seen: set[tuple[Any, Any, Any]] = set()
        for indicator in indicators:
            evidence = indicator.get("evidence", {})
            key = (indicator.get("type"), evidence.get("path"), evidence.get("base_address"))
            if key in seen:
                continue
            seen.add(key)
            total += int(indicator.get("weight", 0))
        return min(total, 100)

    @staticmethod
    def severity_for_score(score: int) -> str:
        """Maps a DLL anomaly score to a severity label."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def confidence_for_indicators(indicators: list[dict[str, Any]]) -> str:
        """Maps independent indicator count to a confidence label."""
        independent_types = {indicator["type"] for indicator in indicators}
        if len(independent_types) >= 3:
            return "HIGH"
        if len(independent_types) == 2:
            return "MEDIUM"
        return "LOW"

    def _build_findings(
        self,
        modules: list[dict[str, Any]],
        injection_report: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for module in modules:
            indicators = self._deduplicate_indicators(
                self._indicators_for_module(module)
                + self._memory_correlation_indicators(module, injection_report)
            )
            if not indicators:
                continue

            score = self.score_indicators(indicators)
            findings.append(
                {
                    "pid": module.get("pid"),
                    "process_name": module.get("process_name"),
                    "module_name": module.get("module_name"),
                    "finding_type": "suspicious_module",
                    "severity": self.severity_for_score(score),
                    "confidence": self.confidence_for_indicators(indicators),
                    "score": score,
                    "indicators": indicators,
                    "module": {
                        "base_address": module.get("base_address"),
                        "size": module.get("size"),
                        "path": module.get("path"),
                    },
                    "memory_correlation": self.correlate_with_memory(module, injection_report),
                    "explanation": (
                        "This module exhibits characteristics that warrant further "
                        "forensic investigation. The indicators are contextual and do "
                        "not independently prove malicious activity."
                    ),
                }
            )

        return findings

    def _indicators_for_module(self, module: dict[str, Any]) -> list[dict[str, Any]]:
        indicators: list[dict[str, Any]] = []
        path = module.get("path")
        path_class = self.classify_path(path)

        if path_class == "unresolved":
            indicators.append(
                self._indicator(
                    "unresolved_module_path",
                    "Module path is missing or could not be resolved.",
                    {
                        "module_name": module.get("module_name"),
                        "path": path,
                        "base_address": module.get("base_address"),
                    },
                )
            )
        elif path_class == "user_writable_or_unusual":
            indicators.append(
                self._indicator(
                    "suspicious_module_path",
                    "Module is loaded from a user-writable or unusual location.",
                    {
                        "module_name": module.get("module_name"),
                        "path": path,
                        "path_classification": path_class,
                    },
                )
            )

        if self._has_unusual_characteristics(module):
            indicators.append(
                self._indicator(
                    "unusual_module_characteristics",
                    "Module name, path, or extension has unusual structural characteristics.",
                    {
                        "module_name": module.get("module_name"),
                        "path": path,
                        "base_address": module.get("base_address"),
                    },
                )
            )

        return indicators

    def correlate_with_memory(
        self,
        module: dict[str, Any],
        injection_report: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Correlates a module with Part 3 suspicious memory evidence when available."""
        if not injection_report:
            return {"status": "unknown"}

        matches = []
        for finding in injection_report.get("findings", []):
            if finding.get("pid") != module.get("pid"):
                continue
            for region in finding.get("memory_regions", []):
                if self._module_matches_region(module, region):
                    matches.append(
                        {
                            "finding_type": finding.get("finding_type"),
                            "region": region.get("virtual_address"),
                            "protection": region.get("protection"),
                        }
                    )

        if matches:
            return {"status": "matched_suspicious_memory", "matches": matches}
        return {"status": "not_mapped_to_suspicious_memory"}

    def _memory_correlation_indicators(
        self,
        module: dict[str, Any],
        injection_report: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        correlation = self.correlate_with_memory(module, injection_report)
        if correlation["status"] != "matched_suspicious_memory":
            return []

        return [
            self._indicator(
                "supporting_suspicious_executable_memory",
                "Module has supporting suspicious executable memory evidence in the same process.",
                {
                    "module_name": module.get("module_name"),
                    "path": module.get("path"),
                    "base_address": module.get("base_address"),
                    "matches": len(correlation.get("matches", [])),
                },
            )
        ]

    def _module_matches_region(
        self, module: dict[str, Any], region: dict[str, Any]
    ) -> bool:
        module_name = str(module.get("module_name") or "").lower()
        module_path = str(module.get("path") or "").lower()
        backing_file = str(region.get("backing_file") or "").lower()
        region_address = str(region.get("virtual_address") or "").lower()
        base_address = str(module.get("base_address") or "").lower()

        if base_address and region_address and base_address == region_address:
            return True
        if backing_file and module_path and backing_file == module_path:
            return True
        if backing_file and module_name and module_name in backing_file:
            return True
        return False

    def _has_unusual_characteristics(self, module: dict[str, Any]) -> bool:
        module_name = module.get("module_name")
        path = module.get("path")

        if module_name:
            suffix = PureWindowsPath(str(module_name)).suffix.lower()
            if suffix and suffix not in self.COMMON_MODULE_EXTENSIONS:
                return True

        if module_name and path:
            path_name = PureWindowsPath(str(path)).name.lower()
            if path_name and path_name != str(module_name).lower():
                return True

        return False

    def _deduplicate_modules(
        self, modules: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        unique: list[dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any, Any]] = set()
        for module in modules:
            key = (
                module.get("pid"),
                module.get("module_name"),
                module.get("base_address"),
                module.get("path"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(module)
        return unique

    @staticmethod
    def _deduplicate_indicators(
        indicators: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        unique: list[dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any]] = set()
        for indicator in indicators:
            evidence = indicator.get("evidence", {})
            key = (indicator.get("type"), evidence.get("path"), evidence.get("base_address"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(indicator)
        return unique

    def _indicator(
        self, indicator_type: str, description: str, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "type": indicator_type,
            "description": description,
            "evidence": {key: value for key, value in evidence.items() if value not in (None, "")},
            "weight": DLL_INDICATOR_WEIGHTS[indicator_type],
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
    def _clean_optional_string(value: Any) -> str | None:
        if value in (None, ""):
            return None
        text = str(value).strip()
        if text.lower() in {"n/a", "not applicable", "unreadable", "disabled"}:
            return None
        return text
