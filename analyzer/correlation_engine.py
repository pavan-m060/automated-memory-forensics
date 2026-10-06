"""Cross-module forensic evidence correlation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.risk_engine import RiskEngine
from analyzer.utils import display_path


class CorrelationEngine:
    """Combines detector-specific findings into process-centric cases."""

    def __init__(self) -> None:
        self.risk_engine = RiskEngine()

    def analyze(
        self,
        *,
        memory_path: str | Path | None,
        hidden_report: dict[str, Any] | None = None,
        injection_report: dict[str, Any] | None = None,
        dll_report: dict[str, Any] | None = None,
        hook_report: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Builds a report containing correlated multi-source evidence."""
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for item in self._extract_hidden(hidden_report):
            grouped[self._group_key(item)].append(item)
        for item in self._extract_generic(injection_report, "process_injection"):
            grouped[self._group_key(item)].append(item)
        for item in self._extract_generic(dll_report, "dll_anomaly"):
            grouped[self._group_key(item)].append(item)
        for item in self._extract_generic(hook_report, "hook_related"):
            grouped[self._group_key(item)].append(item)

        findings = []
        for index, evidence_items in enumerate(grouped.values(), start=1):
            sources = sorted({str(item["source"]) for item in evidence_items})
            if len(sources) < 2:
                continue

            indicators = self._collect_indicators(evidence_items)
            if len(sources) >= 2:
                assessment = self.risk_engine.assess(
                    ["same_process"],
                    indicator_count=len(indicators),
                )
            else:
                assessment = self.risk_engine.assess(
                    sources,
                    indicator_count=len(indicators),
                )
            representative = evidence_items[0]
            findings.append(
                {
                    "correlation_id": f"CORR-{index:04d}",
                    "finding_type": "correlated_forensic_evidence",
                    "pid": representative.get("pid"),
                    "process_name": representative.get("process_name"),
                    "supporting_sources": sources,
                    "correlation_basis": "same_process",
                    "supporting_findings": evidence_items,
                    "supporting_indicators": indicators,
                    "risk_score": assessment.risk_score,
                    "severity": assessment.severity,
                    "confidence": assessment.confidence,
                    "explanation": (
                        "Findings from multiple analyzer modules are associated with the same "
                        "process or process context. This process-level association does not "
                        "necessarily mean the findings independently corroborate the same "
                        "memory region or artifact. Treat this as an investigation lead, "
                        "not standalone proof of malicious activity."
                    ),
                }
            )

        findings.sort(key=lambda item: int(item.get("risk_score", 0)), reverse=True)
        return {
            "analysis": {
                "analysis_type": "evidence_correlation",
                "method": "process-centric cross-module evidence grouping",
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "memory_image": display_path(Path(memory_path)) if memory_path else None,
            },
            "summary": {
                "input_findings": sum(len(items) for items in grouped.values()),
                "candidate_groups": len(grouped),
                "correlated_findings": len(findings),
            },
            "findings": findings,
            "warnings": [
                "Correlation increases triage priority but does not prove rootkit or injection activity."
            ],
            "errors": [],
        }

    @staticmethod
    def _group_key(item: dict[str, Any]) -> str:
        pid = item.get("pid")
        if pid is not None:
            return f"pid:{pid}"
        process_name = item.get("process_name")
        if process_name:
            return f"name:{str(process_name).lower()}"
        return f"unknown:{item.get('source')}:{item.get('finding_type')}"

    @staticmethod
    def _extract_hidden(report: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not isinstance(report, dict):
            return []

        extracted = []
        for finding in report.get("findings", []):
            if not isinstance(finding, dict):
                continue
            extracted.append(
                {
                    "source": "hidden_process",
                    "finding_type": finding.get("finding_type", "potential_hidden_process"),
                    "pid": finding.get("pid"),
                    "process_name": finding.get("name") or finding.get("process_name"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "raw_finding": finding,
                }
            )
        return extracted

    @staticmethod
    def _extract_generic(report: dict[str, Any] | None, source: str) -> list[dict[str, Any]]:
        if not isinstance(report, dict):
            return []

        extracted = []
        for finding in report.get("findings", []):
            if not isinstance(finding, dict):
                continue
            extracted.append(
                {
                    "source": source,
                    "finding_type": finding.get("finding_type"),
                    "pid": finding.get("pid"),
                    "process_name": finding.get("process_name") or finding.get("name"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "raw_finding": finding,
                }
            )
        return extracted

    @staticmethod
    def _collect_indicators(evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        indicators = []
        seen = set()
        for item in evidence_items:
            raw = item.get("raw_finding")
            if not isinstance(raw, dict):
                continue
            for indicator in raw.get("indicators", []):
                if not isinstance(indicator, dict):
                    continue
                key = (
                    item.get("source"),
                    indicator.get("type"),
                    str(indicator.get("evidence", "")),
                )
                if key in seen:
                    continue
                seen.add(key)
                indicators.append(
                    {
                        "source": item.get("source"),
                        "type": indicator.get("type"),
                        "description": indicator.get("description"),
                        "evidence": indicator.get("evidence", {}),
                    }
                )
        return indicators
