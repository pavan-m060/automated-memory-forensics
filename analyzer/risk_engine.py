"""Unified risk and confidence scoring for correlated forensic evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class RiskAssessment:
    """Normalized risk assessment for one correlated finding."""

    risk_score: int
    severity: str
    confidence: str


class RiskEngine:
    """Scores cross-module evidence without claiming proof of compromise."""

    SOURCE_WEIGHTS = {
        "hidden_process": 35,
        "process_injection": 40,
        "dll_anomaly": 25,
        "hook_related": 35,
    }

    @classmethod
    def assess(cls, sources: Iterable[str], indicator_count: int = 0) -> RiskAssessment:
        """Returns a bounded score, severity, and confidence label."""
        unique_sources = {source for source in sources if source}
        base_score = sum(cls.SOURCE_WEIGHTS.get(source, 10) for source in unique_sources)
        score = min(100, base_score + min(20, max(0, indicator_count - len(unique_sources)) * 5))

        return RiskAssessment(
            risk_score=score,
            severity=cls.severity_for_score(score),
            confidence=cls.confidence_for_sources(unique_sources),
        )

    @staticmethod
    def severity_for_score(score: int) -> str:
        """Maps a numeric score to a consistent severity label."""
        if score >= 85:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def confidence_for_sources(sources: Iterable[str]) -> str:
        """Reports source diversity without implying artifact-level proof."""
        count = len(set(sources))

        if count >= 3:
            return "MODERATE"
        if count == 2:
            return "LOW"
        if count == 1:
            return "LOW"
        return "NONE"