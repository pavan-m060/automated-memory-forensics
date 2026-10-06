"""Final JSON and HTML forensic report generation."""


from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from analyzer.utils import save_json_report
from analyzer.pdf_report_generator import PDFReportGenerator

class ReportGenerator:
    """Creates review-ready final reports from analyzer outputs."""

    JSON_NAME = "forensic_report.json"
    HTML_NAME = "forensic_report.html"

    def generate(
        self,
        *,
        output_dir: str | Path,
        provenance: dict[str, Any],
        case_metadata: dict[str, Any] | None = None,
        reports: dict[str, dict[str, Any] | None],
        correlation_report: dict[str, Any],
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
        is_real_forensic_analysis: bool = True,
        status: str = "completed",
    ) -> dict[str, Path]:
        """Writes final JSON and HTML reports and returns their paths."""
        output_path = Path(output_dir)
        final_report = self.build_report(
            case_metadata=case_metadata,
            provenance=provenance,
            reports=reports,
            correlation_report=correlation_report,
            warnings=warnings or [],
            errors=errors or [],
            is_real_forensic_analysis=is_real_forensic_analysis,
            status=status,
        )

        json_path = output_path / self.JSON_NAME
        html_path = output_path / self.HTML_NAME
        save_json_report(json_path, final_report)
        self._write_html(html_path, final_report)
        pdf_path = PDFReportGenerator().generate(
            output_dir=output_path,
            report=final_report,
        )
        return {"json": json_path, "html": html_path, "pdf": pdf_path,}

    @staticmethod
    def build_report(
        *,
        case_metadata: dict[str, Any] | None = None,
        provenance: dict[str, Any],
        reports: dict[str, dict[str, Any] | None],
        correlation_report: dict[str, Any],
        warnings: list[str],
        errors: list[str],
        is_real_forensic_analysis: bool,
        status: str,
    ) -> dict[str, Any]:
        """Builds the canonical final report payload."""
        summaries = {}
        for name, report in reports.items():
            summaries[name] = report.get("summary", {}) if isinstance(report, dict) else {"status": "not_run"}

        correlated_findings = correlation_report.get("findings", [])
        conclusion = ReportGenerator._conclusion(correlated_findings, is_real_forensic_analysis)
        return {
            "schema_version": "1.0",
            "case_metadata": case_metadata or {},
            "analysis": {
                "analysis_type": "final_forensic_report",
                "status": status,
                "analysis_time": datetime.now(timezone.utc).isoformat(),
                "is_real_forensic_analysis": is_real_forensic_analysis,
            },
            "provenance": provenance,
            "summaries": summaries,
            "reports": reports,
            "correlation": correlation_report,
            "correlated_findings": correlated_findings,
            "conclusion": conclusion,
            "warnings": warnings,
            "errors": errors,
            "limitations": [
                "Results depend on Volatility plugin availability and symbol resolution.",
                "Heuristic findings require analyst review before any incident conclusion.",
                "A clean result does not prove absence of rootkit, hook, or injection activity.",
            ],
        }

    @staticmethod
    def _conclusion(findings: Any, is_real_forensic_analysis: bool) -> str:
        if not is_real_forensic_analysis:
            return "Software self-test only. No memory image was analyzed."
        if isinstance(findings, list) and findings:
            return "Correlated forensic indicators were identified and should be reviewed by an analyst."
        return "No correlated multi-source forensic findings were identified."

    @staticmethod
    def _write_html(path: Path, report: dict[str, Any]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(ReportGenerator.to_html(report), encoding="utf-8")
        except OSError as exc:
            from analyzer.utils import AnalysisError

            raise AnalysisError(f"Could not save HTML report to {path}: {exc}") from exc

    @staticmethod
    def to_html(report: dict[str, Any]) -> str:
        """Renders a standalone, investigator-friendly HTML report with modern visual aesthetics."""
        analysis = report.get("analysis", {})
        provenance = report.get("provenance", {})
        findings = report.get("correlated_findings", [])
        summaries = report.get("summaries", {})
        warnings = report.get("warnings", [])
        errors = report.get("errors", [])
        limitations = report.get("limitations", [])

        # Metric summary counts
        proc_summary = summaries.get("processes", {})
        total_procs = proc_summary.get("total_processes") or proc_summary.get("process_count") or "N/A"
        hidden_summary = summaries.get("hidden_processes", {})
        potential_hidden = hidden_summary.get("potential_hidden_count", 0)
        inj_summary = summaries.get("process_injection", {})
        potential_inj = inj_summary.get("potential_injection_findings", 0)
        dll_summary = summaries.get("dll_modules", {})
        susp_dlls = dll_summary.get("suspicious_modules", 0)
        hook_summary = summaries.get("hooks", {})
        hook_findings = hook_summary.get("hook_related_findings", 0)

        correlated_count = len(findings) if isinstance(findings, list) else 0

        # Max risk score calculation
        max_risk = 0
        if isinstance(findings, list) and findings:
            for f in findings:
                if isinstance(f, dict):
                    score = f.get("risk_score", 0)
                    if isinstance(score, int) and score > max_risk:
                        max_risk = score

        max_risk_color = "var(--accent-red)" if max_risk >= 80 else "var(--accent-amber)" if max_risk >= 50 else "var(--accent-green)"

        rows = []
        detailed_cases_html = []
        if isinstance(findings, list) and findings:
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                cid = escape(str(finding.get("correlation_id", "")))
                pid = escape(str(finding.get("pid", "")))
                proc = escape(str(finding.get("process_name", "")))
                risk = escape(str(finding.get("risk_score", "")))
                sev = str(finding.get("severity", "LOW")).upper()
                conf = str(finding.get("confidence", "LOW")).upper()
                sources_list = finding.get("supporting_sources", [])
                sources_str = ", ".join(str(s) for s in sources_list)
                sources_badges = "".join(
                    f'<span class="source-tag">{escape(str(s))}</span>' for s in sources_list
                )

                sev_class = f"badge-sev-{sev.lower()}"
                conf_class = f"badge-conf-{conf.lower()}"

                # Table row
                rows.append(
                    f"<tr>"
                    f"<td><code>{cid}</code></td>"
                    f"<td><strong>{pid}</strong></td>"
                    f"<td><code>{proc}</code></td>"
                    f"<td><span class=\"risk-number\">{risk}</span></td>"
                    f"<td><span class=\"badge {sev_class}\">{sev}</span></td>"
                    f"<td><span class=\"badge {conf_class}\">{conf}</span></td>"
                    f"<td>{sources_badges}</td>"
                    f"</tr>"
                )

                # Detailed case card
                indicators_html = []
                for ind in finding.get("supporting_indicators", []):
                    if not isinstance(ind, dict):
                        continue
                    itype = escape(str(ind.get("type", "")))
                    idesc = escape(str(ind.get("description", "")))
                    isrc = escape(str(ind.get("source", "")))
                    iev = ind.get("evidence", {})
                    ev_details = []
                    if isinstance(iev, dict):
                        for k, v in iev.items():
                            if v not in (None, "", {}):
                                ev_details.append(f"{escape(str(k))}: <code>{escape(str(v))}</code>")
                    ev_str = " | ".join(ev_details)
                    ev_html = f'<div class="indicator-evidence">{ev_str}</div>' if ev_str else ""
                    indicators_html.append(
                        f'<div class="indicator-item">'
                        f'<div class="indicator-header">'
                        f'<span class="indicator-type">{itype}</span>'
                        f'<span class="indicator-src">{isrc}</span>'
                        f'</div>'
                        f'<div class="indicator-desc">{idesc}</div>'
                        f'{ev_html}'
                        f'</div>'
                    )

                expl = escape(str(finding.get("explanation", "")))
                expl_html = f'<div class="case-explanation"><strong>Analyst Lead Explanation:</strong> {expl}</div>' if expl else ""
                indicators_rendered = "".join(indicators_html)
                ind_count = len(indicators_html)
                detailed_cases_html.append(
                    f'<div class="case-card">'
                    f'<div class="case-header">'
                    f'<div class="case-title">Case {cid}: PID {pid} — {proc}</div>'
                    f'<div class="case-meta">'
                    f'<span class="badge {sev_class}">{sev} SEVERITY</span>'
                    f'<span class="badge {conf_class}">{conf} CONFIDENCE</span>'
                    f'<span class="risk-pill">Risk Score: {risk}/100</span>'
                    f'</div>'
                    f'</div>'
                    f'<div class="case-body">'
                    f'<div class="case-section-title">Supporting Indicator Evidence ({ind_count})</div>'
                    f'<div class="indicators-grid">{indicators_rendered}</div>'
                    f'{expl_html}'
                    f'</div>'
                    f'</div>'
                )

        table_body = "\n".join(rows) if rows else '<tr><td colspan="7" class="empty-state">No correlated findings</td></tr>'
        detailed_cases_rendered = "\n".join(detailed_cases_html) if detailed_cases_html else '<div class="empty-box">No correlated findings identified across detectors.</div>'

        warnings_html = "".join(f"<li>{escape(str(w))}</li>" for w in warnings)
        errors_html = "".join(f"<li>{escape(str(e))}</li>" for e in errors)
        limitations_html = "".join(f"<li>{escape(str(l))}</li>" for l in limitations)

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Automated Memory Forensics Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-main: #0f172a;
      --bg-card: #1e293b;
      --bg-card-hover: #334155;
      --border-color: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-cyan: #38bdf8;
      --accent-purple: #c084fc;
      --accent-green: #34d399;
      --accent-amber: #fbbf24;
      --accent-red: #f87171;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      line-height: 1.6;
      padding: 32px 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    
    header {{
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 32px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }}
    .header-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 12px; }}
    h1 {{ font-size: 26px; font-weight: 700; color: #ffffff; letter-spacing: -0.5px; display: flex; align-items: center; gap: 12px; }}
    h1::before {{ content: ''; display: inline-block; width: 12px; height: 26px; background: var(--accent-cyan); border-radius: 4px; }}
    .status-badge {{
      display: inline-block;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent-cyan);
      border: 1px solid rgba(56, 189, 248, 0.3);
    }}
    .header-meta {{ display: flex; flex-wrap: wrap; gap: 24px; color: var(--text-muted); font-size: 14px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px; margin-top: 12px; }}
    .meta-item strong {{ color: var(--text-main); font-weight: 600; }}
    code {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px; color: var(--accent-cyan); word-break: break-all; }}

    /* Grid Dashboard */
    .dashboard-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .metric-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 20px;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .metric-card:hover {{ transform: translateY(-2px); border-color: var(--accent-cyan); }}
    .metric-label {{ font-size: 13px; font-weight: 500; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
    .metric-val {{ font-size: 32px; font-weight: 700; color: #ffffff; line-height: 1; }}
    .metric-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 6px; }}

    .section-title {{ font-size: 20px; font-weight: 600; margin-bottom: 16px; color: #ffffff; display: flex; align-items: center; gap: 10px; }}
    .section-title::before {{ content: ''; display: inline-block; width: 6px; height: 18px; background: var(--accent-purple); border-radius: 2px; }}

    /* Table Styling */
    .table-container {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      overflow-x: auto;
      margin-bottom: 32px;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
    th {{ background: #162032; padding: 14px 18px; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border-color); text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
    td {{ padding: 14px 18px; border-bottom: 1px solid rgba(255,255,255,0.05); color: var(--text-main); }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255,255,255,0.02); }}
    .empty-state {{ text-align: center; color: var(--text-muted); padding: 32px; font-style: italic; }}

    /* Badges */
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
    .badge-sev-critical {{ background: rgba(248, 113, 113, 0.2); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.4); }}
    .badge-sev-high {{ background: rgba(251, 146, 60, 0.2); color: #fb923c; border: 1px solid rgba(251, 146, 60, 0.4); }}
    .badge-sev-medium {{ background: rgba(251, 191, 36, 0.2); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.4); }}
    .badge-sev-low {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
    
    .badge-conf-high {{ background: rgba(52, 211, 153, 0.2); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.4); }}
    .badge-conf-moderate {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
    .badge-conf-low {{ background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.4); }}
    
    .source-tag {{ display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 4px; font-size: 11px; background: rgba(255,255,255,0.06); color: var(--text-muted); border: 1px solid rgba(255,255,255,0.1); }}
    .risk-number {{ font-weight: 700; color: #ffffff; font-size: 15px; }}
    .risk-pill {{ background: rgba(192, 132, 252, 0.15); color: var(--accent-purple); padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; border: 1px solid rgba(192, 132, 252, 0.3); }}

    /* Case Cards */
    .case-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      margin-bottom: 20px;
      overflow: hidden;
    }}
    .case-header {{
      background: #162032;
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      border-bottom: 1px solid var(--border-color);
    }}
    .case-title {{ font-size: 16px; font-weight: 600; color: #ffffff; }}
    .case-meta {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .case-body {{ padding: 20px 24px; }}
    .case-section-title {{ font-size: 13px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 12px; }}
    
    .indicators-grid {{ display: grid; gap: 12px; margin-bottom: 16px; }}
    .indicator-item {{
      background: rgba(0,0,0,0.2);
      border: 1px solid rgba(255,255,255,0.05);
      border-radius: 8px;
      padding: 12px 16px;
    }}
    .indicator-header {{ display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 13px; }}
    .indicator-type {{ font-weight: 600; color: var(--accent-cyan); }}
    .indicator-src {{ color: var(--text-muted); font-size: 12px; }}
    .indicator-desc {{ font-size: 13px; color: var(--text-main); margin-bottom: 4px; }}
    .indicator-evidence {{ font-size: 12px; color: var(--text-muted); line-height: 1.4; }}

    .case-explanation {{
      background: rgba(56, 189, 248, 0.05);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: 8px;
      padding: 14px 18px;
      font-size: 13px;
      color: #e0f2fe;
    }}
    .empty-box {{ background: var(--bg-card); border: 1px dashed var(--border-color); border-radius: 10px; padding: 24px; text-align: center; color: var(--text-muted); margin-bottom: 32px; }}

    /* Conclusion Box */
    .conclusion-box {{
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
      border: 1px solid var(--accent-cyan);
      border-radius: 10px;
      padding: 20px 24px;
      margin-bottom: 32px;
    }}
    .conclusion-title {{ font-size: 15px; font-weight: 600; color: var(--accent-cyan); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .conclusion-text {{ font-size: 15px; color: #ffffff; line-height: 1.5; }}

    /* Info Lists */
    .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 32px; }}
    .info-card {{ background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; }}
    .info-card h3 {{ font-size: 15px; font-weight: 600; color: #ffffff; margin-bottom: 12px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }}
    .info-card ul {{ list-style-type: none; font-size: 13px; color: var(--text-muted); }}
    .info-card li {{ margin-bottom: 8px; padding-left: 16px; position: relative; }}
    .info-card li::before {{ content: '•'; position: absolute; left: 0; color: var(--accent-cyan); }}

    footer {{ text-align: center; font-size: 13px; color: var(--text-muted); padding-top: 24px; border-top: 1px solid var(--border-color); }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-top">
        <h1>Automated Memory Forensics Report</h1>
        <span class="status-badge">{escape(str(analysis.get("status", "COMPLETED")))}</span>
      </div>
      <div class="header-meta">
        <div class="meta-item">Memory Image: <code>{escape(str(provenance.get("memory_image", "None")))}</code></div>
        <div class="meta-item">SHA-256: <code>{escape(str(provenance.get("sha256", "None")))}</code></div>
        <div class="meta-item">Analysis Time: <strong>{escape(str(analysis.get("analysis_time", "")))}</strong></div>
      </div>
    </header>

    <div class="dashboard-grid">
      <div class="metric-card">
        <div class="metric-label">Correlated Cases</div>
        <div class="metric-val" style="color: var(--accent-cyan);">{correlated_count}</div>
        <div class="metric-sub">Multi-detector process leads</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Max Risk Score</div>
        <div class="metric-val" style="color: {max_risk_color};">{max_risk}</div>
        <div class="metric-sub">Out of 100 max triage risk</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Hidden Process Candidates</div>
        <div class="metric-val">{potential_hidden}</div>
        <div class="metric-sub">psscan-only process structures</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Process Injection Cases</div>
        <div class="metric-val">{potential_inj}</div>
        <div class="metric-sub">malfind + VAD + memmap</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Suspicious Modules</div>
        <div class="metric-val">{susp_dlls}</div>
        <div class="metric-sub">dlllist path/memory anomalies</div>
      </div>
    </div>

    <div class="conclusion-box">
      <div class="conclusion-title">Forensic Analysis Conclusion</div>
      <div class="conclusion-text">{escape(str(report.get("conclusion", "")))}</div>
    </div>

    <div class="section-title">Correlated Findings Summary</div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Case ID</th>
            <th>PID</th>
            <th>Process Name</th>
            <th>Risk</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Supporting Sources</th>
          </tr>
        </thead>
        <tbody>
          {table_body}
        </tbody>
      </table>
    </div>

    <div class="section-title">Detailed Investigation Cases</div>
    {detailed_cases_rendered}

    <div class="info-grid">
      <div class="info-card">
        <h3>Analysis Provenance & Reproducibility</h3>
        <ul>
          <li>Python Version: <code>{escape(str(provenance.get("python_version", "N/A")))}</code></li>
          <li>Platform: <code>{escape(str(provenance.get("platform", "N/A")))}</code></li>
          <li>Volatility 3 Version: <code>{escape(str(provenance.get("volatility_version", "N/A")))}</code></li>
          <li>Enabled Analyzers: <code>{escape(", ".join(provenance.get("enabled_analyzers", [])))}</code></li>
        </ul>
      </div>

      <div class="info-card">
        <h3>Warnings & Execution Notes</h3>
        <ul>
          {warnings_html or "<li>No execution warnings recorded.</li>"}
        </ul>
      </div>

      <div class="info-card">
        <h3>Forensic Scope & Limitations</h3>
        <ul>
          {limitations_html or "<li>Results require contextual analyst review.</li>"}
        </ul>
      </div>
    </div>

    <footer>
      <p>Automated Rootkit & Process Injection Memory Forensics Pipeline | Volatility 3 Integration</p>
    </footer>
  </div>
</body>
</html>
"""

