"""Command-line entry point for the memory forensics analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analyzer.correlation_engine import CorrelationEngine
from analyzer.dll_analyzer import DLLAnalyzer
from analyzer.hidden_process_detector import HiddenProcessDetector
from analyzer.hook_detector import HookDetector
from analyzer.injection_detector import InjectionDetector
from analyzer.memory_analyzer import MemoryAnalyzer
from analyzer.process_analyzer import ProcessAnalyzer
from analyzer.report_generator import ReportGenerator
from analyzer.utils import (
    AnalysisError,
    build_provenance,
    configure_logging,
    get_logger,
    save_json_report,
    save_text_report,
)


BANNER = """
==================================================
 Automated Rootkit / Process Injection Detector
 Process + Hidden + Injection + DLL + Hook + Correlation
==================================================
""".strip()


def build_parser() -> argparse.ArgumentParser:
    """Builds the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a Windows memory image with Volatility 3 for baseline processes, "
            "hidden-process candidates, process-injection indicators, DLL/module anomalies, "
            "and hook-related indicators."
        )
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="memory_file",
        required=False,
        help="Path to the Windows memory image, for example input/memory.raw",
    )
    parser.add_argument(
        "--case-id",
        default="UNSPECIFIED",
        help="Case identifier to include in the forensic report.",
    )
    parser.add_argument(
        "--examination-id",
        default="UNSPECIFIED",
        help="Examination identifier to include in the forensic report.",
    )
    parser.add_argument(
        "--examiner-name",
        default="UNSPECIFIED",
        help="Examiner name to include in the forensic report.",
    )
    parser.add_argument(
        "--organization",
        default="UNSPECIFIED",
        help="Organization name to include in the forensic report.",
    )
    parser.add_argument(
        "--case-description",
        default="UNSPECIFIED",
        help="Investigation or case description to include in the forensic report.",
    )
    parser.add_argument(
        "--evidence-id",
        default="UNSPECIFIED",
        help="Evidence identifier to include in the forensic report.",
    )
    parser.add_argument(
        "--evidence-description",
        default="UNSPECIFIED",
        help="Evidence description to include in the forensic report.",
    )
    parser.add_argument(
        "--report-title",
        default="Automated Memory Forensic Examination Report",
        help="Report title to include in the forensic report.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="output",
        help="Directory where JSON and raw Volatility output will be saved.",
    )
    parser.add_argument(
        "--skip-hidden",
        action="store_true",
        help="Skip pslist vs psscan hidden-process comparison.",
    )
    parser.add_argument(
        "--skip-injection",
        action="store_true",
        help="Skip process-injection analysis with malfind/VAD/memory evidence.",
    )
    parser.add_argument(
        "--skip-dll",
        action="store_true",
        help="Skip DLL/module analysis with dlllist evidence.",
    )
    parser.add_argument(
        "--skip-hooks",
        action="store_true",
        help="Skip hook-related analysis with callbacks/SSDT/syscall evidence.",
    )
    parser.add_argument(
        "--demo-check",
        action="store_true",
        help=(
            "Run a software self-test that writes empty final report files without "
            "analyzing a memory image. This is not forensic analysis."
        ),
    )
    return parser


def print_process_table(processes: list[dict[str, object]]) -> None:
    """Prints a concise process table to the terminal."""
    print()
    print("=" * 50)
    print("PROCESS ANALYSIS")
    print("=" * 50)
    print(f"{'PID':<10}{'PPID':<10}PROCESS")
    print("-" * 50)

    for process in processes:
        pid = "" if process.get("pid") is None else str(process.get("pid"))
        ppid = "" if process.get("ppid") is None else str(process.get("ppid"))
        name = str(process.get("name") or "")
        print(f"{pid:<10}{ppid:<10}{name}")

    print()
    print(f"Total Processes: {len(processes)}")


def print_hidden_process_summary(report: dict[str, object]) -> None:
    """Prints hidden-process cross-view analysis results."""
    summary = report["summary"]
    findings = report["findings"]

    if not isinstance(summary, dict) or not isinstance(findings, list):
        raise AnalysisError("Unexpected hidden process report structure.")

    print()
    print("=" * 50)
    print("HIDDEN PROCESS ANALYSIS")
    print("=" * 50)
    print(f"[+] pslist processes: {summary['pslist_count']}")
    print(f"[+] psscan processes: {summary['psscan_count']}")
    print("[*] Comparing process views...")
    print()
    print("-" * 50)
    print("CROSS-VIEW SUMMARY")
    print("-" * 50)
    print(f"Normal processes       : {summary['normal_count']}")
    print(f"psscan-only candidates : {summary['psscan_only_count']}")
    print(f"Potential hidden       : {summary['potential_hidden_count']}")

    if not findings:
        print()
        print("[+] No potential hidden processes identified.")
        print("IMPORTANT: This does not mean the system is guaranteed clean.")
        return

    print()
    print("-" * 50)
    print("SUSPICIOUS PROCESS CANDIDATES")
    print("-" * 50)
    print(f"{'PID':<10}{'NAME':<20}STATUS")
    print("-" * 50)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        pid = "" if finding.get("pid") is None else str(finding.get("pid"))
        name = str(finding.get("name") or "unknown")
        status = str(finding.get("classification") or "")
        print(f"{pid:<10}{name:<20}{status}")


def print_injection_summary(report: dict[str, object]) -> None:
    """Prints process-injection analysis results."""
    summary = report["summary"]
    findings = report["findings"]

    if not isinstance(summary, dict) or not isinstance(findings, list):
        raise AnalysisError("Unexpected injection report structure.")

    print()
    print("=" * 50)
    print("PROCESS INJECTION ANALYSIS")
    print("=" * 50)
    print("[*] Running memory analysis...")
    print("[*] Running malfind...")
    print(f"[+] Suspicious memory regions identified: {summary['suspicious_regions']}")
    print()
    print("[*] Correlating memory regions with processes...")
    print("[*] Checking memory protection characteristics...")
    print("[*] Checking VAD information...")
    print("[*] Correlating available memory mappings...")
    print()
    print("=" * 50)
    print("INJECTION DETECTION SUMMARY")
    print("=" * 50)
    print(f"Processes analyzed       : {summary['processes_analyzed']}")
    print(f"Suspicious regions        : {summary['suspicious_regions']}")
    print(f"Potential injection cases : {summary['potential_injection_findings']}")

    if not findings:
        print()
        print("[+] No potential process injection indicators identified.")
        print("Absence of findings does not guarantee absence of process injection.")
        return

    print()
    print("-" * 50)
    print("POTENTIAL INJECTION FINDINGS")
    print("-" * 50)
    print(f"{'PID':<10}{'PROCESS':<20}{'SCORE':<10}SEVERITY")
    print("-" * 50)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        pid = "" if finding.get("pid") is None else str(finding.get("pid"))
        name = str(finding.get("process_name") or "unknown")
        score = "" if finding.get("score") is None else str(finding.get("score"))
        severity = str(finding.get("severity") or "")
        print(f"{pid:<10}{name:<20}{score:<10}{severity}")

        indicators = finding.get("indicators")
        if isinstance(indicators, list):
            print("Reason:")
            for indicator in indicators[:4]:
                if isinstance(indicator, dict):
                    print(f"- {indicator.get('description')}")


def print_dll_summary(report: dict[str, object]) -> None:
    """Prints DLL/module analysis results."""
    summary = report["summary"]
    findings = report["findings"]

    if not isinstance(summary, dict) or not isinstance(findings, list):
        raise AnalysisError("Unexpected DLL analysis report structure.")

    print()
    print("=" * 50)
    print("DLL / MODULE ANALYSIS")
    print("=" * 50)
    print("[*] Enumerating loaded modules...")
    print(f"[+] Processes analyzed: {summary['processes_analyzed']}")
    print(f"[+] Modules discovered: {summary['total_modules']}")
    print()
    print("[*] Analyzing module paths...")
    print("[*] Correlating modules with memory evidence...")
    print()
    print("=" * 50)
    print("DLL ANALYSIS SUMMARY")
    print("=" * 50)
    print(f"Total modules       : {summary['total_modules']}")
    print(f"Suspicious modules  : {summary['suspicious_modules']}")

    if not findings:
        print()
        print("[+] No suspicious DLL/module indicators identified.")
        print(
            "Module anomalies are indicators for investigation and do not independently prove malicious activity."
        )
        return

    print()
    print("-" * 50)
    print("SUSPICIOUS MODULES")
    print("-" * 50)
    print(f"{'PID':<10}{'PROCESS':<16}{'MODULE':<18}SCORE")
    print("-" * 50)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        pid = "" if finding.get("pid") is None else str(finding.get("pid"))
        process = str(finding.get("process_name") or "unknown")
        module = str(finding.get("module_name") or "unknown")
        score = "" if finding.get("score") is None else str(finding.get("score"))
        print(f"{pid:<10}{process:<16}{module:<18}{score}")
    print(
        "Module anomalies are indicators for investigation and do not independently prove malicious activity."
    )


def print_hook_summary(report: dict[str, object]) -> None:
    """Prints hook-related analysis results."""
    summary = report["summary"]
    findings = report["findings"]

    if not isinstance(summary, dict) or not isinstance(findings, list):
        raise AnalysisError("Unexpected hook analysis report structure.")

    print()
    print("=" * 50)
    print("HOOK-RELATED ANALYSIS")
    print("=" * 50)
    print("[*] Collecting callback, SSDT, ETW, and syscall-related evidence...")
    print(f"[+] Records analyzed: {summary['records_analyzed']}")
    print()
    print("=" * 50)
    print("HOOK ANALYSIS SUMMARY")
    print("=" * 50)
    print(f"Hook-related findings : {summary['hook_related_findings']}")

    if not findings:
        print()
        print("[+] No hook-related indicators identified from available plugins.")
        print("Absence of findings does not guarantee absence of API hooks.")
        return

    print()
    print("-" * 50)
    print("HOOK-RELATED FINDINGS")
    print("-" * 50)
    print(f"{'SOURCE':<24}{'PID':<10}{'SCORE':<10}SEVERITY")
    print("-" * 50)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        source = str(finding.get("source_plugin") or "unknown")
        pid = "" if finding.get("pid") is None else str(finding.get("pid"))
        score = "" if finding.get("score") is None else str(finding.get("score"))
        severity = str(finding.get("severity") or "")
        print(f"{source:<24}{pid:<10}{score:<10}{severity}")


def skipped_report(analysis_type: str, reason: str) -> dict[str, object]:
    """Returns a schema-compatible placeholder for intentionally skipped stages."""
    return {
        "analysis": {
            "analysis_type": analysis_type,
            "status": "skipped",
            "method": "not_run",
        },
        "summary": {
            "status": "skipped",
            "reason": reason,
        },
        "findings": [],
        "warnings": [reason],
        "errors": [],
    }


def run_demo_check(
        output_dir: Path,
        case_metadata: dict[str, object] | None = None,
        ) -> int:
    """Writes self-test reports without pretending a memory image was analyzed."""
    warning = "DEMONSTRATION / SOFTWARE SELF-TEST - NOT REAL FORENSIC ANALYSIS."
    reports: dict[str, dict[str, object] | None] = {
        "processes": skipped_report("process_enumeration", "No memory image analyzed."),
        "hidden_processes": skipped_report("hidden_process_detection", "No memory image analyzed."),
        "process_injection": skipped_report("process_injection_detection", "No memory image analyzed."),
        "dll_modules": skipped_report("dll_module_analysis", "No memory image analyzed."),
        "hooks": skipped_report("hook_related_detection", "No memory image analyzed."),
    }
    correlation_report = CorrelationEngine().analyze(memory_path=None)
    provenance = build_provenance(
        memory_path=None,
        volatility_version=None,
        enabled_analyzers=[],
        disabled_analyzers=list(reports.keys()),
        warnings=[warning, "No memory image analyzed."],
        errors=[],
    )

    paths = ReportGenerator().generate(
        output_dir=output_dir,
        case_metadata=case_metadata,
        provenance=provenance,
        reports=reports,
        correlation_report=correlation_report,
        warnings=[warning, "No memory image analyzed."],
        errors=[],
        is_real_forensic_analysis=False,
        status="demo_check",
    )

    print(BANNER)
    print("[+] Demo check completed.")
    print("[!] NOT REAL FORENSIC ANALYSIS: no memory image was analyzed.")
    print(f"[+] Final JSON report: {paths['json']}")
    print(f"[+] Final HTML report: {paths['html']}")
    print(f"[+] Final PDF report: {paths['pdf']}")
    return 0


def run(args: argparse.Namespace) -> int:
    """Runs the memory analysis workflow."""
    logger = get_logger(__name__)
    output_dir = Path(args.output_dir)

    if args.demo_check:
        return run_demo_check(
            output_dir,
            {
                "case_id": args.case_id,
                "examination_id": args.examination_id,
                "examiner_name": args.examiner_name,
                "organization": args.organization,
                },
        )

    if not args.memory_file:
        raise AnalysisError("A memory image path is required unless --demo-check is used.", exit_code=2)

    memory_path = Path(args.memory_file)

    print(BANNER)
    logger.info("Loading memory image...")

    analyzer = MemoryAnalyzer(memory_path)
    process_analyzer = ProcessAnalyzer()
    hidden_detector = HiddenProcessDetector()
    injection_detector = InjectionDetector()
    dll_analyzer = DLLAnalyzer()
    hook_detector = HookDetector()
    correlation_engine = CorrelationEngine()
    report_generator = ReportGenerator()
    hidden_report: dict[str, object] | None = None
    injection_report: dict[str, object] | None = None
    dll_report: dict[str, object] | None = None
    hook_report: dict[str, object] | None = None
    workflow_warnings: list[str] = []

    logger.info("Validating memory image...")
    print("[1/7] Validating memory image...")
    analyzer.validate_image()

    logger.info("Running process enumeration...")
    print("[2/7] Enumerating processes with pslist...")
    processes, pslist_raw_output = analyzer.enumerate_processes()
    logger.info("Found %s processes", len(processes))

    json_report = process_analyzer.build_report(
        memory_path=memory_path,
        processes=processes,
        volatility_version=analyzer.volatility_version,
    )

    logger.info("Saving results...")
    save_json_report(output_dir / "processes.json", json_report)
    save_text_report(output_dir / "volatility_process_output.txt", pslist_raw_output)
    save_text_report(output_dir / "volatility_pslist_output.txt", pslist_raw_output)

    print_process_table(processes)

    if not args.skip_hidden:
        logger.info("Running hidden process analysis...")
        print("[3/7] Running hidden-process cross-view analysis...")
        print()
        print("[*] Running pslist...")
        print("[*] Running psscan...")
        psscan_processes, psscan_raw_output = analyzer.scan_processes()

        save_text_report(output_dir / "volatility_psscan_output.txt", psscan_raw_output)

        hidden_report = hidden_detector.analyze(
            pslist_processes=processes,
            psscan_processes=psscan_processes,
            memory_path=memory_path,
        )
        save_json_report(output_dir / "hidden_process_findings.json", hidden_report)
        print_hidden_process_summary(hidden_report)
    else:
        logger.info("Skipping hidden process analysis by request.")
        hidden_report = skipped_report("hidden_process_detection", "Skipped by --skip-hidden.")
        workflow_warnings.append("Hidden-process analysis skipped by user.")

    if not args.skip_injection:
        logger.info("Running process injection analysis...")
        print("[4/7] Running process-injection analysis...")
        injection_evidence = analyzer.collect_injection_evidence()

        save_text_report(
            output_dir / "volatility_malfind_output.txt",
            str(injection_evidence["malfind"]["raw_output"]),
        )
        if injection_evidence.get("vadinfo", {}).get("available"):
            save_text_report(
                output_dir / "volatility_vadinfo_output.txt",
                str(injection_evidence["vadinfo"]["raw_output"]),
            )
        if injection_evidence.get("memmap", {}).get("available"):
            save_text_report(
                output_dir / "volatility_memmap_output.txt",
                str(injection_evidence["memmap"]["raw_output"]),
            )

        injection_report = injection_detector.analyze(
            malfind_records=list(injection_evidence["malfind"]["records"]),
            vad_records=list(injection_evidence.get("vadinfo", {}).get("records", [])),
            memmap_records=list(injection_evidence.get("memmap", {}).get("records", [])),
            memory_path=memory_path,
        )
        save_json_report(output_dir / "injection_findings.json", injection_report)
        print_injection_summary(injection_report)
    else:
        logger.info("Skipping process injection analysis by request.")
        injection_report = skipped_report("process_injection_detection", "Skipped by --skip-injection.")
        workflow_warnings.append("Process-injection analysis skipped by user.")

    if not args.skip_dll:
        logger.info("Running DLL/module analysis...")
        print("[5/7] Running DLL/module analysis...")
        try:
            dll_evidence = analyzer.collect_dll_evidence()
        except AnalysisError as exc:
            logger.warning(str(exc))
            workflow_warnings.append(str(exc))
            dll_report = skipped_report("dll_module_analysis", str(exc))
        else:
            save_text_report(
                output_dir / "volatility_dlllist_output.txt",
                str(dll_evidence["raw_output"]),
            )
            dll_report = dll_analyzer.analyze(
                dll_records=list(dll_evidence["records"]),
                memory_path=memory_path,
                injection_report=injection_report,
            )
            module_inventory = dll_analyzer.build_inventory_report(
                dll_records=list(dll_evidence["records"]),
                memory_path=memory_path,
            )
            save_json_report(output_dir / "dll_findings.json", dll_report)
            save_json_report(output_dir / "modules.json", module_inventory)
            print_dll_summary(dll_report)
    else:
        logger.info("Skipping DLL/module analysis by request.")
        dll_report = skipped_report("dll_module_analysis", "Skipped by --skip-dll.")
        workflow_warnings.append("DLL/module analysis skipped by user.")

    if not args.skip_hooks:
        logger.info("Running hook-related analysis...")
        print("[6/7] Running hook-related analysis...")
        hook_evidence = analyzer.collect_hook_evidence()
        hook_records_by_source: dict[str, list[dict[str, object]]] = {}

        raw_output_names = {
            "callbacks": "volatility_callbacks_output.txt",
            "ssdt": "volatility_ssdt_output.txt",
            "etwpatch": "volatility_etwpatch_output.txt",
            "direct_system_calls": "volatility_direct_system_calls_output.txt",
            "indirect_system_calls": "volatility_indirect_system_calls_output.txt",
            "unhooked_system_calls": "volatility_unhooked_system_calls_output.txt",
        }

        for source, evidence in hook_evidence.items():
            if evidence.get("available"):
                hook_records_by_source[source] = list(evidence.get("records", []))
                save_text_report(
                    output_dir / raw_output_names[source],
                    str(evidence.get("raw_output", "")),
                )

        hook_report = hook_detector.analyze(
            evidence_by_source=hook_records_by_source,
            memory_path=memory_path,
            injection_report=injection_report,
            dll_report=dll_report,
        )
        save_json_report(output_dir / "hook_findings.json", hook_report)
        print_hook_summary(hook_report)
    else:
        logger.info("Skipping hook-related analysis by request.")
        hook_report = skipped_report("hook_related_detection", "Skipped by --skip-hooks.")
        workflow_warnings.append("Hook-related analysis skipped by user.")

    print("[7/7] Correlating evidence and writing final report...")
    correlation_report = correlation_engine.analyze(
        memory_path=memory_path,
        hidden_report=hidden_report,
        injection_report=injection_report,
        dll_report=dll_report,
        hook_report=hook_report,
    )
    save_json_report(output_dir / "correlated_findings.json", correlation_report)

    disabled_analyzers = []
    if args.skip_hidden:
        disabled_analyzers.append("hidden_processes")
    if args.skip_injection:
        disabled_analyzers.append("process_injection")
    if args.skip_dll:
        disabled_analyzers.append("dll_modules")
    if args.skip_hooks:
        disabled_analyzers.append("hooks")

    enabled_analyzers = [
        "processes",
        *(["hidden_processes"] if not args.skip_hidden else []),
        *(["process_injection"] if not args.skip_injection else []),
        *(["dll_modules"] if not args.skip_dll else []),
        *(["hooks"] if not args.skip_hooks else []),
        "evidence_correlation",
    ]
    provenance = build_provenance(
        memory_path=memory_path,
        volatility_version=analyzer.volatility_version,
        enabled_analyzers=enabled_analyzers,
        disabled_analyzers=disabled_analyzers,
        warnings=workflow_warnings,
        errors=[],
    )
    final_paths = report_generator.generate(
        output_dir=output_dir,
        case_metadata={
            "case_id": args.case_id,
            "examination_id": args.examination_id,
            "examiner_name": args.examiner_name,
            "organization": args.organization,
            "case_description": args.case_description,
            "evidence_id": args.evidence_id,
            "evidence_description": args.evidence_description,
            "report_title": args.report_title,
        },
    provenance=provenance,
        reports={
            "processes": json_report,
            "hidden_processes": hidden_report,
            "process_injection": injection_report,
            "dll_modules": dll_report,
            "hooks": hook_report,
        },
        correlation_report=correlation_report,
        warnings=workflow_warnings,
        errors=[],
        is_real_forensic_analysis=True,
    )
    print(f"[+] Final JSON report: {final_paths['json']}")
    print(f"[+] Final HTML report: {final_paths['html']}")

    logger.info("Analysis completed successfully")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI wrapper that converts expected user errors into clean messages."""
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return run(args)
    except AnalysisError as exc:
        get_logger(__name__).error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        get_logger(__name__).error("Analysis interrupted by user.")
        return 130
    except Exception as exc:  # pragma: no cover - last-resort safety net
        get_logger(__name__).error("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
