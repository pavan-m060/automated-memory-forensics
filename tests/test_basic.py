from __future__ import annotations

import json

import pytest

from analyzer.correlation_engine import CorrelationEngine
from analyzer.dll_analyzer import DLLAnalyzer
from analyzer.hidden_process_detector import HiddenProcessDetector
from analyzer.hook_detector import HookDetector
from analyzer.injection_detector import InjectionDetector
from analyzer.memory_analyzer import MemoryAnalyzer
from analyzer.process_analyzer import ProcessAnalyzer
from analyzer.report_generator import ReportGenerator
from analyzer.risk_engine import RiskEngine
from analyzer.utils import (
    AnalysisError,
    build_provenance,
    save_json_report,
    sha256_file,
    validate_memory_file,
)
from main import build_parser, main


def test_missing_file_validation(tmp_path):
    missing = tmp_path / "missing.raw"

    with pytest.raises(AnalysisError) as error:
        validate_memory_file(missing)

    assert "does not exist" in str(error.value)


def test_empty_file_detection(tmp_path):
    empty = tmp_path / "empty.raw"
    empty.write_bytes(b"")

    with pytest.raises(AnalysisError) as error:
        validate_memory_file(empty)

    assert "empty" in str(error.value)


def test_cli_argument_parsing_short_and_long():
    parser = build_parser()

    short_args = parser.parse_args(["-f", "input/memory.raw"])
    long_args = parser.parse_args(["--file", "input/memory.mem"])
    skip_args = parser.parse_args(["--file", "input/memory.mem", "--skip-hidden"])
    injection_args = parser.parse_args(["--file", "input/memory.mem", "--skip-injection"])
    dll_args = parser.parse_args(["--file", "input/memory.mem", "--skip-dll"])
    hook_args = parser.parse_args(["--file", "input/memory.mem", "--skip-hooks"])

    assert short_args.memory_file == "input/memory.raw"
    assert long_args.memory_file == "input/memory.mem"
    assert skip_args.skip_hidden is True
    assert injection_args.skip_injection is True
    assert dll_args.skip_dll is True
    assert hook_args.skip_hooks is True


def test_cli_demo_check_does_not_require_memory_file():
    parser = build_parser()

    args = parser.parse_args(["--demo-check"])

    assert args.demo_check is True
    assert args.memory_file is None


def test_json_output_structure(tmp_path):
    output = tmp_path / "processes.json"
    payload = {
        "analysis": {
            "memory_image": "input/memory.raw",
            "analysis_time": "2026-09-12T00:00:00+00:00",
            "volatility_version": "test",
        },
        "processes": [],
    }

    save_json_report(output, payload)
    loaded = json.loads(output.read_text(encoding="utf-8"))

    assert "analysis" in loaded
    assert "processes" in loaded
    assert isinstance(loaded["processes"], list)


def test_process_normalization_logic():
    analyzer = ProcessAnalyzer()
    normalized = analyzer.normalize_process(
        {
            "PID": "500",
            "PPID": "4",
            "ImageFileName": "smss.exe",
            "CreateTime": "2026-09-12 10:00:00 UTC",
            "Offset(V)": "0xfa8001234560",
            "Threads": "2",
        },
        source="pslist",
    )

    assert normalized["pid"] == 500
    assert normalized["ppid"] == 4
    assert normalized["name"] == "smss.exe"
    assert normalized["create_time"] == "2026-09-12 10:00:00 UTC"
    assert normalized["virtual_address"] == "0xfa8001234560"
    assert normalized["source"] == "pslist"
    assert normalized["additional_metadata"]["Threads"] == "2"


def test_pslist_text_parsing():
    output = """
Volatility 3 Framework
PID    PPID    ImageFileName    Offset(V)        Threads
4      0       System           0xfa8001110000   100
500    4       smss.exe         0xfa8002220000   2
"""
    analyzer = MemoryAnalyzer("input/memory.raw")

    rows = analyzer._parse_pslist_text(output)

    assert rows[0]["PID"] == "4"
    assert rows[0]["ImageFileName"] == "System"
    assert rows[1]["PPID"] == "4"


def test_hidden_detector_pid_matching_and_normal_classification():
    detector = HiddenProcessDetector()
    report = detector.analyze(
        pslist_processes=[{"pid": 4, "ppid": 0, "name": "System", "source": "pslist"}],
        psscan_processes=[{"pid": 4, "ppid": 0, "name": "System", "source": "psscan"}],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["normal_count"] == 1
    assert report["summary"]["potential_hidden_count"] == 0
    assert report["classifications"][0]["classification"] == "NORMAL"
    assert report["findings"] == []


def test_hidden_detector_psscan_only_generates_finding():
    detector = HiddenProcessDetector()
    report = detector.analyze(
        pslist_processes=[],
        psscan_processes=[
            {
                "pid": 4321,
                "ppid": 1000,
                "name": "example.exe",
                "create_time": "2026-09-12 10:00:00 UTC",
                "source": "psscan",
            }
        ],
        memory_path="input/memory.raw",
    )

    finding = report["findings"][0]
    assert report["summary"]["psscan_only_count"] == 1
    assert finding["classification"] == "PSSCAN_ONLY"
    assert finding["finding_type"] == "potential_hidden_process"
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "MEDIUM"
    assert finding["evidence"]["pslist_present"] is False
    assert finding["evidence"]["psscan_present"] is True


def test_hidden_detector_pslist_only_is_not_a_finding():
    detector = HiddenProcessDetector()
    report = detector.analyze(
        pslist_processes=[{"pid": 700, "ppid": 500, "name": "csrss.exe"}],
        psscan_processes=[],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["pslist_only_count"] == 1
    assert report["classifications"][0]["classification"] == "PSLIST_ONLY"
    assert report["findings"] == []


def test_hidden_detector_duplicate_handling():
    detector = HiddenProcessDetector()
    report = detector.analyze(
        pslist_processes=[],
        psscan_processes=[
            {"pid": 4321, "name": "example.exe", "virtual_address": "0x1"},
            {"pid": 4321, "name": "example.exe", "virtual_address": "0x2"},
        ],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["psscan_count"] == 1
    assert report["summary"]["potential_hidden_count"] == 1
    assert len(report["findings"]) == 1
    assert len(report["classifications"][0]["views"]["psscan"]["duplicate_records"]) == 1


def test_hidden_detector_ignores_missing_pid_records():
    detector = HiddenProcessDetector()
    report = detector.analyze(
        pslist_processes=[{"pid": None, "name": "unknown"}],
        psscan_processes=[{"name": "unknown"}],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["pslist_count"] == 0
    assert report["summary"]["psscan_count"] == 0
    assert report["classifications"] == []
    assert report["findings"] == []


def test_hidden_detector_json_serialization(tmp_path):
    detector = HiddenProcessDetector()
    report = detector.analyze(
        pslist_processes=[],
        psscan_processes=[{"pid": 99, "name": None}],
        memory_path="input/memory.raw",
    )
    output = tmp_path / "hidden_process_findings.json"

    save_json_report(output, report)
    loaded = json.loads(output.read_text(encoding="utf-8"))

    assert loaded["analysis"]["method"] == "pslist_vs_psscan"
    assert loaded["summary"]["potential_hidden_count"] == 1


def test_injection_detector_empty_malfind_result():
    detector = InjectionDetector()

    report = detector.analyze([], memory_path="input/memory.raw")

    assert report["summary"]["processes_analyzed"] == 0
    assert report["summary"]["suspicious_regions"] == 0
    assert report["findings"] == []


def test_injection_detector_one_suspicious_region_generates_finding():
    detector = InjectionDetector()

    report = detector.analyze(
        [
            {
                "PID": "4280",
                "Process": "explorer.exe",
                "Start VPN": "0x12345000",
                "End VPN": "0x12345fff",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "PrivateMemory": "1",
            }
        ],
        memory_path="input/memory.raw",
    )

    finding = report["findings"][0]
    indicator_types = {indicator["type"] for indicator in finding["indicators"]}
    assert finding["pid"] == 4280
    assert finding["finding_type"] == "potential_process_injection"
    assert "malfind_region" in indicator_types
    assert "executable_writable_memory" in indicator_types


def test_injection_detector_groups_multiple_regions_by_pid():
    detector = InjectionDetector()

    report = detector.analyze(
        [
            {"PID": "4280", "Process": "explorer.exe", "Start VPN": "0x1", "Protection": "PAGE_EXECUTE_READ"},
            {"PID": "4280", "Process": "explorer.exe", "Start VPN": "0x2", "Protection": "PAGE_EXECUTE_READWRITE"},
        ],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["suspicious_processes"] == 1
    assert len(report["findings"][0]["memory_regions"]) == 2


def test_injection_detector_handles_multiple_processes():
    detector = InjectionDetector()

    report = detector.analyze(
        [
            {"PID": "111", "Process": "one.exe", "Start VPN": "0x1", "Protection": "PAGE_EXECUTE_READ"},
            {"PID": "222", "Process": "two.exe", "Start VPN": "0x2", "Protection": "PAGE_EXECUTE_READ"},
        ],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["suspicious_processes"] == 2
    assert {finding["pid"] for finding in report["findings"]} == {111, 222}


def test_injection_detector_rwx_indicator():
    detector = InjectionDetector()
    region = detector.normalize_malfind_record(
        {"PID": 1, "Protection": "PAGE_EXECUTE_READWRITE"}
    )

    indicators = detector._indicators_for_region(region)

    assert any(indicator["type"] == "executable_writable_memory" for indicator in indicators)


def test_injection_detector_private_executable_indicator():
    detector = InjectionDetector()
    region = detector.normalize_malfind_record(
        {"PID": 1, "Protection": "PAGE_EXECUTE_READ", "PrivateMemory": "1"}
    )

    indicators = detector._indicators_for_region(region)

    assert region["memory_type"] == "private"
    assert any(indicator["type"] == "executable_private_memory" for indicator in indicators)


def test_injection_detector_unbacked_executable_indicator():
    detector = InjectionDetector()
    region = detector.normalize_malfind_record(
        {"PID": 1, "Protection": "PAGE_EXECUTE_READ", "File": ""}
    )

    indicators = detector._indicators_for_region(region)

    assert any(indicator["type"] == "unbacked_executable_memory" for indicator in indicators)


def test_injection_detector_indicator_deduplication():
    detector = InjectionDetector()
    indicator = {
        "type": "malfind_region",
        "description": "duplicate",
        "evidence": {"virtual_address": "0x1", "source": "malfind"},
        "weight": 30,
    }

    unique = detector._deduplicate_indicators([indicator, dict(indicator)])

    assert unique == [indicator]


def test_injection_detector_score_calculation_and_cap():
    detector = InjectionDetector()
    indicators = [
        {
            "type": "malfind_region",
            "evidence": {"virtual_address": f"0x{i}", "source": "malfind"},
            "weight": 30,
        }
        for i in range(5)
    ]

    assert detector.score_indicators(indicators) == 100


def test_injection_detector_severity_calculation():
    assert InjectionDetector.severity_for_score(10) == "LOW"
    assert InjectionDetector.severity_for_score(30) == "MEDIUM"
    assert InjectionDetector.severity_for_score(60) == "HIGH"
    assert InjectionDetector.severity_for_score(80) == "CRITICAL"


def test_injection_detector_confidence_calculation():
    detector = InjectionDetector()

    assert detector.confidence_for_indicators([{"type": "malfind_region"}]) == "LOW"
    assert detector.confidence_for_indicators(
        [{"type": "malfind_region"}, {"type": "executable_writable_memory"}]
    ) == "MEDIUM"
    assert detector.confidence_for_indicators(
        [
            {"type": "malfind_region"},
            {"type": "executable_writable_memory"},
            {"type": "executable_private_memory"},
        ]
    ) == "HIGH"


def test_injection_detector_json_serialization(tmp_path):
    detector = InjectionDetector()
    report = detector.analyze(
        [{"PID": "99", "Process": "sample.exe", "Protection": "PAGE_EXECUTE_READ"}],
        memory_path="input/memory.raw",
    )
    output = tmp_path / "injection_findings.json"

    save_json_report(output, report)
    loaded = json.loads(output.read_text(encoding="utf-8"))

    assert loaded["analysis"]["method"] == "malfind + VAD + memory mapping correlation"
    assert loaded["summary"]["potential_injection_findings"] == 1


def test_injection_detector_missing_optional_fields():
    detector = InjectionDetector()

    region = detector.normalize_malfind_record({"PID": "99"})

    assert region["pid"] == 99
    assert region["process_name"] is None
    assert region["memory_type"] == "unknown"


def test_injection_detector_malformed_or_missing_pid_ignored():
    detector = InjectionDetector()

    assert detector.normalize_malfind_record({"PID": "not-a-pid"}) is None
    report = detector.analyze([{"Process": "unknown.exe"}], memory_path="input/memory.raw")

    assert report["summary"]["suspicious_regions"] == 0
    assert report["findings"] == []


def test_injection_detector_file_backed_region_type():
    detector = InjectionDetector()

    region = detector.normalize_malfind_record(
        {"PID": 5, "Protection": "PAGE_EXECUTE_READ", "File": r"C:\\Windows\\System32\\x.dll"}
    )

    assert region["memory_type"] == "file_backed"
    assert region["backing_file"] == r"C:\\Windows\\System32\\x.dll"


def test_dll_analyzer_normalization():
    analyzer = DLLAnalyzer()

    module = analyzer.normalize_module(
        {
            "PID": "4280",
            "Process": "explorer.exe",
            "Base": "0x7ff10000",
            "Size": "0x2000",
            "Name": "example.dll",
            "Path": r"C:\\Windows\\System32\\example.dll",
            "LoadCount": "1",
        }
    )

    assert module["pid"] == 4280
    assert module["process_name"] == "explorer.exe"
    assert module["module_name"] == "example.dll"
    assert module["base_address"] == "0x7ff10000"
    assert module["size"] == 8192
    assert module["source"] == "dlllist"


def test_dll_analyzer_process_grouping():
    analyzer = DLLAnalyzer()
    modules = [
        {"pid": 1, "process_name": "one.exe", "module_name": "a.dll", "base_address": "0x1", "size": 1, "path": "a.dll"},
        {"pid": 1, "process_name": "one.exe", "module_name": "b.dll", "base_address": "0x2", "size": 2, "path": "b.dll"},
    ]

    grouped = analyzer.group_by_process(modules)

    assert len(grouped) == 1
    assert grouped[0]["pid"] == 1
    assert len(grouped[0]["modules"]) == 2


def test_dll_analyzer_path_classification():
    analyzer = DLLAnalyzer()

    assert analyzer.classify_path(r"C:\\Windows\\System32\\kernel32.dll") == "windows_system"
    assert analyzer.classify_path(r"C:\\Program Files\\App\\app.dll") == "application"
    assert analyzer.classify_path(r"C:\\Users\\Lucky\\Downloads\\plugin.dll") == "user_writable_or_unusual"
    assert analyzer.classify_path(None) == "unresolved"


def test_dll_analyzer_normal_system_dll_has_no_finding():
    analyzer = DLLAnalyzer()

    report = analyzer.analyze(
        [
            {
                "PID": "4",
                "Process": "System",
                "Name": "kernel32.dll",
                "Path": r"C:\\Windows\\System32\\kernel32.dll",
            }
        ],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["total_modules"] == 1
    assert report["summary"]["suspicious_modules"] == 0
    assert report["findings"] == []


def test_dll_analyzer_suspicious_path_finding():
    analyzer = DLLAnalyzer()

    report = analyzer.analyze(
        [
            {
                "PID": "4280",
                "Process": "explorer.exe",
                "Name": "plugin.dll",
                "Path": r"C:\\Users\\Lucky\\AppData\\Local\\Temp\\plugin.dll",
            }
        ],
        memory_path="input/memory.raw",
    )

    finding = report["findings"][0]
    assert finding["finding_type"] == "suspicious_module"
    assert finding["indicators"][0]["type"] == "suspicious_module_path"


def test_dll_analyzer_missing_path_indicator():
    analyzer = DLLAnalyzer()

    report = analyzer.analyze(
        [{"PID": "4280", "Process": "explorer.exe", "Name": "unknown.dll"}],
        memory_path="input/memory.raw",
    )

    assert report["findings"][0]["indicators"][0]["type"] == "unresolved_module_path"


def test_dll_analyzer_module_deduplication():
    analyzer = DLLAnalyzer()

    report = analyzer.analyze(
        [
            {"PID": "1", "Name": "a.dll", "Base": "0x1", "Path": r"C:\\Temp\\a.dll"},
            {"PID": "1", "Name": "a.dll", "Base": "0x1", "Path": r"C:\\Temp\\a.dll"},
        ],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["total_modules"] == 1


def test_dll_analyzer_module_memory_correlation():
    analyzer = DLLAnalyzer()
    module = analyzer.normalize_module(
        {
            "PID": "4280",
            "Process": "explorer.exe",
            "Name": "plugin.dll",
            "Base": "0x1000",
            "Path": r"C:\\Users\\Lucky\\AppData\\Local\\Temp\\plugin.dll",
        }
    )
    injection_report = {
        "findings": [
            {
                "pid": 4280,
                "finding_type": "potential_process_injection",
                "memory_regions": [
                    {
                        "virtual_address": "0x1000",
                        "protection": "PAGE_EXECUTE_READWRITE",
                        "backing_file": r"C:\\Users\\Lucky\\AppData\\Local\\Temp\\plugin.dll",
                    }
                ],
            }
        ]
    }

    correlation = analyzer.correlate_with_memory(module, injection_report)

    assert correlation["status"] == "matched_suspicious_memory"


def test_dll_analyzer_score_calculation_and_cap():
    analyzer = DLLAnalyzer()
    indicators = [
        {"type": "suspicious_module_path", "evidence": {"path": f"x{i}"}, "weight": 25}
        for i in range(5)
    ]

    assert analyzer.score_indicators(indicators) == 100


def test_dll_analyzer_severity_calculation():
    assert DLLAnalyzer.severity_for_score(10) == "LOW"
    assert DLLAnalyzer.severity_for_score(30) == "MEDIUM"
    assert DLLAnalyzer.severity_for_score(60) == "HIGH"
    assert DLLAnalyzer.severity_for_score(80) == "CRITICAL"


def test_dll_analyzer_confidence_calculation():
    analyzer = DLLAnalyzer()

    assert analyzer.confidence_for_indicators([{"type": "suspicious_module_path"}]) == "LOW"
    assert analyzer.confidence_for_indicators(
        [{"type": "suspicious_module_path"}, {"type": "unresolved_module_path"}]
    ) == "MEDIUM"
    assert analyzer.confidence_for_indicators(
        [
            {"type": "suspicious_module_path"},
            {"type": "unresolved_module_path"},
            {"type": "supporting_suspicious_executable_memory"},
        ]
    ) == "HIGH"


def test_dll_analyzer_json_serialization(tmp_path):
    analyzer = DLLAnalyzer()
    report = analyzer.analyze(
        [{"PID": "99", "Name": "odd.tmp", "Path": r"C:\\Users\\Public\\odd.tmp"}],
        memory_path="input/memory.raw",
    )
    output = tmp_path / "dll_findings.json"

    save_json_report(output, report)
    loaded = json.loads(output.read_text(encoding="utf-8"))

    assert loaded["analysis"]["method"] == "DLL/module enumeration and contextual analysis"
    assert loaded["summary"]["suspicious_modules"] == 1


def test_dll_analyzer_missing_optional_fields():
    analyzer = DLLAnalyzer()

    module = analyzer.normalize_module({"PID": "99"})

    assert module["pid"] == 99
    assert module["module_name"] is None
    assert module["path"] is None


def test_dll_analyzer_invalid_or_missing_pid_ignored():
    analyzer = DLLAnalyzer()

    assert analyzer.normalize_module({"PID": "not-a-pid", "Name": "x.dll"}) is None
    report = analyzer.analyze([{"Name": "x.dll"}], memory_path="input/memory.raw")

    assert report["summary"]["total_modules"] == 0
    assert report["findings"] == []


def test_dll_analyzer_empty_results():
    analyzer = DLLAnalyzer()

    report = analyzer.analyze([], memory_path="input/memory.raw")

    assert report["summary"]["processes_analyzed"] == 0
    assert report["summary"]["total_modules"] == 0
    assert report["findings"] == []


def test_dll_analyzer_multiple_dlls_and_processes():
    analyzer = DLLAnalyzer()

    report = analyzer.analyze(
        [
            {"PID": "1", "Process": "one.exe", "Name": "a.dll", "Path": r"C:\\Program Files\\One\\a.dll"},
            {"PID": "1", "Process": "one.exe", "Name": "b.dll", "Path": r"C:\\Program Files\\One\\b.dll"},
            {"PID": "2", "Process": "two.exe", "Name": "c.dll", "Path": r"C:\\Program Files\\Two\\c.dll"},
        ],
        memory_path="input/memory.raw",
    )

    assert report["summary"]["processes_analyzed"] == 2
    assert report["summary"]["total_modules"] == 3


def test_hook_detector_callback_normalization_and_anomaly():
    detector = HookDetector()

    report = detector.analyze(
        {
            "callbacks": [
                {
                    "Type": "PspCreateProcessNotifyRoutine",
                    "Callback": "0xfffff80012340000",
                    "Module": "N/A",
                    "Symbol": "N/A",
                    "Detail": "N/A",
                }
            ]
        },
        memory_path="input/memory.raw",
    )

    finding = report["findings"][0]
    assert finding["source_plugin"] == "callbacks"
    assert finding["indicators"][0]["type"] == "unresolved_kernel_callback"
    assert finding["severity"] == "LOW"


def test_hook_detector_known_callback_is_not_a_finding():
    detector = HookDetector()

    report = detector.analyze(
        {
            "callbacks": [
                {
                    "Type": "PspCreateProcessNotifyRoutine",
                    "Callback": "0xfffff80012340000",
                    "Module": "ntoskrnl",
                    "Symbol": "KnownCallback",
                }
            ]
        },
        memory_path="input/memory.raw",
    )

    assert report["summary"]["hook_related_findings"] == 0
    assert report["findings"] == []


def test_hook_detector_etw_patch_finding():
    detector = HookDetector()

    report = detector.analyze(
        {
            "etwpatch": [
                {
                    "PID": "1234",
                    "Process": "sample.exe",
                    "DLL": "ntdll.dll",
                    "Function": "EtwEventWrite",
                    "Offset": "0x1000",
                    "Opcode": "c3 (RET)",
                }
            ]
        },
        memory_path="input/memory.raw",
    )

    finding = report["findings"][0]
    assert finding["pid"] == 1234
    assert finding["indicators"][0]["type"] == "etw_patch_indicator"


def test_hook_detector_direct_and_indirect_syscall_findings():
    detector = HookDetector()

    report = detector.analyze(
        {
            "direct_system_calls": [
                {
                    "Process": "a.exe",
                    "PID": "11",
                    "Range": "private",
                    "Address": "0x111",
                    "Disasm": "syscall; ret",
                }
            ],
            "indirect_system_calls": [
                {
                    "Process": "b.exe",
                    "PID": "22",
                    "Range": "private",
                    "Address": "0x222",
                    "Disasm": "jmp [addr]",
                }
            ],
        },
        memory_path="input/memory.raw",
    )

    indicator_types = {
        finding["indicators"][0]["type"] for finding in report["findings"]
    }
    assert "direct_syscall_indicator" in indicator_types
    assert "indirect_syscall_indicator" in indicator_types


def test_hook_detector_unhooked_system_call_finding():
    detector = HookDetector()

    report = detector.analyze(
        {
            "unhooked_system_calls": [
                {
                    "Function": "NtProtectVirtualMemory",
                    "Distinct Implementations": "4321:sample.exe",
                    "Total Implementations": "4",
                }
            ]
        },
        memory_path="input/memory.raw",
    )

    assert report["findings"][0]["indicators"][0]["type"] == "ntdll_stub_variation"


def test_hook_detector_empty_and_malformed_output():
    detector = HookDetector()

    report = detector.analyze(
        {
            "etwpatch": [{"PID": "not-a-pid", "Process": "bad.exe"}],
            "unknown": [{"anything": "ignored"}],
        },
        memory_path="input/memory.raw",
    )

    assert report["summary"]["records_analyzed"] == 0
    assert report["findings"] == []


def test_hook_detector_score_severity_confidence():
    detector = HookDetector()
    indicators = [
        {
            "type": "etw_patch_indicator",
            "evidence": {"source": "etwpatch", "address": "0x1"},
            "weight": 35,
        },
        {
            "type": "supporting_injection_evidence",
            "evidence": {"source": "injection_findings", "address": "0x1"},
            "weight": 20,
        },
        {
            "type": "supporting_dll_evidence",
            "evidence": {"source": "dll_findings", "function": "x"},
            "weight": 15,
        },
    ]

    assert detector.score_indicators(indicators) == 70
    assert detector.severity_for_score(70) == "HIGH"
    assert detector.confidence_for_indicators(indicators) == "HIGH"


def test_hook_detector_correlation_with_injection_and_dll():
    detector = HookDetector()
    injection_report = {
        "findings": [
            {
                "pid": 1234,
                "memory_regions": [{"virtual_address": "0x1000"}],
            }
        ]
    }
    dll_report = {
        "findings": [
            {
                "module_name": "ntdll.dll",
            }
        ]
    }

    report = detector.analyze(
        {
            "etwpatch": [
                {
                    "PID": "1234",
                    "Process": "sample.exe",
                    "DLL": "ntdll.dll",
                    "Function": "EtwEventWrite",
                    "Offset": "0x1000",
                    "Opcode": "c3 (RET)",
                }
            ]
        },
        memory_path="input/memory.raw",
        injection_report=injection_report,
        dll_report=dll_report,
    )

    indicator_types = {indicator["type"] for indicator in report["findings"][0]["indicators"]}
    assert "supporting_injection_evidence" in indicator_types
    assert "supporting_dll_evidence" in indicator_types


def test_hook_detector_json_serialization(tmp_path):
    detector = HookDetector()
    report = detector.analyze(
        {"ssdt": [{"Index": "1", "Address": "0xffff", "Module": "N/A", "Symbol": "N/A"}]},
        memory_path="input/memory.raw",
    )
    output = tmp_path / "hook_findings.json"

    save_json_report(output, report)
    loaded = json.loads(output.read_text(encoding="utf-8"))

    assert loaded["analysis"]["analysis_type"] == "hook_related_detection"
    assert loaded["summary"]["hook_related_findings"] == 1


def test_memory_analyzer_generic_table_parser_for_callbacks():
    output = """
Volatility 3 Framework
Type    Callback            Module    Symbol    Detail
CbType  0xfffff80012340000  N/A       N/A       N/A
"""
    analyzer = MemoryAnalyzer("input/memory.raw")

    rows = analyzer._parse_table_text(output)

    assert rows[0]["Type"] == "CbType"
    assert rows[0]["Callback"] == "0xfffff80012340000"


def test_memory_analyzer_hook_plugin_failure_handling(monkeypatch):
    analyzer = MemoryAnalyzer("input/memory.raw")

    def fake_run(plugin_name):
        if plugin_name == analyzer.CALLBACKS_PLUGIN:
            return "Type    Callback    Module    Symbol\nCb    0x1    N/A    N/A\n"
        raise AnalysisError("plugin failed")

    monkeypatch.setattr(analyzer, "_run_volatility_plugin", fake_run)

    evidence = analyzer.collect_hook_evidence()

    assert evidence["callbacks"]["available"] is True
    assert evidence["ssdt"]["available"] is False


def test_memory_analyzer_detects_symbol_resolution_failure():
    message = """
    No suitable kernels found during pdbscan
    Unable to validate the plugin requirements:
    ['plugins.Info.kernel.layer_name', 'plugins.Info.kernel.symbol_table_name']
    """

    assert MemoryAnalyzer._is_symbol_resolution_error(message) is True


def test_memory_analyzer_symbol_resolution_error_is_actionable(tmp_path):
    analyzer = MemoryAnalyzer("input/memory.raw")
    analyzer.volatility_cache_path = tmp_path / "cache"
    analyzer.volatility_symbols_path = tmp_path / "cache" / "symbols"

    message = analyzer._symbol_resolution_error_message(
        "windows.info.Info",
        "No suitable kernels found during pdbscan",
    )

    assert "Analysis was not completed" in message
    assert "Cache path" in message
    assert "Symbol path" in message
    assert "pre-populate the Volatility symbols directory" in message


def test_risk_engine_scores_multiple_independent_sources():
    assessment = RiskEngine.assess(
        ["hidden_process", "process_injection", "hook_related"],
        indicator_count=4,
    )

    assert assessment.risk_score == 100
    assert assessment.severity == "CRITICAL"
    assert assessment.confidence == "MODERATE"


def test_risk_engine_confidence_for_single_source():
    assessment = RiskEngine.assess(["dll_anomaly"], indicator_count=1)

    assert assessment.risk_score == 25
    assert assessment.severity == "LOW"
    assert assessment.confidence == "LOW"


def test_correlation_engine_empty_reports():
    report = CorrelationEngine().analyze(memory_path="input/memory.raw")

    assert report["summary"]["input_findings"] == 0
    assert report["summary"]["correlated_findings"] == 0
    assert report["findings"] == []


def test_correlation_engine_combines_findings_by_pid():
    injection_report = {
        "findings": [
            {
                "pid": 123,
                "process_name": "sample.exe",
                "finding_type": "potential_process_injection",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "indicators": [{"type": "malfind_region", "description": "malfind", "evidence": {}}],
            }
        ]
    }
    hook_report = {
        "findings": [
            {
                "pid": 123,
                "process_name": "sample.exe",
                "finding_type": "hook_related_indicator",
                "severity": "HIGH",
                "confidence": "LOW",
                "indicators": [{"type": "etw_patch_indicator", "description": "etw", "evidence": {}}],
            }
        ]
    }

    report = CorrelationEngine().analyze(
        memory_path="input/memory.raw",
        injection_report=injection_report,
        hook_report=hook_report,
    )

    finding = report["findings"][0]
    assert report["summary"]["correlated_findings"] == 1
    assert finding["pid"] == 123
    assert "process-level association" in finding["explanation"]
    assert "same memory region or artifact" in finding["explanation"]
    assert finding["confidence"] == "LOW"
    assert set(finding["supporting_sources"]) == {"process_injection", "hook_related"}


def test_report_generator_writes_json_and_html(tmp_path):
    generator = ReportGenerator()
    correlation_report = {
        "summary": {"correlated_findings": 0},
        "findings": [],
        "warnings": [],
        "errors": [],
    }

    paths = generator.generate(
        output_dir=tmp_path,
        case_metadata={
            "case_id": "TEST-001",
            "examination_id": "EXAM-001",
            "examiner_name": "Test Examiner",
            "organization": "Test Organization",
        },
        provenance={"memory_image": "input/memory.raw", "sha256": "abc"},
        reports={"processes": {"summary": {"process_count": 0}}},
        correlation_report=correlation_report,
        warnings=[],
        errors=[],
    )

    assert paths["json"].exists()
    assert paths["html"].exists()
    loaded = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "1.0"
    assert loaded["analysis"]["analysis_type"] == "final_forensic_report"
    assert loaded["case_metadata"] == {
        "case_id": "TEST-001",
        "examination_id": "EXAM-001",
        "examiner_name": "Test Examiner",
        "organization": "Test Organization",
    }
    assert "No correlated findings" in paths["html"].read_text(encoding="utf-8")


def test_sha256_and_provenance_include_file_metadata(tmp_path):
    memory_image = tmp_path / "sample.raw"
    memory_image.write_bytes(b"abc")

    provenance = build_provenance(
        memory_path=memory_image,
        volatility_version="test-vol",
        enabled_analyzers=["processes"],
        disabled_analyzers=["hooks"],
    )

    assert sha256_file(memory_image) == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
    assert provenance["filename"] == "sample.raw"
    assert provenance["size_bytes"] == 3
    assert provenance["volatility_version"] == "test-vol"
    assert provenance["enabled_analyzers"] == ["processes"]


def test_demo_check_generates_non_forensic_reports(tmp_path):
    exit_code = main(["--demo-check", "-o", str(tmp_path)])

    assert exit_code == 0
    report_path = tmp_path / "forensic_report.json"
    html_path = tmp_path / "forensic_report.html"
    assert report_path.exists()
    assert html_path.exists()
    loaded = json.loads(report_path.read_text(encoding="utf-8"))
    assert loaded["analysis"]["status"] == "demo_check"
    assert loaded["analysis"]["is_real_forensic_analysis"] is False
    assert loaded["correlated_findings"] == []
    assert "NOT REAL FORENSIC ANALYSIS" in "\n".join(loaded["warnings"])

def test_memmap_rejects_different_address():
    detector = InjectionDetector()

    indicators = detector._corroborating_indicators(
        pid=123,
        regions=[{"pid": 123, "virtual_address": "0x1000"}],
        vad_records=[],
        memmap_records=[{"PID": 123, "Virtual": "0x9000"}],
    )

    assert not any(
        i["evidence"].get("source") == "memmap"
        for i in indicators
    )


def test_memmap_accepts_matching_address():
    detector = InjectionDetector()

    indicators = detector._corroborating_indicators(
        pid=123,
        regions=[{"pid": 123, "virtual_address": "0x1000"}],
        vad_records=[],
        memmap_records=[{"PID": 123, "Virtual": "4096"}],
    )

    assert any(
        i["evidence"].get("source") == "memmap"
        for i in indicators
    )