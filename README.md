# Automated Rootkit / Process Injection Detector

B.Tech Cybersecurity capstone project for Windows memory forensics.

## What This Project Is

This application analyzes a Windows RAM dump with Volatility 3. The long-term goal is to detect rootkit and process-injection indicators through explainable forensic modules.

Parts 1 through 7 are now implemented. The application validates a RAM dump, performs baseline process enumeration, compares `pslist` against `psscan` to identify potential hidden-process candidates, analyzes memory-region indicators for potential process injection, reviews loaded DLL/module evidence, collects hook-related indicators from the Volatility plugins available in this environment, correlates evidence across modules, assigns explainable risk/confidence labels, and writes final JSON/HTML reports. It does not make malware claims.

## Why Memory Forensics Matters

Memory forensics helps investigators inspect volatile system state that may not appear on disk, including running processes, loaded modules, network artifacts, injected code regions, and kernel-level structures. Rootkits and process injection often try to hide from normal operating system tools, so RAM analysis is an important evidence source.

## What Part 1 Does

- Validates that a supplied memory image exists, is readable, and is not empty.
- Warns about unusual file extensions without rejecting the image based on name alone.
- Uses Volatility 3 to confirm that the image can be parsed.
- Runs baseline Windows process enumeration with `windows.pslist.PsList`.
- Normalizes process records into a stable JSON schema.
- Saves structured output to `output/processes.json`.
- Preserves raw Volatility output in `output/volatility_process_output.txt`.
- Displays a concise process table in the terminal.

## Part 2 - Hidden Process Detection

Part 2 compares two independent Volatility process views:

- `windows.pslist.PsList` walks the normal active process list.
- `windows.psscan.PsScan` scans memory for process objects that may not appear in the normal list.

Cross-view analysis is useful because a process discovered by memory scanning but missing from normal enumeration can be a potential hidden, unlinked, terminated-but-resident, stale, or anomalous process structure.

The detector classifies each PID as:

- `NORMAL`: present in both `pslist` and `psscan`.
- `PSLIST_ONLY`: present in `pslist` but not `psscan`.
- `PSSCAN_ONLY`: present in `psscan` but not `pslist`.

Only `PSSCAN_ONLY` records generate suspicious findings in this stage. These findings are labeled as `potential_hidden_process` with `HIGH` severity and `MEDIUM` confidence. This does not prove malware or a rootkit. It is an indicator that needs investigator review and future correlation with other evidence.

## Part 3 - Process Injection Detection

Process injection is a technique where code or memory is placed into another process so it can execute in that process context. In memory forensics, this can sometimes be observed through suspicious VADs, executable private memory, writable executable memory, or memory regions identified by malware-analysis plugins.

Part 3 uses:

- `windows.malware.malfind.Malfind` as the primary suspicious memory-region source.
- `windows.vadinfo.VadInfo` as optional VAD context when available.
- `windows.memmap.Memmap` as optional memory mapping context when available.

`malfind` contributes process-specific suspicious memory regions, including fields such as PID, process name, VAD range, protection, private-memory flag, notes, hexdump, and disassembly where Volatility provides them. VAD information helps explain the memory range, protection, tag, private/file-backed characteristics, and mapped file when present. Memory mapping information can provide additional context, but the current stage does not depend on it for a finding.

The detector groups indicators by PID and produces one process-level finding per suspicious process instead of one alert per memory region. A finding is labeled `potential_process_injection`, not confirmed malware.

Indicators currently include:

- `malfind_region`: Volatility reported a suspicious memory region.
- `executable_writable_memory`: memory protection is executable and writable.
- `executable_private_memory`: executable memory is private.
- `unbacked_executable_memory`: executable memory has no obvious backing file in available evidence.
- `suspicious_vad`: VAD metadata or malfind notes add suspicious context.
- `corroborating_evidence`: optional VAD or memmap evidence corroborates the same suspicious process and, for memmap evidence, the matching virtual address.

Scoring is intentionally simple and explainable:

```text
malfind_region                 +30
executable_writable_memory     +25
executable_private_memory      +20
unbacked_executable_memory     +20
suspicious_vad                 +15
corroborating_evidence         +10
maximum score                  100
```

Severity uses the score:

```text
0-29    LOW
30-59   MEDIUM
60-79   HIGH
80-100  CRITICAL
```

Confidence is separate from severity:

```text
1 independent indicator    LOW
2 independent indicators   MEDIUM
3+ independent indicators  HIGH
```

Executable writable memory and executable private memory are suspicious indicators, but they can also occur in legitimate software, JIT-generated code, unpacked code, or runtime-generated memory. Findings require contextual forensic interpretation.

## Part 4 - DLL / Module Analysis

DLLs are shared code modules loaded into Windows processes. In memory forensics, loaded-module analysis helps investigators understand what code a process has mapped, where it came from, and whether module metadata appears unusual.

Part 4 uses `windows.dlllist.DllList` to enumerate loaded modules. Where Volatility provides it, the analyzer records PID, process name, module name, base address, image size, full path, load count, and load time.

The analyzer produces two outputs:

- A normalized module inventory grouped by process.
- Suspicious module findings based on contextual indicators.

Module path analysis distinguishes broad context such as Windows system paths, application directories, user-writable or unusual locations, unresolved paths, and unknown paths. A DLL outside `System32` is not treated as malicious by itself. Legitimate applications often load third-party plugins, app-specific libraries, and runtime components from their own directories.

DLL indicators currently include:

- `suspicious_module_path`: module is loaded from a user-writable or unusual location.
- `unresolved_module_path`: module path is missing or could not be resolved.
- `unusual_module_characteristics`: module name/path/extension has unusual structural characteristics.
- `supporting_suspicious_executable_memory`: Part 3 suspicious memory evidence correlates with the module.

DLL anomaly scoring is intentionally simple and explainable:

```text
suspicious_module_path                  +25
unresolved_module_path                  +10
unusual_module_characteristics          +15
module_memory_inconsistency             +20
supporting_suspicious_executable_memory +25
additional_corroborating_evidence       +10
maximum score                           100
```

Severity uses the score:

```text
0-29    LOW
30-59   MEDIUM
60-79   HIGH
80-100  CRITICAL
```

Confidence is separate from severity:

```text
1 meaningful indicator      LOW
2 corroborating indicators  MEDIUM
3+ independent indicators   HIGH
```

Suspicious DLL/module findings mean the module exhibits characteristics worth forensic review. They do not independently prove malicious activity.

## Part 5 - API / Hook-Related Detection

This environment does not provide an importable `windows.malware.apihooks` plugin. Part 5 therefore implements the strongest defensible hook-related analysis supported by the installed Volatility 3 package rather than claiming full API-hook detection.

Part 5 uses available evidence from:

- `windows.callbacks.Callbacks`: kernel callbacks and notification routines.
- `windows.ssdt.SSDT`: native system service table entries.
- `windows.etwpatch.EtwPatch`: ETW function patch indicators when available.
- `windows.malware.unhooked_system_calls.UnhookedSystemCalls`: differing system-call stub implementations across processes when available.
- Direct and indirect syscall plugins are attempted when supported by the installed Volatility environment; when unavailable, the application records the limitation explicitly.

Findings are labeled as hook-related indicators, such as suspicious callbacks, unresolved function pointers, ETW patch indicators, syscall evasion indicators, or possible control-flow redirection. They are not labeled as confirmed API hooks unless the available evidence would actually support that conclusion.

Hook-related scoring is intentionally simple:

```text
unresolved_kernel_callback      +25
unresolved_ssdt_entry           +30
etw_patch_indicator             +35
direct_syscall_indicator        +30
indirect_syscall_indicator      +35
ntdll_stub_variation            +25
supporting_injection_evidence   +20
supporting_dll_evidence         +15
maximum score                   100
```

Severity and confidence follow the same explainable pattern used by earlier detectors. Correlation is local to Part 5: hook-related addresses/modules may be correlated with Part 3 injection findings and Part 4 DLL findings when the available fields line up.

## Part 6 - Evidence Correlation and Risk Scoring

Part 6 groups findings by process context and creates a correlated finding when at least two independent analyzer families support the same PID or process identity. A same-process correlation does not necessarily mean that the findings independently corroborate the same memory region or artifact; it is an investigation lead that requires analyst review.

Correlation sources currently include:

- `hidden_process`: pslist-vs-psscan hidden-process candidates.
- `process_injection`: malfind/VAD/memmap process-injection indicators.
- `dll_anomaly`: suspicious or unresolved module indicators.
- `hook_related`: callback, SSDT, ETW patch, and syscall-related indicators.

The global risk engine is intentionally explainable. Each independent source contributes a fixed weight, repeated indicators add only limited extra weight, and the final risk score is capped at 100. Confidence is based on independent source count:

```text
0 sources  NONE
1 source   LOW
2 sources  LOW
3+ sources MODERATE
```

Correlated findings are investigation priorities, not proof of compromise.

## Part 7 - Final Report Generation

Part 7 writes:

```text
output/correlated_findings.json
output/forensic_report.json
output/forensic_report.html
```
The output directory can be changed with the `-o/--output-dir` option. For example, `-o output/final` writes the final reports under `output/final/`.

The final report includes:

- schema version
- analysis status and timestamp
- real-analysis flag
- memory image filename, size, and SHA-256 when a real image is analyzed
- Python and Volatility metadata
- enabled and disabled analyzers
- module summaries
- correlated findings
- warnings, errors, and forensic limitations

## Technologies Used

- Python 3
- Volatility 3
- pytest

## Installation

Create and activate a virtual environment on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## How To Place A Memory Dump

Put your Windows memory image in the `input` folder:

```text
input/memory.raw
```

Common extensions such as `.raw`, `.mem`, and `.dmp` are supported. The program treats file content as more important than the extension.

## How To Run

Show help:

```powershell
python main.py --help
```

Analyze a memory image:

```powershell
python main.py -f input/memory.raw
```

Equivalent long option:

```powershell
python main.py --file input/memory.raw
```

Skip hidden-process analysis (`pslist` vs `psscan` comparison):

```powershell
python main.py --file input/memory.raw --skip-hidden
```

Skip process-injection analysis (`malfind` / VAD / `memmap`):

```powershell
python main.py --file input/memory.raw --skip-injection
```

Skip DLL/module analysis (`dlllist`):

```powershell
python main.py --file input/memory.raw --skip-dll
```

Skip hook-related analysis (callbacks / SSDT / ETW / syscalls):

```powershell
python main.py --file input/memory.raw --skip-hooks
```

Run only baseline process enumeration (skip all optional detectors):

```powershell
python main.py --file input/memory.raw --skip-hidden --skip-injection --skip-dll --skip-hooks
```

Run the software self-test without a memory image:

```powershell
python main.py --demo-check
```

`--demo-check` creates final JSON/HTML reports with empty findings and explicitly marks them as `NOT REAL FORENSIC ANALYSIS`. It is useful for project review when no RAM dump is available, but it is not forensic evidence.

## 5-Minute Demo

1. Show the project help:

```powershell
python main.py --help
```

2. Show graceful handling when no memory image is present:

```powershell
python main.py -f input/memory.raw
```

Expected result when the file is absent:

```text
Memory image does not exist: input\memory.raw
```

3. Generate review-ready report files without fake evidence:

```powershell
python main.py --demo-check
```

Expected generated files:

```text
output/forensic_report.json
output/forensic_report.html
```

4. Run the test suite:

```powershell
python -m pytest -p no:cacheprovider
```

Expected result in this environment:

```text
66 passed
```

## Illustrative Example Output

The following is only an illustrative format example, not real forensic output:

```text
==================================================
PROCESS ANALYSIS
==================================================
PID       PPID      PROCESS
--------------------------------------------------
4         0         System
500       4         smss.exe
700       500       csrss.exe

Total Processes: 3

==================================================
HIDDEN PROCESS ANALYSIS
==================================================
[+] pslist processes: 3
[+] psscan processes: 4
[*] Comparing process views...

--------------------------------------------------
CROSS-VIEW SUMMARY
--------------------------------------------------
Normal processes       : 3
psscan-only candidates : 1
Potential hidden       : 1

==================================================
PROCESS INJECTION ANALYSIS
==================================================
[*] Running memory analysis...
[*] Running malfind...
[+] Suspicious memory regions identified: 1

==================================================
INJECTION DETECTION SUMMARY
==================================================
Processes analyzed       : 1
Suspicious regions        : 1
Potential injection cases : 1

==================================================
DLL / MODULE ANALYSIS
==================================================
[*] Enumerating loaded modules...
[+] Processes analyzed: 3
[+] Modules discovered: 40

==================================================
DLL ANALYSIS SUMMARY
==================================================
Total modules       : 40
Suspicious modules  : 1

==================================================
HOOK-RELATED ANALYSIS
==================================================
[*] Collecting callback, SSDT, ETW, and syscall-related evidence...
[+] Records analyzed: 2

==================================================
HOOK ANALYSIS SUMMARY
==================================================
Hook-related findings : 1
```

The example above is illustrative only. Real findings are generated only from an actual RAM dump and Volatility output.

## Output Files

Structured process report:

```text
output/processes.json
```

Raw Volatility process output:

```text
output/volatility_process_output.txt
```

Part 2 hidden-process analysis:

```text
output/hidden_process_findings.json
output/volatility_pslist_output.txt
output/volatility_psscan_output.txt
```

Part 3 process-injection analysis:

```text
output/injection_findings.json
output/volatility_malfind_output.txt
output/volatility_vadinfo_output.txt
output/volatility_memmap_output.txt
```

Part 4 DLL/module analysis:

```text
output/modules.json
output/dll_findings.json
output/volatility_dlllist_output.txt
```

Part 5 hook-related analysis:

```text
output/hook_findings.json
output/volatility_callbacks_output.txt
output/volatility_ssdt_output.txt
output/volatility_etwpatch_output.txt
output/volatility_direct_system_calls_output.txt
output/volatility_indirect_system_calls_output.txt
output/volatility_unhooked_system_calls_output.txt
```

Final correlated and review reports:

```text
output/correlated_findings.json
output/forensic_report.json
output/forensic_report.html
```

The raw output is preserved as evidence from the underlying forensic tool. The JSON report avoids developer-specific absolute paths where possible.

## Project Architecture

```text
rootkit_process_injection_detector/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── input/
├── output/
├── reports/
├── analyzer/
│   ├── memory_analyzer.py
│   ├── hidden_process_detector.py
│   ├── injection_detector.py
│   ├── dll_analyzer.py
│   ├── hook_detector.py
│   ├── correlation_engine.py
│   ├── risk_engine.py
│   ├── report_generator.py
│   ├── process_analyzer.py
│   └── utils.py
└── tests/
    └── test_basic.py
```

`memory_analyzer.py` contains the Volatility-specific integration. `process_analyzer.py` handles normalization and report assembly. `hidden_process_detector.py` performs pslist-vs-psscan comparison. `injection_detector.py` correlates suspicious memory-region indicators. `dll_analyzer.py` normalizes and analyzes loaded modules. `hook_detector.py` normalizes hook-related plugin evidence. `correlation_engine.py` groups multi-source evidence. `risk_engine.py` provides unified risk/confidence scoring. `report_generator.py` writes the final JSON and HTML reports. `utils.py` contains shared validation, provenance, logging, and persistence helpers.

Conceptual flow:

```text
RAM DUMP
   |
                 MemoryAnalyzer
                       |
       pslist + psscan + malfind + dlllist + hook-related plugins
                       |
       Process / Memory / Module / Callback Evidence
                       |
 HiddenProcessDetector + InjectionDetector + DLLAnalyzer + HookDetector
                       |
              Structured JSON Findings
                       |
        CorrelationEngine + RiskEngine + ReportGenerator
                       |
        Final JSON/HTML Forensic Report
```

## Current Limitations

- Requires a real Windows memory image for full analysis.
- Does not provide classic `windows.malware.apihooks` output because that plugin is unavailable here.
- Direct and indirect syscall analysis plugins were not available in the installed Volatility 3 environment, so the detector records them as unavailable rather than treating their absence as negative evidence.
- Risk scores are triage scores, not malware probabilities.
- Process-injection scoring is heuristic and explainable, not a scientific probability.
- DLL/module scoring is heuristic and explainable, not a malware probability.
- Optional VAD or memmap collection may fail depending on Volatility support and image characteristics.
- Volatility symbol download or cache setup may be required depending on the image.

## Real Image Validation Note

The first real end-to-end candidate image tested was:

```text
input/MemoryDump_Lab3.raw
SHA-256: a43797b924f7de2629dc466f61e3c7edff1484e9ad6ac702bddd4c9d5f4be1e5
Size: 1,048,510,464 bytes
```

Direct Volatility validation can be performed with:

```powershell
vol --cache-path .volatility_cache_lab3 -f input\MemoryDump_Lab3.raw windows.info
vol --cache-path .volatility_cache_lab3 -f input\MemoryDump_Lab3.raw windows.pslist
```

Volatility symbol and layer resolution is image- and environment-dependent. Individual plugins may also be unavailable even when baseline process analysis succeeds.

For this project, the application records symbol/layer/plugin failures explicitly and does not treat an unavailable plugin as evidence that no corresponding activity exists.

The Lab3 image was successfully processed by the completed detector pipeline, producing structured JSON and HTML reports. The resulting findings remain heuristic forensic indicators and require analyst interpretation; successful execution does not mean that every optional Volatility plugin was available or that malicious activity was confirmed.


## Roadmap

[COMPLETED] Part 1 - RAM dump validation + basic process analysis

[COMPLETED] Part 2 - Hidden process detection

[COMPLETED] Part 3 - Process injection detection

[COMPLETED] Part 4 - DLL/module analysis

[COMPLETED] Part 5 - API / hook-related detection

[COMPLETED] Part 6 - Full evidence correlation/risk engine

[COMPLETED] Part 7 - Automated forensic reporting

[FUTURE] Part 8 - Optional GUI

## Forensic Design Principles

- Preserve raw evidence.
- Do not modify the memory dump.
- Separate evidence collection from analysis.
- Keep detection logic explainable.
- Record where each result came from.
- Avoid claiming something is malicious without evidence.
- Make future findings traceable to underlying forensic output.
