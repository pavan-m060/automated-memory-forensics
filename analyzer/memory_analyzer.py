"""Volatility 3 integration for Windows memory-image analysis."""

from __future__ import annotations

import contextlib
import importlib
import io
import logging
import os
import re
import tempfile
import sys
from pathlib import Path
from typing import Any

from analyzer.process_analyzer import ProcessAnalyzer
from analyzer.utils import AnalysisError, get_logger, validate_memory_file


class MemoryAnalyzer:
    """Wraps Volatility 3 validation and process enumeration."""

    INFO_PLUGIN = "windows.info.Info"
    PSLIST_PLUGIN = "windows.pslist.PsList"
    PSSCAN_PLUGIN = "windows.psscan.PsScan"
    MALFIND_PLUGIN = "windows.malware.malfind.Malfind"
    VADINFO_PLUGIN = "windows.vadinfo.VadInfo"
    MEMMAP_PLUGIN = "windows.memmap.Memmap"
    DLLLIST_PLUGIN = "windows.dlllist.DllList"
    CALLBACKS_PLUGIN = "windows.callbacks.Callbacks"
    SSDT_PLUGIN = "windows.ssdt.SSDT"
    ETWPATCH_PLUGIN = "windows.etwpatch.EtwPatch"
    DIRECT_SYSCALL_PLUGIN = (
        "windows.malware.direct_system_calls.DirectSystemCalls"
    )
    INDIRECT_SYSCALL_PLUGIN = (
        "windows.malware.indirect_system_calls.IndirectSystemCalls"
    )
    UNHOOKED_SYSCALL_PLUGIN = (
        "windows.malware.unhooked_system_calls.UnhookedSystemCalls"
    )

    def __init__(self, memory_path: Path | str) -> None:
        self.memory_path = Path(memory_path)
        self.logger = get_logger(__name__)
        self.process_analyzer = ProcessAnalyzer()
        self.volatility_version = "unknown"
        self.volatility_cache_path: Path | None = None
        self.volatility_symbols_path: Path | None = None

    def validate_image(self) -> None:
        """Validates filesystem properties and confirms Volatility can parse the image."""
        warnings = validate_memory_file(self.memory_path)

        for warning in warnings:
            self.logger.warning(warning)

        output = self._run_volatility_plugin(self.INFO_PLUGIN)

        if not output.strip():
            raise AnalysisError(
                "Memory image could not be parsed by Volatility 3."
            )

    def enumerate_processes(
        self,
    ) -> tuple[list[dict[str, Any]], str]:
        """Runs Volatility's Windows pslist plugin and normalizes process rows."""
        rows, raw_output = self.enumerate_process_view("pslist")

        if not rows:
            raise AnalysisError(
                "Volatility completed process enumeration but no process rows "
                "were parsed. The image may be unsupported, corrupt, or the "
                "Volatility output format may have changed."
            )

        return rows, raw_output

    def enumerate_process_view(
        self,
        view: str,
    ) -> tuple[list[dict[str, Any]], str]:
        """Enumerates processes from a named Volatility process view."""
        plugin_by_view = {
            "pslist": self.PSLIST_PLUGIN,
            "psscan": self.PSSCAN_PLUGIN,
        }

        plugin_name = plugin_by_view.get(view)

        if plugin_name is None:
            raise AnalysisError(
                f"Unsupported process view requested: {view}"
            )

        raw_output = self._run_volatility_plugin(plugin_name)
        rows = self._parse_process_text(raw_output)

        if not rows:
            raise AnalysisError(
                f"Volatility completed {view} but no process rows were parsed. "
                "The image may be unsupported, corrupt, or the Volatility "
                "output format may have changed."
            )

        return (
            self.process_analyzer.normalize_processes(
                rows,
                source=view,
            ),
            raw_output,
        )

    def scan_processes(
        self,
    ) -> tuple[list[dict[str, Any]], str]:
        """Runs Volatility's Windows psscan plugin and normalizes process rows."""
        try:
            return self.enumerate_process_view("psscan")
        except AnalysisError as exc:
            raise AnalysisError(
                "Hidden process analysis could not be completed because "
                f"psscan failed. {exc}",
                exit_code=exc.exit_code,
            ) from exc

    def collect_injection_evidence(
        self,
    ) -> dict[str, dict[str, Any]]:
        """Collects process-injection evidence from supported Volatility plugins."""
        evidence: dict[str, dict[str, Any]] = {}

        try:
            malfind_raw = self._run_volatility_plugin(
                self.MALFIND_PLUGIN
            )

            evidence["malfind"] = {
                "records": self._parse_process_text(malfind_raw),
                "raw_output": malfind_raw,
                "available": True,
                "error": None,
            }

        except AnalysisError as exc:
            raise AnalysisError(
                "Process injection analysis could not be completed because "
                f"malfind failed. {exc}",
                exit_code=exc.exit_code,
            ) from exc

        for name, plugin in (
            ("vadinfo", self.VADINFO_PLUGIN),
            ("memmap", self.MEMMAP_PLUGIN),
        ):
            try:
                raw_output = self._run_volatility_plugin(plugin)

                evidence[name] = {
                    "records": self._parse_process_text(raw_output),
                    "raw_output": raw_output,
                    "available": True,
                    "error": None,
                }

            except AnalysisError as exc:
                self.logger.warning(
                    "%s analysis unavailable. Continuing with malfind "
                    "and available memory evidence.",
                    name.upper(),
                )

                evidence[name] = {
                    "records": [],
                    "raw_output": "",
                    "available": False,
                    "error": str(exc),
                }

        return evidence

    def collect_dll_evidence(self) -> dict[str, Any]:
        """Collects loaded DLL/module evidence with Volatility dlllist."""
        try:
            raw_output = self._run_volatility_plugin(
                self.DLLLIST_PLUGIN
            )

        except AnalysisError as exc:
            raise AnalysisError(
                f"DLL/module analysis could not be completed. {exc}",
                exit_code=exc.exit_code,
            ) from exc

        return {
            "records": self._parse_process_text(raw_output),
            "raw_output": raw_output,
            "available": True,
            "error": None,
        }

    def collect_hook_evidence(
        self,
    ) -> dict[str, dict[str, Any]]:
        """Collects available hook-related evidence from supported Volatility plugins."""
        plugins = {
            "callbacks": self.CALLBACKS_PLUGIN,
            "ssdt": self.SSDT_PLUGIN,
            "etwpatch": self.ETWPATCH_PLUGIN,
            "direct_system_calls": self.DIRECT_SYSCALL_PLUGIN,
            "indirect_system_calls": self.INDIRECT_SYSCALL_PLUGIN,
            "unhooked_system_calls": self.UNHOOKED_SYSCALL_PLUGIN,
        }

        evidence: dict[str, dict[str, Any]] = {}

        for name, plugin in plugins.items():
            try:
                raw_output = self._run_volatility_plugin(plugin)

                evidence[name] = {
                    "records": (
                        self._parse_unhooked_system_calls_text(raw_output)
                        if name == "unhooked_system_calls"
                        else self._parse_table_text(raw_output)
                    ),
                    "raw_output": raw_output,
                    "available": True,
                    "error": None,
                    "plugin": plugin,
                }

            except AnalysisError as exc:
                self.logger.warning(
                    "%s hook-related analysis unavailable. "
                    "Continuing with available evidence.",
                    name,
                )

                evidence[name] = {
                    "records": [],
                    "raw_output": "",
                    "available": False,
                    "error": str(exc),
                    "plugin": plugin,
                }

        return evidence

    def _run_volatility_plugin(
        self,
        plugin_name: str,
    ) -> str:
        """Runs a Volatility 3 plugin in-process.

        Volatility first gets its normal automatic Windows layer detection.

        If normal detection fails because the Windows kernel layer/symbol
        requirements cannot be satisfied, and VOLATILITY_PAE_DTB is explicitly
        provided, the plugin is retried using a WindowsIntelPAE layer with
        the supplied DTB.

        Example:

            set VOLATILITY_PAE_DTB=0x185000

        The normal Volatility path remains the default. The explicit PAE
        configuration is only a fallback.
        """

        self._prepare_volatility_environment()

        try:
            volatility3 = importlib.import_module("volatility3")
            volatility_cli = importlib.import_module("volatility3.cli")

        except ImportError as exc:
            raise AnalysisError(
                "Volatility 3 is not installed. "
                "Install it with: pip install volatility3",
                exit_code=3,
            ) from exc

        self.volatility_version = self._detect_volatility_version(
            volatility3
        )

        def run_cli(
            extra_args: list[str] | None = None,
        ) -> tuple[str, str, int]:
            """Runs Volatility CLI and captures stdout/stderr safely."""

            stdout = io.StringIO()
            stderr = io.StringIO()

            original_argv = sys.argv[:]

            sys.argv = [
                "vol",
                "-q",
                "--cache-path",
                str(self.volatility_cache_path),
                "-s",
                str(self.volatility_symbols_path),
                "-f",
                str(self.memory_path),
            ]

            if extra_args:
                sys.argv.extend(extra_args)

            sys.argv.append(plugin_name)

            volatility_logger = logging.getLogger("volatility3")

            original_volatility_level = (
                volatility_logger.level
            )

            root_logger = logging.getLogger()

            original_root_level = root_logger.level
            original_handlers = root_logger.handlers[:]

            original_handler_formatters = {
                handler: handler.formatter
                for handler in original_handlers
            }

            original_handler_levels = {
                handler: handler.level
                for handler in original_handlers
            }

            volatility_logger.setLevel(logging.ERROR)

            exit_code = 0

            try:
                with contextlib.redirect_stdout(
                    stdout
                ), contextlib.redirect_stderr(stderr):

                    try:
                        volatility_cli.main()

                    except SystemExit as exc:
                        if isinstance(exc.code, int):
                            exit_code = exc.code
                        elif exc.code is None:
                            exit_code = 0
                        else:
                            exit_code = 1

                    except Exception as exc:
                        exit_code = 1
                        stderr.write(str(exc))

            finally:
                sys.argv = original_argv

                volatility_logger.setLevel(
                    original_volatility_level
                )

                root_logger.handlers = original_handlers
                root_logger.setLevel(original_root_level)

                for handler in original_handlers:
                    handler.setFormatter(
                        original_handler_formatters[handler]
                    )
                    handler.setLevel(
                        original_handler_levels[handler]
                    )

            return (
                stdout.getvalue(),
                stderr.getvalue(),
                exit_code,
            )

        # ============================================================
        # ATTEMPT 1
        # Normal Volatility automagic
        # ============================================================

        stdout, stderr, exit_code = run_cli()

        combined_diagnostics = (
            f"{stderr}\n{stdout}"
        ).strip()

        if exit_code == 0:
            return stdout

        # ============================================================
        # ATTEMPT 2
        # Explicit WindowsIntelPAE layer
        #
        # Only enabled when the user explicitly provides:
        #
        #     VOLATILITY_PAE_DTB=0x185000
        #
        # ============================================================

        pae_dtb = os.environ.get(
            "VOLATILITY_PAE_DTB"
        )

        should_try_pae_override = (
            bool(pae_dtb)
            and self._is_symbol_resolution_error(
                combined_diagnostics
            )
        )

        if should_try_pae_override:

            try:
                normalized_dtb = pae_dtb.strip().lower()

                if normalized_dtb.startswith("0x"):
                    page_map_offset = int(
                        normalized_dtb,
                        16,
                    )
                else:
                    page_map_offset = int(
                        normalized_dtb,
                        0,
                    )

                if page_map_offset < 0:
                    raise ValueError(
                        "DTB must be non-negative."
                    )

            except (TypeError, ValueError) as exc:
                raise AnalysisError(
                    "Invalid VOLATILITY_PAE_DTB value. "
                    "Use a hexadecimal or decimal DTB, "
                    "for example 0x185000."
                ) from exc

            # Example:
            #
            # windows.info.Info
            #       ↓
            # Info
            #
            # windows.pslist.PsList
            #       ↓
            # PsList
            #
            plugin_class = plugin_name.rsplit(
                ".",
                1,
            )[-1]

            # Convert the Windows path to a proper file:// URI.
            #
            # This also correctly percent-encodes the Japanese
            # characters in the user's OneDrive path.
            file_uri = self.memory_path.resolve().as_uri()

            explicit_layer_args = [
                "-e",
                (
                     f'plugins.{plugin_class}.kernel.layer_name.class='
                     '"volatility3.framework.layers.intel.WindowsIntelPAE"'
                ),
                "-e",
                (
                     f'plugins.{plugin_class}.'
                     'kernel.layer_name.memory_layer.class='
                     '"volatility3.framework.layers.physical.FileLayer"'
                ),
                "-e",
                (
                     f'plugins.{plugin_class}.'
                     'kernel.layer_name.memory_layer.location='
                     f'"{file_uri}"'
                ),
                "-e",
                (
                     f'plugins.{plugin_class}.'
                     'kernel.layer_name.page_map_offset='
                     f"{page_map_offset}"
                ),
            ]

            self.logger.warning(
                "Normal Volatility Windows layer detection failed "
                "for %s. Retrying with explicit WindowsIntelPAE "
                "DTB 0x%x.",
                plugin_name,
                page_map_offset,
            )

            stdout, stderr, exit_code = run_cli(
                explicit_layer_args
            )

            if exit_code == 0:
                self.logger.info(
                    "Volatility succeeded using explicit "
                    "WindowsIntelPAE layer with DTB 0x%x.",
                    page_map_offset,
                )

                return stdout

            combined_diagnostics = (
                f"{stderr}\n{stdout}"
            ).strip()

        # ============================================================
        # FINAL FAILURE
        # ============================================================

        if self._is_symbol_resolution_error(
            combined_diagnostics
        ):
            raise AnalysisError(
                self._symbol_resolution_error_message(
                    plugin_name,
                    combined_diagnostics,
                )
            )

        raise AnalysisError(
            f"Volatility plugin failed ({plugin_name}): "
            f"{combined_diagnostics or 'no diagnostic output'}"
        )

    def _prepare_volatility_environment(self) -> None:
        """Prepares writable Volatility cache and symbol directories."""
        appdata = os.environ.get("APPDATA")

        candidates = []

        if appdata:
            candidates.append(
                Path(appdata) / "volatility3"
            )

        candidates.append(
            Path.cwd() / ".volatility_cache"
        )

        candidates.append(
            Path(tempfile.gettempdir())
            / "rootkit_detector_volatility3"
        )

        for cache_path in candidates:
            symbols_path = cache_path / "symbols"

            try:
                cache_path.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                symbols_path.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                probe = (
                    cache_path
                    / ".volatility_write_test"
                )

                probe.write_text(
                    "ok",
                    encoding="utf-8",
                )

                probe.unlink(
                    missing_ok=True
                )

            except OSError:
                continue

            self.volatility_cache_path = cache_path
            self.volatility_symbols_path = symbols_path

            if (
                appdata is None
                or cache_path
                != Path(appdata) / "volatility3"
            ):
                os.environ["APPDATA"] = str(
                    cache_path.parent
                )

            return

        raise AnalysisError(
            "Volatility cache setup failed. "
            "Could not create a writable cache/symbol directory.",
            exit_code=3,
        )

    @staticmethod
    def _is_symbol_resolution_error(
        message: str,
    ) -> bool:
        """Detects Volatility failures caused by kernel layer/symbol resolution."""

        lowered = message.lower()

        return any(
            fragment in lowered
            for fragment in (
                "no suitable kernels found during pdbscan",
                "symbol_table_name",
                "kernel.layer_name",
                "a symbol table requirement was not fulfilled",
                "a translation layer requirement was not fulfilled",
            )
        )

    def _symbol_resolution_error_message(
        self,
        plugin_name: str,
        volatility_message: str,
    ) -> str:
        """Builds an actionable symbol-resolution failure message."""

        cache_path = (
            self.volatility_cache_path
            or Path("<unknown>")
        )

        symbols_path = (
            self.volatility_symbols_path
            or Path("<unknown>")
        )

        diagnostic = self._symbol_resolution_diagnostic(
            volatility_message
        )

        return (
            f"Volatility could not resolve Windows kernel "
            f"symbols for {plugin_name}. "
            "Analysis was not completed. Volatility reported "
            "an unsatisfied kernel layer/symbol requirement, "
            "commonly seen when PDB scanning cannot identify "
            "a suitable kernel or the required Windows symbol "
            "table is unavailable. "
            f"Cache path: {cache_path}. "
            f"Symbol path: {symbols_path}. "
            "Confirm the image is supported by this Volatility "
            "3 version, verify network access to symbol sources, "
            "or pre-populate the Volatility symbols directory "
            "with the correct Windows ISF for this image. "
            f"Key Volatility diagnostic: {diagnostic}"
        )

    @staticmethod
    def _symbol_resolution_diagnostic(
        volatility_message: str,
    ) -> str:
        """Extracts concise, useful Volatility diagnostics from noisy output."""

        interesting_fragments = (
            "No suitable kernels found during pdbscan",
            "Unable to validate the plugin requirements",
            "kernel.layer_name",
            "kernel.symbol_table_name",
            "A symbol table requirement was not fulfilled",
            "A translation layer requirement was not fulfilled",
        )

        lines = []

        for line in volatility_message.splitlines():
            cleaned = line.strip()

            if any(
                fragment in cleaned
                for fragment in interesting_fragments
            ):
                lines.append(cleaned)

        if not lines:
            lines = [
                volatility_message.strip()[:300]
                or "no diagnostic output"
            ]

        return " | ".join(lines[:5])

    @staticmethod
    def _detect_volatility_version(
        volatility_module: Any,
    ) -> str:
        version = getattr(
            volatility_module,
            "__version__",
            None,
        )

        if version:
            return str(version)

        try:
            constants = importlib.import_module(
                "volatility3.framework.constants"
            )

            return str(
                getattr(
                    constants,
                    "PACKAGE_VERSION",
                    "unknown",
                )
            )

        except ImportError:
            return "unknown"

    def _parse_pslist_text(
        self,
        output: str,
    ) -> list[dict[str, str]]:
        """Backward-compatible parser wrapper for Part 1 tests."""
        return self._parse_process_text(output)

    def _parse_process_text(
        self,
        output: str,
    ) -> list[dict[str, str]]:
        """Parses text renderer output from Volatility process plugins."""

        lines = [
            line.rstrip()
            for line in output.splitlines()
            if line.strip()
        ]

        header_index = self._find_header_index(
            lines
        )

        if header_index is None:
            return []

        headers = re.split(
            r"\s{2,}|\t+",
            lines[header_index].strip(),
        )

        rows: list[dict[str, str]] = []

        for line in lines[header_index + 1:]:
            if set(line.strip()) <= {"-", "="}:
                continue

            values = re.split(
                r"\s{2,}|\t+",
                line.strip(),
                maxsplit=max(
                    len(headers) - 1,
                    0,
                ),
            )

            if len(values) < 3:
                continue

            row = dict(
                zip(
                    headers,
                    values,
                )
            )

            if "PID" not in row:
                continue

            rows.append(row)

        return rows
    
    @staticmethod
    def _parse_unhooked_system_calls_text(
        output: str,
    ) -> list[dict[str, str]]:
        """Parses Volatility's unhooked_system_calls output."""

        lines = [
            line.rstrip()
            for line in output.splitlines()
            if line.strip()
        ]

        header_index = None

        for index, line in enumerate(lines):
            if (
                "Function" in line
                and "Distinct Implementations" in line
                and "Total Implementations" in line
            ):
                header_index = index
                break

        if header_index is None:
            return []

        rows: list[dict[str, str]] = []

        for line in lines[header_index + 1:]:
            if set(line.strip()) <= {"-", "="}:
                continue

            values = line.split("\t")
            if not values:
                continue
            rows.append(
                {
                    "Function": values[0].strip(),
                    "Distinct Implementations": (
                        values[1].strip()
                        if len(values) > 1
                        else ""
                    ),
                    "Total Implementations": (
                        values[2].strip()
                        if len(values) > 2
                        else ""
                    ),
                 }
            )

        return rows
    
    def _parse_table_text(
        self,
        output: str,
    ) -> list[dict[str, str]]:
        """Parses generic Volatility text-renderer tables."""

        lines = [
            line.rstrip()
            for line in output.splitlines()
            if line.strip()
        ]

        header_index = (
            self._find_any_table_header_index(
                lines
            )
        )

        if header_index is None:
            return []

        headers = re.split(
            r"\s{2,}|\t+",
            lines[header_index].strip(),
        )

        rows: list[dict[str, str]] = []

        for line in lines[header_index + 1:]:
            if set(line.strip()) <= {"-", "="}:
                continue

            values = re.split(
                r"\s{2,}|\t+",
                line.strip(),
                maxsplit=max(
                    len(headers) - 1,
                    0,
                ),
            )

            if len(values) < 2:
                continue

            rows.append(
                dict(
                    zip(
                        headers,
                        values,
                    )
                )
            )

        return rows

    @staticmethod
    def _find_header_index(
        lines: list[str],
    ) -> int | None:

        for index, line in enumerate(lines):

            if (
                "PID" in line
                and "PPID" in line
                and (
                    "ImageFileName" in line
                    or "Process" in line
                    or "Name" in line
                )
            ):
                return index

            if (
                "PID" in line
                and (
                    "ImageFileName" in line
                    or "Process" in line
                    or "Name" in line
                )
            ):
                return index

        return None

    @staticmethod
    def _find_any_table_header_index(
        lines: list[str],
    ) -> int | None:

        known_headers = (
            (
                "Type",
                "Callback",
                "Module",
                "Symbol",
            ),
            (
                "Index",
                "Address",
                "Module",
                "Symbol",
            ),
            (
                "PID",
                "Process",
                "DLL",
                "Function",
                "Offset",
                "Opcode",
            ),
            (
                "Process",
                "PID",
                "Range",
                "Address",
                "Disasm",
            ),
            (
                "Function",
                "Distinct Implementations",
                "Total Implementations",
            ),
            (
                "PID",
                "Name",
                "Library",
                "Function",
                "Address",
            ),
        )

        for index, line in enumerate(lines):
            if any(
                all(
                    header in line
                    for header in headers
                )
                for headers in known_headers
            ):
                return index

        return None