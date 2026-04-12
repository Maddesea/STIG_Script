"""Command-line interface and main entry point."""

from __future__ import annotations

import argparse
import gc
import json
import logging
import re
import shutil
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
import threading
import time
import zipfile
from pathlib import Path
from typing import List, Optional

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import APP_NAME, VERSION
from stig_assessor.core.deps import Deps
from stig_assessor.core.logging import LOG
from stig_assessor.core.state import GlobalState
from stig_assessor.evidence.manager import EvidenceMgr
from stig_assessor.exceptions import ParseError, ValidationError
from stig_assessor.io.file_ops import FO
from stig_assessor.processor.processor import Proc
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro
from stig_assessor.templates.boilerplate import BP


class Spinner:
    """A simple CLI spinner for long-running operations."""

    def __init__(self, message="Processing"):
        self.message = message
        self.running = False
        self.thread = None

    def spin(self):
        spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while self.running:
            sys.stderr.write(
                f"\r{format_color(self.message, 'blue')} {format_color(spinner_chars[idx], 'yellow')} "
            )
            sys.stderr.flush()
            idx = (idx + 1) % len(spinner_chars)
            time.sleep(0.1)
        sys.stderr.flush()

    def __enter__(self):
        if sys.stdout.isatty():
            self.running = True
            self.thread = threading.Thread(target=self.spin, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join()


def prompt_missing(prompt_text: str) -> str:
    """Prompt for missing arguments if in interactive mode."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            # Clear any current line content
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            val = input(format_color(f"? {prompt_text}: ", "yellow")).strip()
            return val
        except (EOFError, KeyboardInterrupt):
            print()
            return ""
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# ANSI COLOR SUPPORT
# ──────────────────────────────────────────────────────────────────────────────

_ANSI_CODES = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _color_supported() -> bool:
    """Detect whether the current terminal supports ANSI color output.

    Respects the NO_COLOR (https://no-color.org) convention and checks
    whether stderr (used for spinner output) is a real TTY.
    """
    import os

    if os.environ.get("NO_COLOR"):
        return False
    # Check stderr since that's where spinner/progress output goes
    if not (hasattr(sys.stderr, "isatty") and sys.stderr.isatty()):
        return False
    # Enable VT100 processing on Windows 10+
    if Cfg.IS_WIN:
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            # STD_ERROR_HANDLE = -12, STD_OUTPUT_HANDLE = -11
            for handle_id in (-11, -12):
                handle = kernel32.GetStdHandle(handle_id)
                mode = ctypes.c_ulong()
                kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except (AttributeError, OSError, ValueError):
            return False
    return True


_USE_COLOR: bool = _color_supported()


def format_color(text: str, color: str) -> str:
    """Format text with ANSI color codes when terminal supports it.

    Automatically disabled when output is piped, redirected, or when
    the ``NO_COLOR`` environment variable is set.

    Args:
        text: The string to colorize.
        color: Color name (red, green, yellow, blue, magenta, cyan, bold, dim).

    Returns:
        Colorized string if terminal supports it, otherwise the original text.
    """
    if not _USE_COLOR:
        return text
    code = _ANSI_CODES.get(color, "")
    if not code:
        return text
    return f"{code}{text}{_ANSI_CODES['reset']}"


# GUI is imported conditionally right before use in main() for faster headless load.


def ensure_default_boilerplates() -> None:
    """Initialize default boilerplate templates if they don't exist."""
    if Cfg.BOILERPLATE_FILE and not Cfg.BOILERPLATE_FILE.exists():
        BP().export(Cfg.BOILERPLATE_FILE)
        LOG.i(f"Default boilerplate templates saved to {Cfg.BOILERPLATE_FILE}")


class STIGHelpFormatter(argparse.RawTextHelpFormatter):
    """Custom format for CLI help (#21)."""

    def format_help(self):
        help_text = super().format_help()
        if sys.stdout.isatty():
            help_text = help_text.replace("usage:", format_color("USAGE:", "yellow"))
            help_text = help_text.replace(
                "options:", format_color("OPTIONS:", "yellow")
            )

            # Colorize all argument groups
            groups = [
                "Create CKL from XCCDF:",
                "Merge Checklists:",
                "Compare Checklists:",
                "Extract Fixes:",
                "Apply Remediation Results:",
                "Evidence Management:",
                "History Management:",
                "Repair Checklist:",
                "Batch Processing:",
                "Integrity Verification:",
                "Compliance Statistics:",
                "Boilerplate Management:",
            ]
            for group in groups:
                help_text = help_text.replace(group, format_color(group, "green"))

            # Colorize epilog section
            help_text = help_text.replace(
                "COMMON USE-CASES (Windows Operations):",
                format_color("COMMON USE-CASES (Windows Operations):", "yellow"),
            )
            help_text = re.sub(
                r"(\d+\.\s+[^:]+:)",
                lambda m: format_color(m.group(1), "blue"),
                help_text,
            )
            help_text = help_text.replace(
                "stig-assessor", format_color("stig-assessor", "green")
            )
        return help_text


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main CLI entry point.

    Args:
        argv: Command-line arguments (None = sys.argv)

    Returns:
        Exit code (0 = success)
    """
    ensure_default_boilerplates()
    ok, err_list = Cfg.check()
    if not ok:
        for err in err_list:
            print(format_color(f"ERROR: {err}", "red"), file=sys.stderr)
        return 1

    state = GlobalState()
    epilog_text = """
COMMON USE-CASES (Windows Operations):

1. Creating a Checklist:
   stig-assessor --create --xccdf U_Windows_Server_2022_STIG_V3R1_Manual-xccdf.xml \\
                 --asset WEBSERVER01 --apply-boilerplate

2. Batch Operations:
   stig-assessor --batch-convert C:\\STIGs\\Downloads\\

3. Merging Checklists:
   stig-assessor --apply-results "C:\\Fixes\\Server_Results.json" \\
                 --checklist "C:\\Audits\\WEBSERVER01_Base.ckl"

4. Extracting Fixes:
   stig-assessor --extract U_Windows_10_V2R5_Manual-xccdf.xml --outdir .\\Fixes\\
"""

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{VERSION}",
        formatter_class=STIGHelpFormatter,
        epilog=epilog_text,
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument("--gui", action="store_true", help="Launch graphical interface")
    parser.add_argument(
        "--web", action="store_true", help="Launch native web interface"
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch interactive text user interface (CLI)",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Launch the guided interactive CLI wizard",
    )

    create_group = parser.add_argument_group("Create CKL from XCCDF")
    create_group.add_argument(
        "--create", action="store_true", help="Create CKL from XCCDF"
    )
    create_group.add_argument(
        "--create-cklb",
        action="store_true",
        help="Create CKLB (JSON) from XCCDF",
    )
    create_group.add_argument("--xccdf", help="XCCDF XML file")
    create_group.add_argument("--asset", help="Asset name")
    create_group.add_argument("--out", help="Output CKL path")
    create_group.add_argument("--ip", help="Asset IP")
    create_group.add_argument("--mac", help="Asset MAC")
    create_group.add_argument("--role", default="None", help="Asset role")
    create_group.add_argument("--marking", default="CUI", help="Asset marking")
    create_group.add_argument(
        "--apply-boilerplate",
        action="store_true",
        help="Apply boilerplate templates",
    )
    create_group.add_argument(
        "--dry-run", action="store_true", help="Dry run (no output written)"
    )

    convert_group = parser.add_argument_group("Format Conversion")
    convert_group.add_argument(
        "--convert-to-cklb", help="Convert an existing .ckl to .cklb"
    )
    convert_group.add_argument(
        "--convert-to-ckl", help="Convert an existing .cklb to .ckl"
    )

    batch_group = parser.add_argument_group("Batch Operations")
    batch_group.add_argument(
        "--batch-convert",
        metavar="DIR",
        help="Convert directory of XCCDFs to CKLs",
    )
    batch_group.add_argument(
        "--batch-out", help="Output directory for batch conversion"
    )
    batch_group.add_argument(
        "--batch-asset-prefix",
        default="ASSET",
        help="Asset name prefix for batch conversion",
    )
    batch_group.add_argument(
        "--batch-out-ext",
        choices=[".ckl", ".cklb"],
        default=".ckl",
        help="Output format for batch conversion (default: .ckl)",
    )

    merge_group = parser.add_argument_group("Merge Checklists")
    merge_group.add_argument(
        "--merge",
        action="store_true",
        help="Merge checklists preserving history",
    )
    merge_group.add_argument("--base", help="Base checklist")
    merge_group.add_argument(
        "--histories", nargs="+", help="Historical checklists to merge"
    )
    merge_group.add_argument("--merge-out", help="Merged output CKL")
    merge_group.add_argument(
        "--no-preserve-history",
        action="store_true",
        help="Disable history preservation",
    )
    merge_group.add_argument(
        "--no-boilerplate",
        action="store_true",
        help="Disable boilerplate application",
    )
    merge_group.add_argument(
        "--merge-dry-run",
        action="store_true",
        help="Dry run (no output written)",
    )
    merge_group.add_argument(
        "--merge-conflict",
        choices=["prefer_history", "prefer_base", "prefer_most_assessed"],
        default="prefer_history",
        help="Conflict resolution strategy",
    )
    merge_group.add_argument(
        "--merge-details-mode",
        choices=["overwrite", "prepend", "append", "keep_base", "keep_history"],
        default="keep_history",
        help="Mode for merging Finding Details",
    )
    merge_group.add_argument(
        "--merge-comments-mode",
        choices=["overwrite", "prepend", "append", "keep_base", "keep_history"],
        default="keep_history",
        help="Mode for merging Comments",
    )
    merge_group.add_argument(
        "--merge-status-mode",
        choices=["overwrite", "keep_base", "keep_history"],
        default="keep_history",
        help="Mode for merging Status",
    )
    merge_group.add_argument(
        "--merge-status-filter",
        nargs="+",
        help="Merge only specific statuses (e.g. Open NotAFinding)",
    )
    merge_group.add_argument(
        "--merge-severity-filter",
        nargs="+",
        help="Merge only specific severities (e.g. high medium)",
    )
    merge_group.add_argument(
        "--merge-vid-list",
        nargs="+",
        help="Merge only specific Vulnerability IDs (space separated)",
    )
    merge_group.add_argument(
        "--merge-vid-include",
        metavar="REGEX",
        help="Regex pattern: only merge matching VIDs",
    )
    merge_group.add_argument(
        "--merge-vid-exclude",
        metavar="REGEX",
        help="Regex pattern: skip matching VIDs",
    )

    waiver_group = parser.add_argument_group("Waiver Operations")
    waiver_group.add_argument(
        "--apply-waiver",
        help="Apply a waiver to a list of VIDs. Requires --checklist, --vids, --approver, --reason, and --until",
        action="store_true",
    )
    waiver_group.add_argument(
        "--vids",
        nargs="+",
        help="Space-separated list of vulnerability IDs (e.g. V-254440)",
    )
    waiver_group.add_argument(
        "--approver", help="Name or ID of the waiver approval authority"
    )
    waiver_group.add_argument("--reason", help="Justification/Reason for the waiver")
    waiver_group.add_argument(
        "--until", help="Expiration date for the waiver (YYYY-MM-DD)"
    )

    diff_group = parser.add_argument_group("Compare Checklists")
    diff_group.add_argument(
        "--diff",
        nargs=2,
        metavar=("CKL1", "CKL2"),
        help="Compare two checklists",
    )
    diff_group.add_argument(
        "--diff-format",
        choices=["summary", "detailed", "json", "html"],
        default="summary",
        help="Diff output format (default: summary)",
    )

    extract_group = parser.add_argument_group("Extract Fixes")
    extract_group.add_argument("--extract", help="XCCDF file to extract fixes from")
    extract_group.add_argument(
        "--extract-ckl",
        help="Optional checklist file (.ckl/.cklb) to filter fixes by assessment status",
    )
    extract_group.add_argument(
        "--status-filter",
        nargs="+",
        choices=["Open", "Not_Reviewed", "Not_Applicable", "NotAFinding", "All"],
        default=["Open", "Not_Reviewed"],
        help="Filter fixes by status found in --checklist (default: Open Not_Reviewed)",
    )
    extract_group.add_argument(
        "--extract-severity",
        nargs="+",
        choices=["high", "medium", "low"],
        help="Filter fixes by severity",
    )
    extract_group.add_argument(
        "--extract-vid-list",
        nargs="+",
        help="Extract fixes for only specific VIDs (space separated)",
    )
    extract_group.add_argument(
        "--extract-vid-include",
        metavar="REGEX",
        help="Regex pattern: only extract matching VIDs",
    )
    extract_group.add_argument(
        "--extract-vid-exclude",
        metavar="REGEX",
        help="Regex pattern: skip matching VIDs",
    )
    extract_group.add_argument("--outdir", help="Output directory for fixes")
    extract_group.add_argument(
        "--no-json", action="store_true", help="Do not export JSON"
    )
    extract_group.add_argument(
        "--no-csv", action="store_true", help="Do not export CSV"
    )
    extract_group.add_argument(
        "--no-bash", action="store_true", help="Do not export Bash script"
    )
    extract_group.add_argument(
        "--no-ps", action="store_true", help="Do not export PowerShell script"
    )
    extract_group.add_argument(
        "--no-ansible",
        action="store_true",
        help="Do not export Ansible playbook",
    )
    extract_group.add_argument(
        "--no-html",
        action="store_true",
        help="Do not export HTML playbook",
    )
    extract_group.add_argument(
        "--script-dry-run",
        action="store_true",
        help="Generate scripts in dry-run mode",
    )
    extract_group.add_argument(
        "--enable-rollbacks",
        action="store_true",
        help="Generate pre-flight registry backups (Win only)",
    )
    extract_group.add_argument(
        "--evidence",
        action="store_true",
        help="Generate automated evidence gathering scripts (Bash & PowerShell)",
    )

    result_group = parser.add_argument_group("Apply Remediation Results")
    result_group.add_argument(
        "--apply-results",
        nargs="+",
        metavar="JSON",
        help="One or more results JSON files to import",
    )
    result_group.add_argument("--checklist", help="Checklist to update")
    result_group.add_argument("--results-out", help="Updated checklist output path")
    result_group.add_argument(
        "--no-auto-status",
        action="store_true",
        help="Do not auto-mark successes as NotAFinding",
    )
    result_group.add_argument(
        "--results-dry-run",
        action="store_true",
        help="Dry run (no output written)",
    )
    result_group.add_argument(
        "--details-mode",
        choices=["prepend", "append", "overwrite"],
        default="prepend",
        help="Mode for injecting finding details (default: prepend)",
    )
    result_group.add_argument(
        "--comment-mode",
        choices=["prepend", "append", "overwrite"],
        default="prepend",
        help="Mode for injecting comments (default: prepend)",
    )

    evidence_group = parser.add_argument_group("Evidence Management")
    evidence_group.add_argument(
        "--import-evidence",
        nargs=2,
        metavar=("VID", "FILE"),
        help="Import evidence file",
    )
    evidence_group.add_argument("--evidence-desc", help="Evidence description")
    evidence_group.add_argument(
        "--evidence-cat", default="general", help="Evidence category"
    )
    evidence_group.add_argument(
        "--export-evidence", help="Export all evidence to directory"
    )
    evidence_group.add_argument(
        "--package-evidence", help="Create evidence ZIP package"
    )
    evidence_group.add_argument(
        "--import-evidence-package", help="Import evidence from package"
    )

    history_group = parser.add_argument_group("History Management")
    history_group.add_argument("--export-history", help="Export history JSON")
    history_group.add_argument("--import-history", help="Import history JSON")
    history_group.add_argument(
        "--track-ckl", help="Ingest a completed checklist into the SQLite DB"
    )
    history_group.add_argument(
        "--show-drift", help="Asset name to show compliance drift for"
    )

    bp_group = parser.add_argument_group("Boilerplate Management")
    bp_group.add_argument(
        "--bp-list", action="store_true", help="List all boilerplates"
    )
    bp_group.add_argument("--bp-list-vid", help="List boilerplates for a specific VID")
    bp_group.add_argument(
        "--bp-set", action="store_true", help="Set a boilerplate comment"
    )
    bp_group.add_argument(
        "--bp-delete", action="store_true", help="Delete a boilerplate comment"
    )
    bp_group.add_argument(
        "--bp-export",
        metavar="PATH",
        help="Export all boilerplates to a JSON file",
    )
    bp_group.add_argument(
        "--bp-import",
        metavar="PATH",
        help="Import boilerplates from a JSON file (merges with current)",
    )
    bp_group.add_argument(
        "--bp-reset",
        action="store_true",
        help="Reset all boilerplates to factory defaults",
    )
    bp_group.add_argument(
        "--bp-clone",
        nargs=2,
        metavar=("FROM_VID", "TO_VID"),
        help="Clone boilerplate templates from one VID to another",
    )
    bp_group.add_argument(
        "--bp-import-ckl",
        metavar="PATH",
        help="Import boilerplates directly from a CKL file",
    )
    bp_group.add_argument(
        "--bp-reset-vid",
        metavar="VID",
        help="Reset boilerplate for a specific VID to wildcard defaults",
    )
    bp_group.add_argument(
        "--bp-apply-ckl",
        metavar="PATH",
        help="Apply boilerplate templates to an existing checklist",
    )
    bp_group.add_argument(
        "--bp-apply-mode",
        choices=["overwrite_empty", "prepend", "append", "merge", "overwrite_all"],
        default="overwrite_empty",
        help="How to apply boilerplates (default: overwrite_empty)",
    )
    bp_group.add_argument(
        "--bp-out",
        metavar="PATH",
        help="Output path for boilerplate application (optional)",
    )
    bp_group.add_argument(
        "--bp-status-filter",
        nargs="+",
        help="Filter boilerplate application by finding status",
    )
    bp_group.add_argument(
        "--bp-severity-filter",
        nargs="+",
        help="Filter boilerplate application by finding severity",
    )
    bp_group.add_argument(
        "--bp-vid-list",
        nargs="+",
        help="Filter boilerplate application by specific VIDs (space separated)",
    )
    bp_group.add_argument(
        "--bp-date-override",
        metavar="YYYY-MM-DD",
        help="Override {date} variable in boilerplates",
    )
    bp_group.add_argument(
        "--bp-duplicates",
        action="store_true",
        help="Analyze templates to find duplicate findings across VIDs",
    )
    bp_group.add_argument("--vid", help="Vulnerability ID (e.g. V-12345)")
    bp_group.add_argument("--status", help="Finding Status (e.g. NotAFinding, Open)")
    bp_group.add_argument("--finding", help="Finding Details text for boilerplate")
    bp_group.add_argument("--comment", help="Comments text for boilerplate")

    profile_group = parser.add_argument_group("Profile Management")
    profile_group.add_argument(
        "--save-profile",
        metavar="NAME",
        help="Save current arguments as a named profile",
    )
    profile_group.add_argument(
        "--use-profile",
        metavar="NAME",
        help="Load arguments from a named profile",
    )
    profile_group.add_argument(
        "--export-configs",
        metavar="ZIP",
        help="Export all boilerplates, profiles, and plugins to a ZIP",
    )
    profile_group.add_argument(
        "--import-configs",
        metavar="ZIP",
        help="Import configs from a ZIP bundle",
    )

    parser.add_argument("--validate", help="Validate checklist compatibility")

    # New features for v7.2.0
    repair_group = parser.add_argument_group("Repair Checklist")
    repair_group.add_argument("--repair", help="Repair corrupted checklist")
    repair_group.add_argument("--repair-out", help="Repaired checklist output path")

    integrity_group = parser.add_argument_group("Integrity Verification")
    integrity_group.add_argument(
        "--verify-integrity", help="Verify checklist integrity with checksums"
    )
    integrity_group.add_argument(
        "--compute-checksum", help="Compute and display checksum for a file"
    )

    stats_group = parser.add_argument_group("Compliance Statistics")
    stats_group.add_argument(
        "--stats", help="Generate compliance statistics for checklist"
    )
    stats_group.add_argument(
        "--stats-format",
        choices=["text", "json", "csv", "html"],
        default="text",
        help="Statistics output format (default: text)",
    )
    stats_group.add_argument(
        "--stats-out", help="Output file for statistics (default: stdout)"
    )
    stats_group.add_argument(
        "--export-html",
        help="Generate a standalone HTML compliance report from a checklist",
    )
    stats_group.add_argument(
        "--fleet-stats",
        help="Generate aggregate fleet compliance statistics from a directory or ZIP of checklists",
    )

    # Productivity Enhancements
    prod_group = parser.add_argument_group("Productivity Enhancements")
    prod_group.add_argument(
        "--bulk-edit", help="Bulk edit vulnerabilities in checklist"
    )
    prod_group.add_argument("--bulk-out", help="Output path for bulk edited checklist")
    prod_group.add_argument(
        "--filter-severity",
        choices=["high", "medium", "low"],
        help="Filter bulk operations by severity",
    )
    prod_group.add_argument(
        "--filter-status",
        nargs="+",
        choices=["Open", "Not_Reviewed", "Not_Applicable", "NotAFinding"],
        help="Filter bulk operations by current status",
    )
    prod_group.add_argument("--filter-vid", help="Filter bulk operations by VID Regex")
    prod_group.add_argument("--apply-status", help="Status to apply to matching items")
    prod_group.add_argument(
        "--apply-comment", help="Comment to apply to matching items"
    )
    prod_group.add_argument(
        "--apply-finding", help="Finding Details to apply to matching items"
    )
    prod_group.add_argument(
        "--append-comment",
        action="store_true",
        help="Append comment instead of overwrite",
    )
    prod_group.add_argument(
        "--append-finding",
        action="store_true",
        help="Append finding instead of overwrite",
    )
    prod_group.add_argument(
        "--preview", action="store_true", help="Preview changes without executing them"
    )
    prod_group.add_argument(
        "--export-poam", help="Export Open/Not Reviewed findings to an eMASS POAM (CSV)"
    )

    args = parser.parse_args(argv)

    # ------------------------------------------------------------- Interactive Wizard
    if getattr(args, "interactive", False) or (argv is None and len(sys.argv) == 1):
        from stig_assessor.ui.wizard import launch_wizard

        launch_wizard()
        return 0

    # ------------------------------------------------------------- Profile Management
    if getattr(args, "use_profile", None):
        profile_path = Cfg.APP_DIR / "presets" / f"{args.use_profile}.json"
        if profile_path.exists():
            with open(profile_path, "r") as f:
                saved_args = json.load(f)
            # Inject saved arguments if current arguments aren't explicitly provided
            for k, v in saved_args.items():
                if getattr(args, k, None) in (None, False, "") and v:
                    setattr(args, k, v)
            LOG.i(f"Loaded assessment profile: {args.use_profile}")
        else:
            LOG.w(f"Profile '{args.use_profile}' not found in presets.")

    if getattr(args, "save_profile", None):
        profile_path = Cfg.APP_DIR / "presets" / f"{args.save_profile}.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        # Exclude internal state args
        save_dict = {
            k: v
            for k, v in vars(args).items()
            if v and k not in ("save_profile", "use_profile", "gui", "web", "verbose")
        }
        with open(profile_path, "w") as f:
            json.dump(save_dict, f, indent=2)
        LOG.i(f"Profile '{args.save_profile}' saved to {profile_path}")
        print(
            f"Profile '{args.save_profile}' saved. Use --use-profile '{args.save_profile}' to apply it later."
        )
        if len(sys.argv) <= 3:
            return (
                0  # Exit if they only invoked save-profile without other main actions
            )

    if getattr(args, "export_configs", None):

        out_zip = Path(args.export_configs)
        LOG.i(f"Exporting configurations to {out_zip}...")
        with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for subdir in ["presets", "boilerplates", "plugins"]:
                d = Cfg.APP_DIR / subdir
                if d.exists():
                    for f in d.rglob("*"):
                        if f.is_file():
                            zf.write(f, arcname=f"{subdir}/{f.name}")
        LOG.i("Export complete.")
        return 0

    if getattr(args, "import_configs", None):

        in_zip = Path(args.import_configs)
        if not in_zip.exists():
            parser.error(f"Bundle file not found: {in_zip}")
        LOG.i(f"Importing configurations from {in_zip}...")
        with zipfile.ZipFile(in_zip, "r") as zf:
            # Prevent arbitrary extraction
            for member in zf.namelist():
                if (
                    member.startswith(("presets/", "boilerplates/", "plugins/"))
                    and ".." not in member
                ):
                    dest = Cfg.APP_DIR / member
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)
        LOG.i("Import complete.")
        return 0

    if args.verbose:
        LOG.log.setLevel(logging.DEBUG)

    try:
        if args.gui:
            if not Deps.HAS_TKINTER:
                print(
                    "ERROR: tkinter not available. Install python3-tk.",
                    file=sys.stderr,
                )
                return 1
            from stig_assessor.ui.gui.core import GUI

            gui = GUI()
            gui.run()
            return 0

        if args.web:
            import webbrowser

            from stig_assessor.ui.web import start_server

            # Open browser slightly after server starts
            def open_browser():
                import builtins

                time.sleep(1.0)
                port = getattr(builtins, "_stig_web_port", 8080)
                webbrowser.open(f"http://127.0.0.1:{port}/")

            threading.Thread(target=open_browser, daemon=True).start()
            start_server(port=8080)
            return 0

        if args.tui:
            try:
                from stig_assessor.ui.tui import start_tui

                start_tui()
                return 0
            except ImportError:
                print(
                    "ERROR: Curses environment is incomplete or unsupported on this OS. Please use --gui or --web instead.",
                    file=sys.stderr,
                )
                return 1

        proc = Proc()

        if getattr(args, "apply_waiver", False):
            if not all(
                [
                    args.checklist,
                    args.vids,
                    args.approver,
                    args.reason,
                    getattr(args, "until", None),
                ]
            ):
                parser.error(
                    "--apply-waiver requires --checklist, --vids, --approver, --reason, and --until"
                )
            out_file = args.results_out or args.checklist
            LOG.i(f"Applying waivers to {args.checklist} for VIDs: {args.vids}")
            res = proc.apply_waivers(
                args.checklist,
                out_file,
                args.vids,
                args.approver,
                args.reason,
                getattr(args, "until"),
            )
            print(
                f"Waivers applied directly to {res['updates']} findings. Output saved to {out_file}"
            )
            return 0

        if args.convert_to_cklb:
            ckl_path = Path(args.convert_to_cklb)
            cklb_out = ckl_path.with_suffix(".cklb")
            print(f"Converting {ckl_path.name} to {cklb_out.name}...")
            # Load as json dict, which validates and parses it
            # wait, proc._json_to_checklist works the other way.
            # I can just load the XML, and convert to JSON and write.
            # The most straightforward way is using FO methods.
            tree = FO.parse_xml(ckl_path)
            cklb_data = proc._checklist_to_json(tree.getroot())
            FO.write_cklb(cklb_data, cklb_out)
            print("Done.")
            return 0

        if args.convert_to_ckl:
            cklb_path = Path(args.convert_to_ckl)
            ckl_out = cklb_path.with_suffix(".ckl")
            print(f"Converting {cklb_path.name} to {ckl_out.name}...")
            cklb_data = FO.parse_cklb(cklb_path)
            tree = proc._json_to_checklist(cklb_data)
            from stig_assessor.xml.utils import XmlUtils

            XmlUtils.indent_xml(tree.getroot())
            tree.write(ckl_out, encoding="utf-8", xml_declaration=True)
            print("Done.")
            return 0

        if args.fleet_stats:
            from stig_assessor.processor.fleet_stats import FleetStats

            fs = FleetStats()
            fs_path = Path(args.fleet_stats)
            if fs_path.is_dir():
                result = fs.process_directory(fs_path)
            elif zipfile.is_zipfile(fs_path):
                result = fs.process_zip(fs_path)
            else:
                parser.error("Fleet stats requires a directory or a valid ZIP file.")
            print(
                format_color(json.dumps(result, indent=2, ensure_ascii=False), "green")
            )
            return 0

        if args.batch_convert:
            batch_dir = Path(args.batch_convert)
            if not batch_dir.is_dir():
                parser.error(
                    f"--batch-convert requires a valid directory, got: {batch_dir}"
                )
            xccdfs = list(batch_dir.glob("*.xml"))
            if not xccdfs:
                LOG.w(f"No XML files found in {batch_dir}")
                return 0

            from concurrent.futures import ThreadPoolExecutor

            def process_xccdf(xccdf_path):
                out_path = xccdf_path.with_suffix(args.batch_out_ext)
                try:
                    proc.xccdf_to_ckl(
                        xccdf=str(xccdf_path),
                        out=str(out_path),
                        asset=xccdf_path.stem.split("-")[0][
                            :15
                        ],  # Default naive asset name
                        apply_boilerplate=args.apply_boilerplate,
                    )
                    return True, xccdf_path.name
                except (ParseError, ValidationError, OSError, ValueError) as e:
                    return False, f"{xccdf_path.name}: {e}"

            print(f"Batch converting {len(xccdfs)} XCCDFs to {args.batch_out_ext}...")
            success, errors = 0, []
            with ThreadPoolExecutor() as exe:
                for ok, msg in exe.map(process_xccdf, xccdfs):
                    if ok:
                        success += 1
                    else:
                        errors.append(msg)
            print(f"Batch complete. {success}/{len(xccdfs)} converted.")
            if errors:
                print("Errors:")
                for e in errors:
                    print(f" - {e}")
            return 0

        if args.create or args.create_cklb:
            if not args.xccdf:
                args.xccdf = prompt_missing("Please enter the path to the XCCDF file")
            if not args.asset:
                args.asset = prompt_missing("Please enter the Asset name")

            if not (args.xccdf and args.asset):
                parser.error("--create requires at least --xccdf and --asset")

            out_path = args.out
            ext = ".cklb" if args.create_cklb else ".ckl"
            if not out_path:
                xccdf_path = Path(args.xccdf)
                out_path = str(
                    xccdf_path.with_name(f"{args.asset}_{xccdf_path.stem}{ext}")
                )
                LOG.i(f"Auto-resolved output path: {out_path}")
            else:
                out_path = str(Path(out_path).with_suffix(ext))

            with Spinner("Converting XCCDF to CKL..."):
                result = proc.xccdf_to_ckl(
                    args.xccdf,
                    out_path,
                    args.asset,
                    ip=args.ip or "",
                    mac=args.mac or "",
                    role=args.role,
                    marking=args.marking,
                    dry=args.dry_run,
                    apply_boilerplate=args.apply_boilerplate,
                )
            print(
                format_color(json.dumps(result, indent=2, ensure_ascii=False), "green")
            )
            return 0

        if getattr(args, "merge", False):
            if not getattr(args, "base", None):
                args.base = prompt_missing(
                    "Please enter the path to the base checklist"
                )
            if not args.histories:
                hist = prompt_missing(
                    "Please enter historical checklists (space-separated)"
                )
                args.histories = [h for h in hist.split()] if hist else None

            if not (args.base and args.histories):
                parser.error("--merge requires at least --base and --histories")

            merge_out = args.merge_out
            if not merge_out:
                base_path = Path(args.base)
                merge_out = str(base_path.with_name(f"{base_path.stem}_merged.ckl"))
                LOG.i(f"Auto-resolved merge output path: {merge_out}")

            with Spinner("Merging checklists..."):
                result = proc.merge_advanced(
                    args.base,
                    args.histories,
                    merge_out,
                    preserve_history=not args.no_preserve_history,
                    apply_boilerplate=not args.no_boilerplate,
                    dry=args.merge_dry_run,
                    conflict_resolution=args.merge_conflict,
                    details_mode=args.merge_details_mode,
                    comments_mode=args.merge_comments_mode,
                    status_mode=args.merge_status_mode,
                    status_filter=args.merge_status_filter,
                    severity_filter=args.merge_severity_filter,
                    vid_list=args.merge_vid_list,
                    vid_include=args.merge_vid_include,
                    vid_exclude=args.merge_vid_exclude,
                )
            print(
                format_color(json.dumps(result, indent=2, ensure_ascii=False), "green")
            )
            return 0

        if getattr(args, "diff", None):
            ckl1, ckl2 = args.diff
            result = proc.diff(ckl1, ckl2, output_format=args.diff_format)
            if args.diff_format == "json":
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif args.diff_format == "html":
                from stig_assessor.processor.html_diff import \
                    generate_html_diff

                out_html = Path(ckl1).with_name(f"{Path(ckl1).stem}_diff.html")
                generate_html_diff(ckl1, ckl2, str(out_html))
                print(format_color(f"HTML Diff Report generated: {out_html}", "green"))
            else:
                print(result.get("formatted_text", ""))
            return 0

        if getattr(args, "extract", None):
            extract_outdir = args.outdir
            if not extract_outdir:
                extract_path = Path(args.extract)
                extract_outdir = str(
                    extract_path.with_name(f"{extract_path.stem}_fixes")
                )
                LOG.i(f"Auto-resolved output directory: {extract_outdir}")

            with Spinner("Extracting fixes..."):
                extractor = FixExt(args.extract, checklist=args.extract_ckl)

                # Handle 'All' status filter
                status_filter = args.status_filter
                if status_filter and "All" in status_filter:
                    status_filter = None

                extractor.extract(
                    status_filter=status_filter,
                    severity_filter=args.extract_severity,
                    vid_list=args.extract_vid_list,
                    vid_include=args.extract_vid_include,
                    vid_exclude=args.extract_vid_exclude,
                )

                if args.extract_severity:
                    extractor.fixes = [
                        f
                        for f in extractor.fixes
                        if f.severity.lower() in args.extract_severity
                    ]

                outdir = Path(extract_outdir)
                outdir.mkdir(parents=True, exist_ok=True, mode=0o700)

                if not args.no_json:
                    extractor.to_json(outdir / "fixes.json")
                if not args.no_csv:
                    extractor.to_csv(outdir / "fixes.csv")
                if not args.no_bash:
                    extractor.to_bash(
                        outdir / "remediate.sh", dry_run=args.script_dry_run
                    )
                if not args.no_ps:
                    extractor.to_powershell(
                        outdir / "Remediate.ps1",
                        dry_run=args.script_dry_run,
                        enable_rollbacks=args.enable_rollbacks,
                    )
                if getattr(args, "evidence", False):
                    extractor.to_evidence_bash(outdir / "gather_evidence.sh")
                    extractor.to_evidence_powershell(outdir / "GatherEvidence.ps1")
                if not args.no_ansible:
                    extractor.to_ansible(
                        outdir / "remediate.yml", dry_run=args.script_dry_run
                    )
                if not getattr(args, "no_html", False):
                    try:
                        from stig_assessor.remediation.html_playbook import \
                            generate_html_playbook

                        generate_html_playbook(
                            extractor, outdir / "remediation_playbook.html"
                        )
                    except (ImportError, OSError, ValueError, RuntimeError) as e:
                        LOG.w(f"Could not generate HTML playbook: {e}")

            print(
                format_color(
                    json.dumps(extractor.stats_summary(), indent=2, ensure_ascii=False),
                    "green",
                )
            )
            return 0

        if args.apply_results:
            if not args.checklist:
                args.checklist = prompt_missing(
                    "Please enter the path to the target checklist"
                )

            if not args.checklist:
                parser.error("--apply-results requires --checklist")

            results_out = args.results_out
            if not results_out:
                checklist_path = Path(args.checklist)
                results_out = str(
                    checklist_path.with_name(f"{checklist_path.stem}_updated.ckl")
                )
                LOG.i(f"Auto-resolved results output path: {results_out}")

            # ═══ ENHANCED: Support multiple result files ═══
            result_files = (
                args.apply_results
                if isinstance(args.apply_results, list)
                else [args.apply_results]
            )

            processor = FixResPro()
            total_loaded = 0
            total_skipped = 0
            failed_files = []

            print(
                format_color(
                    f"[INFO] Processing {len(result_files)} result file(s)...",
                    "blue",
                ),
                file=sys.stderr,
            )

            for idx, result_file in enumerate(result_files, 1):
                try:
                    print(
                        format_color(
                            f"[{idx}/{len(result_files)}] Loading {Path(result_file).name}...",
                            "blue",
                        ),
                        file=sys.stderr,
                    )
                    imported, skipped = processor.load(result_file)
                    total_loaded += imported
                    total_skipped += skipped
                    print(
                        format_color(
                            f"  ✓ Loaded {imported} results (skipped {skipped})",
                            "green",
                        ),
                        file=sys.stderr,
                    )
                except (
                    OSError,
                    ValueError,
                    json.JSONDecodeError,
                    KeyError,
                ) as exc:
                    print(
                        format_color(f"  ✘ Failed: {exc}", "red"),
                        file=sys.stderr,
                    )
                    failed_files.append({"file": str(result_file), "error": str(exc)})
                    continue

            if not processor.results:
                print(
                    format_color(
                        "[ERROR] No valid results loaded from any file", "red"
                    ),
                    file=sys.stderr,
                )
                return 1

            print(
                format_color(
                    f"\n[INFO] Applying {len(processor.results)} unique results to checklist...",
                    "blue",
                ),
                file=sys.stderr,
            )

            # Apply to checklist
            with Spinner("Applying remediations to checklist..."):
                result = processor.update_ckl(
                    args.checklist,
                    results_out,
                    auto_status=not args.no_auto_status,
                    dry=args.results_dry_run,
                    details_mode=args.details_mode,
                    comment_mode=args.comment_mode,
                )

            # Add batch statistics
            result["batch_stats"] = {
                "files_total": len(result_files),
                "files_failed": len(failed_files),
                "results_loaded": total_loaded,
                "results_skipped": total_skipped,
                "unique_vulns": len(processor.results),
            }

            if failed_files:
                result["failed_files"] = failed_files

            if len(failed_files) == 0:
                print(
                    format_color(
                        json.dumps(result, indent=2, ensure_ascii=False),
                        "green",
                    )
                )
            else:
                print(
                    format_color(
                        json.dumps(result, indent=2, ensure_ascii=False),
                        "yellow",
                    )
                )
            return (
                0 if len(failed_files) == 0 else 2
            )  # Exit code 2 if some files failed

        evidence_mgr = EvidenceMgr()

        if args.import_evidence:
            vid, path = args.import_evidence
            dest = evidence_mgr.import_file(
                vid,
                path,
                description=args.evidence_desc or "",
                category=args.evidence_cat or "general",
            )
            print(f"Evidence imported: {dest}")
            return 0

        if args.export_evidence:
            count = evidence_mgr.export_all(args.export_evidence)
            print(f"Exported {count} evidence files to {args.export_evidence}")
            return 0

        if args.package_evidence:
            archive = evidence_mgr.package(args.package_evidence)
            print(f"Evidence package created: {archive}")
            return 0

        if args.import_evidence_package:
            count = evidence_mgr.import_package(args.import_evidence_package)
            print(f"Imported {count} evidence files from package")
            return 0

        if args.export_history:
            proc.history.export(args.export_history)
            print(f"History exported to {args.export_history}")
            return 0

        if args.import_history:
            count = proc.history.imp(args.import_history)
            print(f"Imported {count} history entries")
            return 0

        if args.track_ckl:
            if not proc.history.db:
                print(
                    format_color("ERROR: SQLite History DB is not initialized.", "red"),
                    file=sys.stderr,
                )
                return 1
            # Simple ingest by extracting vulns
            try:
                tree = proc._load_file_as_xml(Path(args.track_ckl))
                root = tree.getroot()
                vulns = proc._extract_vuln_data(root)
                asset_elem = root.find(".//HOST_NAME")
                asset_name = asset_elem.text if asset_elem is not None else "Unknown"

                results = []
                for vid, vdata in vulns.items():
                    results.append(
                        {
                            "vid": vid,
                            "status": vdata.get("status", "Not_Reviewed"),
                            "severity": vdata.get("severity", "medium"),
                            "find": vdata.get("finding_details", ""),
                            "comm": vdata.get("comments", ""),
                        }
                    )

                db_id = proc.history.db.save_assessment(
                    asset_name, args.track_ckl, "STIG", results
                )
                print(
                    format_color(
                        f"Successfully ingested {len(results)} findings into database (Assessment ID: {db_id})",
                        "green",
                    )
                )
            except (ParseError, ValidationError, OSError, ValueError) as e:
                print(
                    format_color(f"Failed to ingest CKL: {e}", "red"),
                    file=sys.stderr,
                )
                return 1
            return 0

        if args.show_drift:
            if not proc.history.db:
                print(
                    format_color("ERROR: SQLite History DB is not initialized.", "red"),
                    file=sys.stderr,
                )
                return 1
            asset_name = args.show_drift
            # We need the current assessment id, let's just get the latest one
            with proc.history.db._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM assessments WHERE asset_name = ? ORDER BY timestamp DESC LIMIT 1",
                    (asset_name,),
                )
                row = cursor.fetchone()
                if not row:
                    print(
                        format_color(
                            f"No assessments found for asset '{asset_name}'",
                            "yellow",
                        )
                    )
                    return 1
                latest_id = row[0]

            drift = proc.history.db.get_drift(asset_name, latest_id)
            if "error" in drift:
                print(format_color(drift["error"], "yellow"))
            else:
                print(
                    format_color(f"=== Compliance Drift for {asset_name} ===", "blue")
                )
                print(f"Fixed (Open -> NotAFinding): {len(drift['fixed'])}")
                print(
                    f"Regressed (NotAFinding -> Open): {format_color(str(len(drift['regressed'])), 'red')}"
                )
                print(f"Changed: {len(drift['changed'])}")
                print(f"New Rules: {len(drift['new'])}")
                print(f"Removed Rules: {len(drift['removed'])}")
                print(f"Unchanged: {len(drift['unchanged'])}")
            return 0

        if args.bp_list:
            bp_all = proc.boiler.list_all()
            print(json.dumps(bp_all, indent=2, ensure_ascii=False))
            return 0

        if args.bp_list_vid:
            bp_all = proc.boiler.list_all()
            res = bp_all.get(args.bp_list_vid, {})
            print(json.dumps({args.bp_list_vid: res}, indent=2, ensure_ascii=False))
            return 0

        if args.bp_set:
            if not args.vid or not args.status:
                parser.error("--bp-set requires --vid and --status")
            proc.boiler.set(
                args.vid, args.status, args.finding or "", args.comment or ""
            )
            print(
                format_color(f"Boilerplate set for {args.vid} / {args.status}", "green")
            )
            return 0

        if args.bp_delete:
            if not args.vid:
                parser.error("--bp-delete requires at least --vid")
            deleted = proc.boiler.delete(args.vid, args.status)
            if deleted:
                print(
                    format_color(
                        f"Deleted boilerplate {'for ' + args.status if args.status else 'all statuses'} on {args.vid}",
                        "green",
                    )
                )
            else:
                print(format_color("Boilerplate not found", "yellow"))
            return 0

        if args.bp_export:
            proc.boiler.export(args.bp_export)
            print(format_color(f"Boilerplates exported to {args.bp_export}", "green"))
            return 0

        if args.bp_import:
            proc.boiler.imp(args.bp_import)
            print(format_color(f"Boilerplates imported from {args.bp_import}", "green"))
            return 0

        if args.bp_reset:
            proc.boiler.reset_all()
            print(format_color("Boilerplates reset to factory defaults", "green"))
            return 0

        if args.bp_reset_vid:
            if proc.boiler.reset_vid(args.bp_reset_vid):
                print(
                    format_color(
                        f"Reset {args.bp_reset_vid} to wildcard defaults", "green"
                    )
                )
            else:
                print(
                    format_color(
                        f"No custom templates found for {args.bp_reset_vid}", "yellow"
                    )
                )
            return 0

        if args.bp_import_ckl:
            result = proc.boiler.import_from_checklist(args.bp_import_ckl)
            print(
                format_color(
                    f"Imported {result['imported']} boilerplates from {args.bp_import_ckl} (Skipped: {result['skipped']})",
                    "green",
                )
            )
            return 0

        if args.bp_apply_ckl:
            out_path = (
                args.bp_out
                if getattr(args, "bp_out", None)
                else Path(args.bp_apply_ckl).with_name(
                    f"{Path(args.bp_apply_ckl).stem}_bp.ckl"
                )
            )
            result = proc.apply_boilerplates(
                args.bp_apply_ckl,
                str(out_path),
                apply_mode=args.bp_apply_mode,
                status_filter=getattr(args, "bp_status_filter", None),
                severity_filter=getattr(args, "bp_severity_filter", None),
                vid_list=getattr(args, "bp_vid_list", None),
                date_override=getattr(args, "bp_date_override", None),
            )
            print(
                format_color(
                    f"Applied boilerplates to {result['updated']} findings. Saved to {out_path}",
                    "green",
                )
            )
            return 0

        if getattr(args, "bp_duplicates", False):
            dups = proc.boiler.find_duplicates()
            if not dups:
                print(format_color("No duplicate templates found.", "green"))
                return 0

            print(format_color(f"Found {len(dups)} duplicate text entries:", "yellow"))
            for duplicate in dups:
                print(
                    f"[{duplicate['status']}] {duplicate['field']} (used in {duplicate['count']} VIDs):"
                )
                print(
                    f"   Sample VIDs: {', '.join(duplicate['vids'][:5])}{'...' if duplicate['count'] > 5 else ''}"
                )
                print(f"   Text: {duplicate['text_preview']}\n")
            return 0

        if args.bp_clone:
            vid_from, vid_to = args.bp_clone
            ok = proc.boiler.clone(vid_from, vid_to)
            if ok:
                print(
                    format_color(
                        f"Cloned boilerplates from {vid_from} → {vid_to}",
                        "green",
                    )
                )
            else:
                print(format_color(f"Source VID {vid_from} not found", "yellow"))
            return 0

        if args.validate:
            ok, errors, warnings_, info = proc.validator.validate(args.validate)
            print(
                json.dumps(
                    {
                        "ok": ok,
                        "errors": errors,
                        "warnings": warnings_,
                        "info": info,
                    },
                    indent=2,
                )
            )
            return 0 if ok else 1

        # New features for v7.2.0
        if args.repair:
            repair_out = args.repair_out
            if not repair_out:
                repair_path = Path(args.repair)
                repair_out = str(
                    repair_path.with_name(f"{repair_path.stem}_repaired.ckl")
                )
                LOG.i(f"Auto-resolved repair output path: {repair_out}")

            with Spinner("Repairing checklist..."):
                result = proc.repair(args.repair, repair_out)

            print(
                format_color(json.dumps(result, indent=2, ensure_ascii=False), "green")
            )
            return 0

        if args.verify_integrity:
            result = proc.verify_integrity(args.verify_integrity)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result["valid"] else 1

        if args.compute_checksum:
            checksum = proc.compute_checksum(args.compute_checksum)
            print(f"{checksum}  {args.compute_checksum}")
            return 0

        if args.stats:
            result = proc.generate_stats(args.stats, output_format=args.stats_format)
            if args.stats_out:
                output_path = Path(args.stats_out)
                output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with open(output_path, "w", encoding="utf-8") as f:
                    if args.stats_format == "json":
                        json.dump(result, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(
                            result
                            if isinstance(result, str)
                            else json.dumps(result, indent=2)
                        )
                print(f"Statistics written to {output_path}")
            else:
                if args.stats_format == "json":
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                else:
                    print(result)
            return 0

        # Productivity Features
        if getattr(args, "bulk_edit", None):
            if not getattr(args, "apply_status", None) and not args.preview:
                parser.error(
                    "--bulk-edit requires --apply-status unless --preview is used"
                )
            out = args.bulk_out or str(
                Path(args.bulk_edit).with_name(
                    f"{Path(args.bulk_edit).stem}_updated.ckl"
                )
            )
            result = proc.bulk_edit(
                args.bulk_edit,
                out,
                severity=getattr(args, "filter_severity", None),
                regex_vid=getattr(args, "filter_vid", None),
                status_filter=getattr(args, "filter_status", None),
                new_status=getattr(args, "apply_status", "") or "",
                new_comment=getattr(args, "apply_comment", "") or "",
                new_finding=getattr(args, "apply_finding", "") or "",
                append_comment=getattr(args, "append_comment", False),
                append_finding=getattr(args, "append_finding", False),
                preview=args.preview,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.export_poam:
            poam_str = proc.export_poam(args.export_poam)
            poam_out = Path(args.export_poam).with_name(
                f"{Path(args.export_poam).stem}_poam.csv"
            )
            with open(poam_out, "w", encoding="utf-8") as f:
                f.write(poam_str)
            print(f"eMASS POAM exported successfully to {poam_out}")
            return 0

        if args.export_html:
            from stig_assessor.processor.html_report import \
                generate_html_report

            ckl_input = Path(args.export_html)
            html_out = ckl_input.with_suffix(".html")
            with Spinner(f"Generating HTML report from {ckl_input.name}..."):
                result_path = generate_html_report(ckl_input, html_out)
            print(
                format_color(
                    f"HTML compliance report generated: {result_path}", "green"
                )
            )
            return 0

        parser.print_help()
        return 0

    except KeyboardInterrupt:
        print(
            format_color("\nOperation cancelled by user", "yellow"),
            file=sys.stderr,
        )
        return 130
    except OSError as exc:
        LOG.e(f"Fatal error (OS/IO): {exc}", exc=True)
        print(format_color(f"ERROR: OS/IO {exc}", "red"), file=sys.stderr)
        return 1
    except ValueError as exc:
        LOG.e(f"Fatal error (Value): {exc}", exc=True)
        print(format_color(f"ERROR: Value {exc}", "red"), file=sys.stderr)
        return 1
    finally:
        state.cleanup()
        gc.collect()


if __name__ == "__main__":
    sys.exit(main())
