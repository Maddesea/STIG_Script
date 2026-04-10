"""Interactive CLI Wizard for STIG Assessor.

Provides a guided, menu-driven CLI experience with full feature parity
to the headless TUI and scripted CLI. Designed for operators who prefer
step-by-step prompts over memorizing argument flags.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import APP_NAME, VERSION
from stig_assessor.exceptions import FileError, ParseError, ValidationError
from stig_assessor.processor.processor import Proc


# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOR (standalone — no dependency on cli.py)
# ─────────────────────────────────────────────────────────────────────────────

_ANSI = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}

_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, color: str) -> str:
    """Colorize text when terminal supports it."""
    if not _USE_COLOR:
        return text
    return f"{_ANSI.get(color, '')}{text}{_ANSI['reset']}"


# ─────────────────────────────────────────────────────────────────────────────
# WIZARD
# ─────────────────────────────────────────────────────────────────────────────

class InteractiveWizard:
    """Full-featured interactive CLI wizard."""

    def __init__(self):
        self.proc = Proc()
        self.running = True

    # ── Screen helpers ───────────────────────────────────────────────────────

    def _clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def _header(self, subtitle: str = ""):
        self._clear()
        print(_c("=" * 64, "blue"))
        print(_c(f"  {APP_NAME} - INTERACTIVE WIZARD  v{VERSION}", "cyan"))
        if subtitle:
            print(_c(f"  {subtitle}", "dim"))
        print(_c("=" * 64, "blue"))
        print()

    def _pause(self):
        print()
        input(_c("  Press Enter to return to menu…", "dim"))

    def _success(self, msg: str):
        print(_c(f"\n  [v] {msg}", "green"))

    def _error(self, msg: str):
        print(_c(f"\n  [x] {msg}", "red"))

    # ── Prompts ──────────────────────────────────────────────────────────────

    def _prompt(self, message: str, required: bool = True, validate_file: bool = False, validate_dir: bool = False) -> str:
        """Prompt with optional path validation."""
        while True:
            val = input(_c(f"  ? {message}: ", "yellow")).strip()
            if not val and required:
                print(_c("    This field is required.", "red"))
                continue
            if not val:
                return val
            if validate_file and not os.path.isfile(val):
                print(_c(f"    File not found: {val}", "red"))
                continue
            if validate_dir and not os.path.isdir(val):
                print(_c(f"    Directory not found: {val}", "red"))
                continue
            return val

    def _prompt_yn(self, message: str, default: bool = False) -> bool:
        """Yes/No prompt."""
        hint = "(Y/n)" if default else "(y/N)"
        val = input(_c(f"  ? {message} {hint}: ", "yellow")).strip().lower()
        if not val:
            return default
        return val.startswith("y")

    def _prompt_choice(self, message: str, choices: List[str]) -> str:
        """Prompt with constrained choices."""
        hint = "/".join(choices)
        while True:
            val = input(_c(f"  ? {message} [{hint}]: ", "yellow")).strip()
            if val in choices:
                return val
            print(_c(f"    Please choose one of: {hint}", "red"))

    # ── Menu engine ──────────────────────────────────────────────────────────

    def _menu(self, title: str, options: List[Tuple[str, Callable]]) -> None:
        self._header(title)

        for idx, (label, _) in enumerate(options, 1):
            num = _c(f"{idx:2d}", "cyan")
            print(f"  {num}. {label}")

        print(f"  {_c(' 0', 'cyan')}. {'Exit' if title == 'Main Menu' else 'Back'}")
        print(_c("  " + "-" * 60, "dim"))

        while True:
            choice = input(_c("  Select: ", "yellow")).strip()
            if choice == "0":
                self.running = False
                return
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    options[idx][1]()
                    return
                print(_c("    Invalid selection.", "red"))
            except ValueError:
                print(_c("    Please enter a number.", "red"))

    # ════════════════════════════════════════════════════════════════════════
    # ACTIONS
    # ════════════════════════════════════════════════════════════════════════

    def build_checklist(self):
        """Convert XCCDF benchmark to CKL checklist."""
        self._header("Build Checklist from XCCDF")

        xccdf = self._prompt("Path to DISA XCCDF XML", validate_file=True)
        asset = self._prompt("Target Asset Name")
        out_dir = self._prompt("Output Directory (Enter for current)", required=False)
        apply_bp = self._prompt_yn("Apply boilerplate templates?")

        out_dir = out_dir or "."
        out_file = str(Path(out_dir) / f"{asset}_output.ckl")

        print(_c(f"\n  Generating {out_file}…", "cyan"))
        try:
            res = self.proc.xccdf_to_ckl(xccdf, out_file, asset=asset, apply_boilerplate=apply_bp)
            self._success(f"Processed {res.get('processed', 0)} rules → {out_file}")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def merge_checklists(self):
        """Merge multiple CKLs with history preservation."""
        self._header("Merge Checklists")

        base = self._prompt("Path to Base CKL/CKLB", validate_file=True)
        hists_str = self._prompt("Paths to History CKLs (comma-separated)")
        hists = [h.strip() for h in hists_str.split(",") if h.strip()]
        out_file = self._prompt("Output merged file path")

        print(_c(f"\n  Merging {len(hists)} history files…", "cyan"))
        try:
            res = self.proc.merge(base, hists, out_file)
            self._success(f"Updated {res.get('updated', 0)} findings → {out_file}")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def extract_playbooks(self):
        """Extract remediation scripts from XCCDF."""
        self._header("Extract Remediation Playbooks")

        xccdf = self._prompt("Path to DISA XCCDF XML", validate_file=True)
        checklist = self._prompt("Path to Checklist (for filtering, optional)", required=False, validate_file=True)
        
        print(_c("\n  Pick Statuses to Include:", "bold"))
        print("    1. Open + Not_Reviewed (Recommended)")
        print("    2. Everything (All Statuses)")
        print("    3. Custom Status List")
        choice = input(_c("  Select: ", "yellow")).strip()
        
        status_filter = ["Open", "Not_Reviewed"]
        if choice == "2":
            status_filter = ["All"]
        elif choice == "3":
            status_filter = [s.strip() for s in self._prompt("Enter statuses (comma-sep, e.g. Open,NotAFinding)").split(",")]

        platform = self._prompt_choice("Target Platform", ["windows", "linux", "both"])
        out_dir = self._prompt("Output Directory")

        print(_c(f"\n  Extracting scripts to {out_dir}…", "cyan"))
        try:
            os.makedirs(out_dir, exist_ok=True)
            from stig_assessor.remediation.extractor import FixExt

            extractor = FixExt(xccdf, checklist=checklist if checklist else None)
            extractor.extract(status_filter=None if "All" in status_filter else status_filter)
            
            extractor.to_json(os.path.join(out_dir, "fixes.json"))
            extractor.to_csv(os.path.join(out_dir, "fixes.csv"))
            
            if platform in ("linux", "both"):
                extractor.to_bash(os.path.join(out_dir, "remediate.sh"))
                extractor.to_ansible(os.path.join(out_dir, "remediate.yml"))
            
            if platform in ("windows", "both"):
                extractor.to_powershell(os.path.join(out_dir, "Remediate.ps1"), enable_rollbacks=True)

            try:
                from stig_assessor.remediation.html_playbook import generate_html_playbook
                generate_html_playbook(extractor, os.path.join(out_dir, "remediation_playbook.html"))
            except (ImportError, OSError, ValueError):
                pass

            self._success(f"Playbooks generated in {out_dir}")
            print(_c(f"  Note: Evidence logs will be mapped to 'evidence/' directory when scripts run.", "dim"))
        except (ParseError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def compare_checklists(self):
        """Compare two checklists and show differences."""
        self._header("Compare Checklists (Diff)")

        ckl1 = self._prompt("Path to Baseline CKL (Before)", validate_file=True)
        ckl2 = self._prompt("Path to Target CKL (After)", validate_file=True)

        print(_c("\n  Comparing checklists…", "cyan"))
        try:
            res = self.proc.diff(ckl1, ckl2)
            changes = res.get("changed", [])
            summary = res.get("summary", {})
            self._success(f"Differences found: {len(changes)}")
            print(f"    Baseline: {summary.get('total_in_baseline', '?')} | Comparison: {summary.get('total_in_comparison', '?')}")
            print(f"    Changed: {summary.get('changed', 0)} | Unchanged: {summary.get('unchanged', 0)}")
            print(f"    Only in baseline: {summary.get('only_in_baseline', 0)} | Only in comparison: {summary.get('only_in_comparison', 0)}")

            try:
                from stig_assessor.processor.html_diff import generate_html_diff
                out_html = str(Path(ckl1).with_name(f"{Path(ckl1).stem}_diff.html"))
                generate_html_diff(ckl1, ckl2, out_html)
                print(_c(f"    HTML diff: {out_html}", "green"))
            except (ImportError, OSError, ValueError):
                pass

        except (ParseError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def generate_stats(self):
        """Generate compliance statistics from a checklist."""
        self._header("Generate Compliance Statistics")

        ckl_path = self._prompt("Path to CKL/CKLB file", validate_file=True)
        fmt = self._prompt_choice("Output format", ["text", "json", "csv", "html"])

        print(_c("\n  Generating statistics…", "cyan"))
        try:
            stats = self.proc.generate_stats(ckl_path, output_format=fmt)
            out_ext = {"text": ".txt", "json": ".json", "csv": ".csv", "html": ".html"}[fmt]
            out_file = str(Path(ckl_path).with_suffix(f".stats{out_ext}"))

            with open(out_file, "w", encoding="utf-8") as f:
                if fmt == "json":
                    json.dump(stats, f, indent=2, ensure_ascii=False)
                else:
                    f.write(stats if isinstance(stats, str) else json.dumps(stats, indent=2))

            self._success(f"Stats written to {out_file}")
        except (ParseError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def generate_html_report(self):
        """Generate a self-contained HTML compliance report."""
        self._header("Generate HTML Report")

        ckl_path = self._prompt("Path to CKL/CKLB file", validate_file=True)

        out_file = str(Path(ckl_path).with_suffix(".html"))
        print(_c(f"\n  Generating report → {out_file}…", "cyan"))
        try:
            from stig_assessor.processor.html_report import generate_html_report
            generate_html_report(ckl_path, out_file)
            self._success(f"HTML report generated: {out_file}")
        except (ParseError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def fleet_stats(self):
        """Aggregate fleet compliance from directory or ZIP of CKLs."""
        self._header("Fleet Statistics")

        target = self._prompt("Path to directory or ZIP of CKLs")
        if not os.path.exists(target):
            self._error("Path not found.")
            self._pause()
            return

        print(_c("\n  Analyzing fleet compliance…", "cyan"))
        try:
            from stig_assessor.processor.fleet_stats import FleetStats
            fs = FleetStats()
            if os.path.isfile(target) and target.lower().endswith(".zip"):
                stats = fs.process_zip(target)
            else:
                stats = fs.process_directory(target)

            out_file = str(Path(target).with_name("fleet_stats.json"))
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)

            self._success(f"Analyzed {stats.get('total_assets', 0)} assets → {out_file}")
        except (ParseError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def repair_checklist(self):
        """Repair a corrupted or non-compliant checklist."""
        self._header("Repair Checklist")

        ckl_path = self._prompt("Path to CKL to repair", validate_file=True)
        out_file = self._prompt("Output repaired file path (Enter for auto)", required=False)
        if not out_file:
            out_file = str(Path(ckl_path).with_name(f"{Path(ckl_path).stem}_repaired.ckl"))

        print(_c(f"\n  Repairing → {out_file}…", "cyan"))
        try:
            result = self.proc.repair(ckl_path, out_file)
            self._success(f"Applied {result.get('repairs', 0)} repairs → {out_file}")
            for detail in result.get("details", [])[:10]:
                print(f"    • {detail}")
            remaining = len(result.get("details", [])) - 10
            if remaining > 0:
                print(_c(f"    … and {remaining} more", "dim"))
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def export_poam(self):
        """Export Open/Not Reviewed findings to eMASS POAM CSV."""
        self._header("Export eMASS POAM")

        ckl_path = self._prompt("Path to CKL file", validate_file=True)

        print(_c("\n  Exporting POAM…", "cyan"))
        try:
            poam_str = self.proc.export_poam(ckl_path)
            out_file = str(Path(ckl_path).with_name(f"{Path(ckl_path).stem}_poam.csv"))
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(poam_str)
            self._success(f"POAM exported to {out_file}")
        except (ParseError, FileError, OSError, ValueError, AttributeError) as e:
            self._error(str(e))
        self._pause()

    def manage_boilerplates(self):
        """Sub-menu for boilerplate template management."""
        bp_options = [
            ("List all boilerplates", self._bp_list),
            ("Set a boilerplate", self._bp_set),
            ("Delete a boilerplate", self._bp_delete),
            ("Export boilerplates to JSON", self._bp_export),
            ("Import boilerplates from JSON", self._bp_import),
            ("Reset to factory defaults", self._bp_reset),
        ]
        # Temporarily set running to True for sub-menu
        saved = self.running
        self.running = True
        while self.running:
            self._menu("Boilerplate Management", bp_options)
        self.running = saved  # restore so main loop continues

    def _bp_list(self):
        bp_all = self.proc.boiler.list_all()
        if not bp_all:
            print(_c("  No boilerplates configured.", "yellow"))
        else:
            print(json.dumps(bp_all, indent=2, ensure_ascii=False))
        self._pause()

    def _bp_set(self):
        vid = self._prompt("Vulnerability ID (e.g. V-12345)")
        status = self._prompt_choice("Status", ["NotAFinding", "Open", "Not_Reviewed", "Not_Applicable"])
        finding = self._prompt("Finding Details text", required=False)
        comment = self._prompt("Comments text", required=False)
        self.proc.boiler.set(vid, status, finding or "", comment or "")
        self._success(f"Boilerplate set for {vid} / {status}")
        self._pause()

    def _bp_delete(self):
        vid = self._prompt("Vulnerability ID to delete")
        status = self._prompt("Status to delete (Enter for all)", required=False)
        deleted = self.proc.boiler.delete(vid, status or None)
        if deleted:
            self._success(f"Deleted boilerplate for {vid}")
        else:
            print(_c("  Boilerplate not found.", "yellow"))
        self._pause()

    def _bp_export(self):
        path = self._prompt("Export path (JSON file)")
        try:
            self.proc.boiler.export(path)
            self._success(f"Boilerplates exported to {path}")
        except (OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def _bp_import(self):
        path = self._prompt("Import path (JSON file)", validate_file=True)
        try:
            self.proc.boiler.imp(path)
            self._success(f"Boilerplates imported from {path}")
        except (OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def _bp_reset(self):
        if self._prompt_yn("Reset ALL boilerplates to defaults? This cannot be undone."):
            self.proc.boiler.reset_all()
            self._success("Boilerplates reset to factory defaults.")
        self._pause()

    def show_about(self):
        """Show version and environment info."""
        self._header("About")
        print(f"  {_c('Application:', 'cyan')}  {APP_NAME}")
        print(f"  {_c('Version:', 'cyan')}      {VERSION}")
        print(f"  {_c('App Dir:', 'cyan')}       {Cfg.APP_DIR}")
        print(f"  {_c('Log Dir:', 'cyan')}       {Cfg.LOG_DIR}")
        print(f"  {_c('Platform:', 'cyan')}      {'Windows' if Cfg.IS_WIN else ('Linux' if Cfg.IS_LIN else 'macOS')}")
        print(f"  {_c('Python:', 'cyan')}        {sys.version.split()[0]}")
        print()
        print(_c("  Capabilities:", "bold"))
        capabilities = [
            "XCCDF → CKL/CKLB Conversion",
            "Checklist Merging with History",
            "Fix Extraction (JSON/CSV/Bash/PS/Ansible)",
            "Bulk Remediation Import",
            "Evidence Management",
            "Boilerplate Templates",
            "HTML Compliance Reports",
            "Fleet Statistics",
            "eMASS POAM Export",
            "Checklist Repair",
            "Checklist Diff",
        ]
        for cap in capabilities:
            print(f"    • {cap}")
        self._pause()


    def bulk_edit_ckl(self):
        """Bulk update vulnerabilities."""
        self._header("Bulk Edit Checklist")
        ckl = self._prompt("Source CKL file", validate_file=True)
        out = self._prompt("Output CKL file")
        sev = self._prompt("Filter by Severity (high/medium/low, Enter for any)", required=False)
        vid = self._prompt("Filter by V-ID regex (e.g. ^V-123, Enter for any)", required=False)
        status = self._prompt_choice("New Status", ["NotAFinding", "Open", "Not_Reviewed", "Not_Applicable"])
        comment = self._prompt("New Comments")
        append = self._prompt_yn("Append to existing comments?", default=True)

        try:
            res = self.proc.bulk_edit(ckl, out, severity=sev, regex_vid=vid, new_status=status, new_comment=comment, append_comment=append)
            self._success(f"Updated {res['updates']} vulnerabilities. Saved to {res['output']}")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def apply_waiver(self):
        """Apply waivers to vulnerabilities."""
        self._header("Apply Waivers")
        ckl = self._prompt("Source CKL file", validate_file=True)
        out = self._prompt("Output CKL file")
        vids_str = self._prompt("Vulnerability IDs (comma separated)")
        vids = [v.strip() for v in vids_str.split(",") if v.strip()]
        approver = self._prompt("Approver Name/Title")
        reason = self._prompt("Waiver Justification")
        valid = self._prompt("Valid Until (YYYY-MM-DD)")

        print(_c("\n  Applying waivers…", "dim"))
        try:
            res = self.proc.apply_waivers(ckl, out, vids, approver, reason, valid)
            self._success(f"Applied waivers to {res['updates']} vulnerabilities. Saved to {res['output']}")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def batch_convert(self):
        """Batch convert multiple XCCDF files."""
        self._header("Batch Convert Checklists")
        in_dir = self._prompt("Input Directory (containing XCCDF files)", validate_dir=True)
        out_dir = self._prompt("Output Directory for CKL files", validate_dir=True)
        prefix = self._prompt("Asset name prefix", required=False) or "ASSET"
        apply_bp = self._prompt_yn("Apply boilerplate templates?", default=False)

        print(_c("\n  Converting (this may take a while)…", "dim"))
        try:
            res = self.proc.batch_convert(in_dir, out_dir, asset_prefix=prefix, apply_boilerplate=apply_bp)
            self._success(f"Batch convert complete: {res['converted']} succeeded, {res.get('failed', 0)} failed")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(str(e))
        self._pause()

    def advanced_pipeline(self):
        """Run a guided end-to-end pipeline (Build -> Apply Fixes -> Report)."""
        self._header("Advanced End-to-End Pipeline")
        print(_c("  This pipeline will walk you through Building, Remediating, and Reporting.", "cyan"))

        # Step 1: Create
        print(_c("\n  [Step 1] Build Checklist", "yellow"))
        xccdf = self._prompt("Input XCCDF/XML format file", validate_file=True)
        out1 = self._prompt("Output CKL file")
        asset = self._prompt("Asset Name (optional)", required=False)
        try:
            self.proc.xccdf_to_ckl(xccdf, out1, asset=asset or 'ASSET')
            self._success(f"Built CKL to {out1}")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(f"Failed Phase 1: {e}")
            self._pause()
            return

        # Step 2: Remediate
        if not self._prompt_yn("\nProceed to Remediate this checklist from Results?", default=True):
            self._pause()
            return
        print(_c("\n  [Step 2] Apply Remediation Results", "yellow"))
        fix_dir = self._prompt("Directory with JSON/CSV result files", validate_dir=True)
        out2 = self._prompt("Output CKL file (post-remediation)", default=out1)
        try:
            from stig_assessor.remediation.processor import FixResPro
            fix_proc = FixResPro()
            fix_proc.load_dir(fix_dir)
            res2 = fix_proc.update_ckl(out1, out2)
            self._success(f"Applied fixes: {res2['updated']} updated, {len(res2.get('not_found', []))} missing.")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(f"Failed Phase 2: {e}")
            self._pause()
            return

        # Step 3: Reporting
        if not self._prompt_yn("\nProceed to Generate Output Report?", default=True):
            self._pause()
            return
        print(_c("\n  [Step 3] Generate HTML Report", "yellow"))
        html_out = self._prompt("HTML Output path")
        try:
            from stig_assessor.processor.html_report import generate_html_report
            generate_html_report(out2, html_out)
            self._success(f"Report generated successfully.")
        except (ParseError, ValidationError, FileError, OSError, ValueError) as e:
            self._error(f"Failed Phase 3: {e}")
            self._pause()
            return

        print(_c("\n  Pipeline successfully finished!", "green", "bold"))
        if self._prompt_yn(f"Open {html_out} in default browser?", default=True):
            try:
                if os.name == "nt":
                    os.startfile(html_out)
                elif sys.platform == "darwin":
                    subprocess.call(["open", html_out])
                else:
                    subprocess.call(["xdg-open", html_out])
            except Exception as e:
                self._error(f"Could not open file: {e}")
        self._pause()


    # ── Main loop ────────────────────────────────────────────────────────────

    def run(self):
        options: List[Tuple[str, Callable]] = [
            ("Run Advanced End-to-End Pipeline", self.advanced_pipeline),
            ("Build Checklist from XCCDF", self.build_checklist),
            ("Merge Historical Checklists", self.merge_checklists),
            ("Extract Remediation Playbooks", self.extract_playbooks),
            ("Compare Checklists (Diff)", self.compare_checklists),
            ("Generate Compliance Statistics", self.generate_stats),
            ("Generate HTML Report", self.generate_html_report),
            ("Fleet Statistics", self.fleet_stats),
            ("Repair Checklist", self.repair_checklist),
            ("Bulk Edit Checklist", self.bulk_edit_ckl),
            ("Apply Waivers", self.apply_waiver),
            ("Batch Convert", self.batch_convert),
            ("Export eMASS POAM", self.export_poam),
            ("Manage Boilerplates ->", self.manage_boilerplates),
            ("About", self.show_about),
        ]

        while self.running:
            self._menu("Main Menu", options)


def launch_wizard():
    """Entry point for the interactive wizard."""
    wizard = InteractiveWizard()
    try:
        wizard.run()
    except KeyboardInterrupt:
        print("\n\n  Exiting Wizard.")
        sys.exit(0)
