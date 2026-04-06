"""Command-line interface and main entry point."""

from __future__ import annotations
from typing import List, Optional
from pathlib import Path
import argparse
import sys
import logging
import json
import gc
import threading
import time
import re


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
        sys.stderr.write("\r" + " " * (len(self.message) + 4) + "\r")
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





def format_color(text: str, color: str) -> str:
    """Format text (ANSI removed per zero-dependency TTY guidelines)."""
    return text


from stig_assessor.core.config import Cfg, APP_NAME, VERSION
from stig_assessor.core.logging import LOG
from stig_assessor.core.deps import Deps
from stig_assessor.core.state import GlobalState
from stig_assessor.templates.boilerplate import BP
from stig_assessor.processor.processor import Proc
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro
from stig_assessor.evidence.manager import EvidenceMgr

# Import GUI conditionally
if Deps.HAS_TKINTER:
    from stig_assessor.ui.gui import GUI


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
            help_text = help_text.replace("options:", format_color("OPTIONS:", "yellow"))

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
                r"(\d+\.\s+[^:]+:)", lambda m: format_color(m.group(1), "blue"), help_text
            )
            help_text = help_text.replace("stig-assessor", format_color("stig-assessor", "green"))
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
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--gui", action="store_true", help="Launch graphical interface")
    parser.add_argument("--web", action="store_true", help="Launch native web interface")

    create_group = parser.add_argument_group("Create CKL from XCCDF")
    create_group.add_argument("--create", action="store_true", help="Create CKL from XCCDF")
    create_group.add_argument("--xccdf", help="XCCDF XML file")
    create_group.add_argument("--asset", help="Asset name")
    create_group.add_argument("--out", help="Output CKL path")
    create_group.add_argument("--ip", help="Asset IP")
    create_group.add_argument("--mac", help="Asset MAC")
    create_group.add_argument("--role", default="None", help="Asset role")
    create_group.add_argument("--marking", default="CUI", help="Asset marking")
    create_group.add_argument(
        "--apply-boilerplate", action="store_true", help="Apply boilerplate templates"
    )
    create_group.add_argument("--dry-run", action="store_true", help="Dry run (no output written)")

    merge_group = parser.add_argument_group("Merge Checklists")
    merge_group.add_argument(
        "--merge", action="store_true", help="Merge checklists preserving history"
    )
    merge_group.add_argument("--base", help="Base checklist")
    merge_group.add_argument("--histories", nargs="+", help="Historical checklists to merge")
    merge_group.add_argument("--merge-out", help="Merged output CKL")
    merge_group.add_argument(
        "--no-preserve-history", action="store_true", help="Disable history preservation"
    )
    merge_group.add_argument(
        "--no-boilerplate", action="store_true", help="Disable boilerplate application"
    )
    merge_group.add_argument(
        "--merge-dry-run", action="store_true", help="Dry run (no output written)"
    )

    diff_group = parser.add_argument_group("Compare Checklists")
    diff_group.add_argument(
        "--diff", nargs=2, metavar=("CKL1", "CKL2"), help="Compare two checklists"
    )
    diff_group.add_argument(
        "--diff-format",
        choices=["summary", "detailed", "json"],
        default="summary",
        help="Diff output format (default: summary)",
    )

    extract_group = parser.add_argument_group("Extract Fixes")
    extract_group.add_argument("--extract", help="XCCDF file to extract fixes from")
    extract_group.add_argument("--outdir", help="Output directory for fixes")
    extract_group.add_argument("--no-json", action="store_true", help="Do not export JSON")
    extract_group.add_argument("--no-csv", action="store_true", help="Do not export CSV")
    extract_group.add_argument("--no-bash", action="store_true", help="Do not export Bash script")
    extract_group.add_argument(
        "--no-ps", action="store_true", help="Do not export PowerShell script"
    )
    extract_group.add_argument(
        "--script-dry-run", action="store_true", help="Generate scripts in dry-run mode"
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
        "--no-auto-status", action="store_true", help="Do not auto-mark successes as NotAFinding"
    )
    result_group.add_argument(
        "--results-dry-run", action="store_true", help="Dry run (no output written)"
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
        "--import-evidence", nargs=2, metavar=("VID", "FILE"), help="Import evidence file"
    )
    evidence_group.add_argument("--evidence-desc", help="Evidence description")
    evidence_group.add_argument("--evidence-cat", default="general", help="Evidence category")
    evidence_group.add_argument("--export-evidence", help="Export all evidence to directory")
    evidence_group.add_argument("--package-evidence", help="Create evidence ZIP package")
    evidence_group.add_argument("--import-evidence-package", help="Import evidence from package")

    history_group = parser.add_argument_group("History Management")
    history_group.add_argument("--export-history", help="Export history JSON")
    history_group.add_argument("--import-history", help="Import history JSON")

    bp_group = parser.add_argument_group("Boilerplate Management")
    bp_group.add_argument("--bp-list", action="store_true", help="List all boilerplates")
    bp_group.add_argument("--bp-list-vid", help="List boilerplates for a specific VID")
    bp_group.add_argument("--bp-set", action="store_true", help="Set a boilerplate comment")
    bp_group.add_argument("--bp-delete", action="store_true", help="Delete a boilerplate comment")
    bp_group.add_argument("--vid", help="Vulnerability ID (e.g. V-12345)")
    bp_group.add_argument("--status", help="Finding Status (e.g. NotAFinding, Open)")
    bp_group.add_argument("--finding", help="Finding Details text for boilerplate")
    bp_group.add_argument("--comment", help="Comments text for boilerplate")

    parser.add_argument("--validate", help="Validate checklist compatibility")

    # New features for v7.2.0
    repair_group = parser.add_argument_group("Repair Checklist")
    repair_group.add_argument("--repair", help="Repair corrupted checklist")
    repair_group.add_argument("--repair-out", help="Repaired checklist output path")

    batch_group = parser.add_argument_group("Batch Processing")
    batch_group.add_argument("--batch-convert", help="Directory containing XCCDF files to convert")
    batch_group.add_argument("--batch-out", help="Output directory for batch conversion")
    batch_group.add_argument(
        "--batch-asset-prefix", default="ASSET", help="Asset name prefix for batch conversion"
    )

    integrity_group = parser.add_argument_group("Integrity Verification")
    integrity_group.add_argument(
        "--verify-integrity", help="Verify checklist integrity with checksums"
    )
    integrity_group.add_argument(
        "--compute-checksum", help="Compute and display checksum for a file"
    )

    stats_group = parser.add_argument_group("Compliance Statistics")
    stats_group.add_argument("--stats", help="Generate compliance statistics for checklist")
    stats_group.add_argument(
        "--stats-format",
        choices=["text", "json", "csv"],
        default="text",
        help="Statistics output format (default: text)",
    )
    stats_group.add_argument("--stats-out", help="Output file for statistics (default: stdout)")

    args = parser.parse_args(argv)

    if args.verbose:
        LOG.log.setLevel(logging.DEBUG)

    try:
        if args.gui:
            if not Deps.HAS_TKINTER:
                print("ERROR: tkinter not available. Install python3-tk.", file=sys.stderr)
                return 1
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

        proc = Proc()

        if args.create:
            if not args.xccdf:
                args.xccdf = prompt_missing("Please enter the path to the XCCDF file")
            if not args.asset:
                args.asset = prompt_missing("Please enter the Asset name")

            if not (args.xccdf and args.asset):
                parser.error("--create requires at least --xccdf and --asset")

            out_path = args.out
            if not out_path:
                xccdf_path = Path(args.xccdf)
                out_path = str(xccdf_path.with_name(f"{args.asset}_{xccdf_path.stem}.ckl"))
                LOG.i(f"Auto-resolved output path: {out_path}")

            with Spinner(f"Converting XCCDF to CKL..."):
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
            print(format_color(json.dumps(result, indent=2, ensure_ascii=False), "green"))
            return 0

        if args.merge:
            if not args.base:
                args.base = prompt_missing("Please enter the path to the base checklist")
            if not args.histories:
                hist = prompt_missing("Please enter historical checklists (space-separated)")
                args.histories = [h for h in hist.split()] if hist else None

            if not (args.base and args.histories):
                parser.error("--merge requires at least --base and --histories")

            merge_out = args.merge_out
            if not merge_out:
                base_path = Path(args.base)
                merge_out = str(base_path.with_name(f"{base_path.stem}_merged.ckl"))
                LOG.i(f"Auto-resolved merge output path: {merge_out}")

            with Spinner("Merging checklists..."):
                result = proc.merge(
                    args.base,
                    args.histories,
                    merge_out,
                    preserve_history=not args.no_preserve_history,
                    apply_boilerplate=not args.no_boilerplate,
                    dry=args.merge_dry_run,
                )
            print(format_color(json.dumps(result, indent=2, ensure_ascii=False), "green"))
            return 0

        if args.diff:
            ckl1, ckl2 = args.diff
            result = proc.diff(ckl1, ckl2, output_format=args.diff_format)
            if args.diff_format == "json":
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(result.get("formatted_text", ""))
            return 0

        if args.extract:
            extract_outdir = args.outdir
            if not extract_outdir:
                extract_path = Path(args.extract)
                extract_outdir = str(extract_path.with_name(f"{extract_path.stem}_fixes"))
                LOG.i(f"Auto-resolved output directory: {extract_outdir}")

            with Spinner("Extracting fixes..."):
                extractor = FixExt(args.extract)
                extractor.extract()
                outdir = Path(extract_outdir)
                outdir.mkdir(parents=True, exist_ok=True, mode=0o700)

                if not args.no_json:
                    extractor.to_json(outdir / "fixes.json")
                if not args.no_csv:
                    extractor.to_csv(outdir / "fixes.csv")
                if not args.no_bash:
                    extractor.to_bash(outdir / "remediate.sh", dry_run=args.script_dry_run)
                if not args.no_ps:
                    extractor.to_powershell(outdir / "Remediate.ps1", dry_run=args.script_dry_run)

            print(
                format_color(
                    json.dumps(extractor.stats_summary(), indent=2, ensure_ascii=False), "green"
                )
            )
            return 0

        if args.apply_results:
            if not args.checklist:
                args.checklist = prompt_missing("Please enter the path to the target checklist")

            if not args.checklist:
                parser.error("--apply-results requires --checklist")

            results_out = args.results_out
            if not results_out:
                checklist_path = Path(args.checklist)
                results_out = str(checklist_path.with_name(f"{checklist_path.stem}_updated.ckl"))
                LOG.i(f"Auto-resolved results output path: {results_out}")

            # ═══ ENHANCED: Support multiple result files ═══
            result_files = (
                args.apply_results if isinstance(args.apply_results, list) else [args.apply_results]
            )

            processor = FixResPro()
            total_loaded = 0
            total_skipped = 0
            failed_files = []

            print(
                format_color(f"[INFO] Processing {len(result_files)} result file(s)...", "blue"),
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
                        format_color(f"  ✓ Loaded {imported} results (skipped {skipped})", "green"),
                        file=sys.stderr,
                    )
                except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
                    print(format_color(f"  ✘ Failed: {exc}", "red"), file=sys.stderr)
                    failed_files.append({"file": str(result_file), "error": str(exc)})
                    continue

            if not processor.results:
                print(
                    format_color(f"[ERROR] No valid results loaded from any file", "red"),
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
                print(format_color(json.dumps(result, indent=2, ensure_ascii=False), "green"))
            else:
                print(format_color(json.dumps(result, indent=2, ensure_ascii=False), "yellow"))
            return 0 if len(failed_files) == 0 else 2  # Exit code 2 if some files failed

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
            proc.boiler.set(args.vid, args.status, args.finding or "", args.comment or "")
            print(format_color(f"Boilerplate set for {args.vid} / {args.status}", "green"))
            return 0
            
        if args.bp_delete:
            if not args.vid:
                parser.error("--bp-delete requires at least --vid")
            deleted = proc.boiler.delete(args.vid, args.status)
            if deleted:
                print(format_color(f"Deleted boilerplate {'for ' + args.status if args.status else 'all statuses'} on {args.vid}", "green"))
            else:
                print(format_color("Boilerplate not found", "yellow"))
            return 0

        if args.validate:
            ok, errors, warnings_, info = proc.validator.validate(args.validate)
            print(
                json.dumps(
                    {"ok": ok, "errors": errors, "warnings": warnings_, "info": info}, indent=2
                )
            )
            return 0 if ok else 1

        # New features for v7.2.0
        if args.repair:
            repair_out = args.repair_out
            if not repair_out:
                repair_path = Path(args.repair)
                repair_out = str(repair_path.with_name(f"{repair_path.stem}_repaired.ckl"))
                LOG.i(f"Auto-resolved repair output path: {repair_out}")

            with Spinner("Repairing checklist..."):
                result = proc.repair(args.repair, repair_out)

            print(format_color(json.dumps(result, indent=2, ensure_ascii=False), "green"))
            return 0

        if args.batch_convert:
            batch_out = args.batch_out
            if not batch_out:
                batch_path = Path(args.batch_convert)
                batch_out = str(batch_path.parent / f"{batch_path.name}_ckls")
                LOG.i(f"Auto-resolved batch output directory: {batch_out}")

            with Spinner(f"Batch converting directory '{args.batch_convert}'..."):
                result = proc.batch_convert(
                    args.batch_convert,
                    batch_out,
                    asset_prefix=args.batch_asset_prefix,
                    apply_boilerplate=(
                        args.apply_boilerplate if hasattr(args, "apply_boilerplate") else False
                    ),
                )
            print(
                format_color(
                    json.dumps(result, indent=2, ensure_ascii=False),
                    "green" if result.get("failures", 0) == 0 else "yellow",
                )
            )
            return 0 if result.get("failures", 0) == 0 else 2

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
                        f.write(result if isinstance(result, str) else json.dumps(result, indent=2))
                print(f"Statistics written to {output_path}")
            else:
                if args.stats_format == "json":
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                else:
                    print(result)
            return 0

        parser.print_help()
        return 0

    except KeyboardInterrupt:
        print(format_color("\nOperation cancelled by user", "yellow"), file=sys.stderr)
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
