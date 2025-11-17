"""Command-line interface and main entry point."""

from __future__ import annotations
from typing import List, Optional
from pathlib import Path
import argparse
import sys
import logging
import json
import gc

# Temporary imports from monolithic file - will be replaced when other teams complete their modules
# This allows Team 12 to work in parallel while Teams 0-11 modularize their components
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from STIG_Script import (
        # Core components (Team 1, Team 0)
        Cfg, LOG, Deps, APP_NAME, VERSION, GlobalState,
        # Boilerplate (Team 7)
        BP,
        # Processor (Team 11)
        Proc,
        # Remediation (Teams 8, 10)
        FixExt, FixResPro,
        # Evidence (Team 9)
        EvidenceMgr,
    )
    # Get the global instance
    GLOBAL = GlobalState()
except ImportError:
    # If running as part of the full modular package
    from stig_assessor.core.config import Cfg, APP_NAME, VERSION
    from stig_assessor.core.logging import LOG
    from stig_assessor.core.deps import Deps
    from stig_assessor.core.state import GLOBAL_STATE as GLOBAL
    from stig_assessor.templates.boilerplate import BP
    from stig_assessor.processor.processor import Proc
    from stig_assessor.remediation.extractor import FixExt
    from stig_assessor.remediation.processor import FixResPro
    from stig_assessor.evidence.manager import EvidenceMgr

# Import GUI conditionally
if Deps.HAS_TKINTER:
    try:
        from STIG_Script import GUI
    except ImportError:
        from stig_assessor.ui.gui import GUI


def ensure_default_boilerplates() -> None:
    """Initialize default boilerplate templates if they don't exist."""
    if Cfg.BOILERPLATE_FILE and not Cfg.BOILERPLATE_FILE.exists():
        BP().export(Cfg.BOILERPLATE_FILE)
        LOG.i(f"Default boilerplate templates saved to {Cfg.BOILERPLATE_FILE}")


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
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{VERSION}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--gui", action="store_true", help="Launch graphical interface")

    create_group = parser.add_argument_group("Create CKL from XCCDF")
    create_group.add_argument("--create", action="store_true", help="Create CKL from XCCDF")
    create_group.add_argument("--xccdf", help="XCCDF XML file")
    create_group.add_argument("--asset", help="Asset name")
    create_group.add_argument("--out", help="Output CKL path")
    create_group.add_argument("--ip", help="Asset IP")
    create_group.add_argument("--mac", help="Asset MAC")
    create_group.add_argument("--role", default="None", help="Asset role")
    create_group.add_argument("--marking", default="CUI", help="Asset marking")
    create_group.add_argument("--apply-boilerplate", action="store_true", help="Apply boilerplate templates")
    create_group.add_argument("--dry-run", action="store_true", help="Dry run (no output written)")

    merge_group = parser.add_argument_group("Merge Checklists")
    merge_group.add_argument("--merge", action="store_true", help="Merge checklists preserving history")
    merge_group.add_argument("--base", help="Base checklist")
    merge_group.add_argument("--histories", nargs="+", help="Historical checklists to merge")
    merge_group.add_argument("--merge-out", help="Merged output CKL")
    merge_group.add_argument("--no-preserve-history", action="store_true", help="Disable history preservation")
    merge_group.add_argument("--no-boilerplate", action="store_true", help="Disable boilerplate application")
    merge_group.add_argument("--merge-dry-run", action="store_true", help="Dry run (no output written)")

    diff_group = parser.add_argument_group("Compare Checklists")
    diff_group.add_argument("--diff", nargs=2, metavar=("CKL1", "CKL2"), help="Compare two checklists")
    diff_group.add_argument("--diff-format", choices=["summary", "detailed", "json"], default="summary",
                           help="Diff output format (default: summary)")

    extract_group = parser.add_argument_group("Extract Fixes")
    extract_group.add_argument("--extract", help="XCCDF file to extract fixes from")
    extract_group.add_argument("--outdir", help="Output directory for fixes")
    extract_group.add_argument("--no-json", action="store_true", help="Do not export JSON")
    extract_group.add_argument("--no-csv", action="store_true", help="Do not export CSV")
    extract_group.add_argument("--no-bash", action="store_true", help="Do not export Bash script")
    extract_group.add_argument("--no-ps", action="store_true", help="Do not export PowerShell script")
    extract_group.add_argument("--script-dry-run", action="store_true", help="Generate scripts in dry-run mode")

    result_group = parser.add_argument_group("Apply Remediation Results")
    result_group.add_argument("--apply-results", nargs="+", help="Results JSON file(s) to import (supports multiple files)")
    result_group.add_argument("--checklist", help="Checklist to update")
    result_group.add_argument("--results-out", help="Updated checklist output path")
    result_group.add_argument("--no-auto-status", action="store_true", help="Do not auto-mark successes as NotAFinding")
    result_group.add_argument("--results-dry-run", action="store_true", help="Dry run (no output written)")

    evidence_group = parser.add_argument_group("Evidence Management")
    evidence_group.add_argument("--import-evidence", nargs=2, metavar=("VID", "FILE"), help="Import evidence file")
    evidence_group.add_argument("--evidence-desc", help="Evidence description")
    evidence_group.add_argument("--evidence-cat", default="general", help="Evidence category")
    evidence_group.add_argument("--export-evidence", help="Export all evidence to directory")
    evidence_group.add_argument("--package-evidence", help="Create evidence ZIP package")
    evidence_group.add_argument("--import-evidence-package", help="Import evidence from package")

    history_group = parser.add_argument_group("History Management")
    history_group.add_argument("--export-history", help="Export history JSON")
    history_group.add_argument("--import-history", help="Import history JSON")

    parser.add_argument("--validate", help="Validate checklist compatibility")

    # New features for v7.2.0
    repair_group = parser.add_argument_group("Repair Checklist")
    repair_group.add_argument("--repair", help="Repair corrupted checklist")
    repair_group.add_argument("--repair-out", help="Repaired checklist output path")

    batch_group = parser.add_argument_group("Batch Processing")
    batch_group.add_argument("--batch-convert", help="Directory containing XCCDF files to convert")
    batch_group.add_argument("--batch-out", help="Output directory for batch conversion")
    batch_group.add_argument("--batch-asset-prefix", default="ASSET", help="Asset name prefix for batch conversion")

    integrity_group = parser.add_argument_group("Integrity Verification")
    integrity_group.add_argument("--verify-integrity", help="Verify checklist integrity with checksums")
    integrity_group.add_argument("--compute-checksum", help="Compute and display checksum for a file")

    stats_group = parser.add_argument_group("Compliance Statistics")
    stats_group.add_argument("--stats", help="Generate compliance statistics for checklist")
    stats_group.add_argument("--stats-format", choices=["text", "json", "csv"], default="text",
                            help="Statistics output format (default: text)")
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

        proc = Proc()

        if args.create:
            if not (args.xccdf and args.asset and args.out):
                parser.error("--create requires --xccdf, --asset, and --out")
            result = proc.xccdf_to_ckl(
                args.xccdf,
                args.out,
                args.asset,
                ip=args.ip or "",
                mac=args.mac or "",
                role=args.role,
                marking=args.marking,
                dry=args.dry_run,
                apply_boilerplate=args.apply_boilerplate,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.merge:
            if not (args.base and args.histories and args.merge_out):
                parser.error("--merge requires --base, --histories, and --merge-out")
            result = proc.merge(
                args.base,
                args.histories,
                args.merge_out,
                preserve_history=not args.no_preserve_history,
                apply_boilerplate=not args.no_boilerplate,
                dry=args.merge_dry_run,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.diff:
            ckl1, ckl2 = args.diff
            result = proc.diff(ckl1, ckl2, output_format=args.diff_format)
            if args.diff_format == "json":
                print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.extract:
            if not args.outdir:
                parser.error("--extract requires --outdir")

            extractor = FixExt(args.extract)
            extractor.extract()
            outdir = Path(args.outdir)
            outdir.mkdir(parents=True, exist_ok=True)

            if not args.no_json:
                extractor.to_json(outdir / "fixes.json")
            if not args.no_csv:
                extractor.to_csv(outdir / "fixes.csv")
            if not args.no_bash:
                extractor.to_bash(outdir / "remediate.sh", dry_run=args.script_dry_run)
            if not args.no_ps:
                extractor.to_powershell(outdir / "Remediate.ps1", dry_run=args.script_dry_run)

            print(json.dumps(extractor.stats_summary(), indent=2, ensure_ascii=False))
            return 0


        if args.apply_results:
            if not (args.checklist and args.results_out):
                parser.error("--apply-results requires --checklist and --results-out")

            # Support multiple result files (args.apply_results is always a list due to nargs="+")
            result_files = args.apply_results

            processor = FixResPro()
            total_loaded = 0
            total_skipped = 0
            failed_files = []

            print(f"[INFO] Processing {len(result_files)} result file(s)...", file=sys.stderr)

            for idx, result_file in enumerate(result_files, 1):
                try:
                    print(f"[{idx}/{len(result_files)}] Loading {Path(result_file).name}...", file=sys.stderr)
                    imported, skipped = processor.load(result_file)
                    total_loaded += imported
                    total_skipped += skipped
                    print(f"  ✓ Loaded {imported} results (skipped {skipped})", file=sys.stderr)
                except Exception as exc:
                    print(f"  ✘ Failed: {exc}", file=sys.stderr)
                    failed_files.append({"file": str(result_file), "error": str(exc)})
                    continue

            if not processor.results:
                print(f"[ERROR] No valid results loaded from any file", file=sys.stderr)
                return 1

            print(f"\n[INFO] Applying {len(processor.results)} unique results to checklist...", file=sys.stderr)

            # Apply to checklist
            result = processor.update_ckl(
                args.checklist,
                args.results_out,
                auto_status=not args.no_auto_status,
                dry=args.results_dry_run,
            )

            # Add batch statistics
            result['batch_stats'] = {
                'files_total': len(result_files),
                'files_failed': len(failed_files),
                'results_loaded': total_loaded,
                'results_skipped': total_skipped,
                'unique_vulns': len(processor.results),
            }

            if failed_files:
                result['failed_files'] = failed_files

            print(json.dumps(result, indent=2, ensure_ascii=False))
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

        if args.validate:
            ok, errors, warnings_, info = proc.validator.validate(args.validate)
            print(json.dumps({"ok": ok, "errors": errors, "warnings": warnings_, "info": info}, indent=2))
            return 0 if ok else 1

        # New features for v7.2.0
        if args.repair:
            if not args.repair_out:
                parser.error("--repair requires --repair-out")
            result = proc.repair(args.repair, args.repair_out)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.batch_convert:
            if not args.batch_out:
                parser.error("--batch-convert requires --batch-out")
            result = proc.batch_convert(
                args.batch_convert,
                args.batch_out,
                asset_prefix=args.batch_asset_prefix,
                apply_boilerplate=getattr(args, 'apply_boilerplate', False)
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get('failures', 0) == 0 else 2

        if args.verify_integrity:
            result = proc.verify_integrity(args.verify_integrity)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result['valid'] else 1

        if args.compute_checksum:
            checksum = proc.compute_checksum(args.compute_checksum)
            print(f"{checksum}  {args.compute_checksum}")
            return 0

        if args.stats:
            result = proc.generate_stats(args.stats, output_format=args.stats_format)
            if args.stats_out:
                output_path = Path(args.stats_out)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    if args.stats_format == 'json':
                        json.dump(result, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(result if isinstance(result, str) else json.dumps(result, indent=2))
                print(f"Statistics written to {output_path}")
            else:
                if args.stats_format == 'json':
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                else:
                    print(result)
            return 0

        parser.print_help()
        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as exc:
        LOG.e(f"Fatal error: {exc}", exc=True)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        GLOBAL.cleanup()
        gc.collect()


if __name__ == "__main__":
    sys.exit(main())
