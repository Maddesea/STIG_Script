#!/usr/bin/env python3
"""
Remediation JSON Generator for STIG Assessor Complete

This script generates remediation JSON files that can be fed to STIG_Script.py
using the --apply-results command.

Usage Examples:
    # Interactive mode - generates template
    python generate_remediation.py

    # From CSV file
    python generate_remediation.py --from-csv results.csv --output remediation.json

    # From checklist (extract VIDs)
    python generate_remediation.py --from-ckl checklist.ckl --status Open --output remediation.json

    # Single result
    python generate_remediation.py --vid V-123456 --ok --msg "Fixed" --output single.json

    # Batch mode with multiple VIDs
    python generate_remediation.py --batch V-1,V-2,V-3 --all-ok --output batch.json

    # Multi-system format
    python generate_remediation.py --multi-system server1.csv server2.csv --output multi.json

Apply results to checklist:
    python STIG_Script.py --apply-results remediation.json --checklist current.ckl --results-out updated.ckl

Version: 1.0.0
Compatible with: STIG Assessor Complete 7.0.0+
"""

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# ═══════════════════════════════════════════════════════════════════════════
# JSON FORMAT SCHEMA
# ═══════════════════════════════════════════════════════════════════════════

EXAMPLE_FORMATS = {
    "simple_array": {
        "description": "Simple array of results (recommended for single-system)",
        "example": [
            {
                "vid": "V-123456",
                "ts": "2025-11-16T12:00:00Z",
                "ok": True,
                "msg": "Successfully remediated",
                "out": "Command executed successfully",
                "err": ""
            },
            {
                "vid": "V-123457",
                "ts": "2025-11-16T12:00:00Z",
                "ok": False,
                "msg": "Failed to remediate",
                "out": "",
                "err": "Permission denied"
            }
        ]
    },
    "standard_object": {
        "description": "Object with metadata (recommended for tracked deployments)",
        "example": {
            "meta": {
                "description": "Windows Server 2022 remediation results",
                "timestamp": "2025-11-16T12:00:00Z",
                "hostname": "SERVER-01",
                "operator": "admin@example.mil",
                "remediation_version": "1.0"
            },
            "results": [
                {
                    "vid": "V-123456",
                    "ts": "2025-11-16T12:00:00Z",
                    "ok": True,
                    "msg": "Successfully remediated",
                    "out": "Registry key updated",
                    "err": ""
                }
            ]
        }
    },
    "multi_system": {
        "description": "Multiple systems in one file",
        "example": {
            "systems": {
                "SERVER-01": [
                    {
                        "vid": "V-123456",
                        "ts": "2025-11-16T12:00:00Z",
                        "ok": True,
                        "msg": "Remediated",
                        "out": "",
                        "err": ""
                    }
                ],
                "SERVER-02": [
                    {
                        "vid": "V-123456",
                        "ts": "2025-11-16T12:00:00Z",
                        "ok": True,
                        "msg": "Remediated",
                        "out": "",
                        "err": ""
                    }
                ]
            }
        }
    }
}


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_timestamp() -> str:
    """Get current timestamp in ISO 8601 format with UTC timezone."""
    return datetime.now(timezone.utc).isoformat()


def create_result(
    vid: str,
    ok: bool = True,
    msg: str = "",
    out: str = "",
    err: str = "",
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a single remediation result entry.

    Args:
        vid: Vulnerability ID (e.g., "V-123456")
        ok: True if remediation succeeded, False otherwise
        msg: Human-readable message
        out: Command output or success details
        err: Error message if ok=False
        timestamp: ISO 8601 timestamp (defaults to current time)

    Returns:
        Dictionary representing a remediation result
    """
    return {
        "vid": vid.strip(),
        "ts": timestamp or get_timestamp(),
        "ok": bool(ok),
        "msg": msg.strip(),
        "out": out.strip(),
        "err": err.strip()
    }


def validate_vid(vid: str) -> bool:
    """Check if VID format is valid (V-XXXXXX)."""
    if not vid.startswith("V-"):
        return False
    try:
        int(vid[2:])
        return True
    except ValueError:
        return False


def extract_vids_from_ckl(ckl_path: Path, status_filter: Optional[str] = None) -> List[str]:
    """
    Extract vulnerability IDs from a CKL file.

    Args:
        ckl_path: Path to CKL file
        status_filter: Only extract VIDs with this status (e.g., "Open", "Not_Reviewed")

    Returns:
        List of vulnerability IDs
    """
    try:
        tree = ET.parse(ckl_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error: Cannot parse CKL file: {e}", file=sys.stderr)
        return []

    vids = []
    stigs = root.find("STIGS")
    if stigs is None:
        return vids

    for istig in stigs.findall("iSTIG"):
        for vuln in istig.findall("VULN"):
            # Find VID
            stig_data = vuln.findall("STIG_DATA")
            vid = None
            for data in stig_data:
                name = data.find("VULN_ATTRIBUTE")
                value = data.find("ATTRIBUTE_DATA")
                if name is not None and name.text == "Vuln_Num":
                    if value is not None and value.text:
                        vid = value.text.strip()
                        break

            if not vid:
                continue

            # Apply status filter if specified
            if status_filter:
                status_node = vuln.find("STATUS")
                if status_node is None or status_node.text != status_filter:
                    continue

            vids.append(vid)

    return vids


def read_csv_results(csv_path: Path) -> List[Dict[str, Any]]:
    """
    Read remediation results from CSV file.

    CSV format:
        vid,ok,msg,out,err
        V-123456,true,Remediated,Command output,
        V-123457,false,Failed,,Permission denied

    Args:
        csv_path: Path to CSV file

    Returns:
        List of result dictionaries
    """
    results = []

    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                vid = row.get('vid', '').strip()
                if not vid or not validate_vid(vid):
                    print(f"Warning: Skipping invalid VID: {vid}", file=sys.stderr)
                    continue

                ok_val = row.get('ok', 'true').strip().lower()
                ok = ok_val in ('true', '1', 'yes', 'success')

                results.append(create_result(
                    vid=vid,
                    ok=ok,
                    msg=row.get('msg', ''),
                    out=row.get('out', ''),
                    err=row.get('err', ''),
                    timestamp=row.get('ts', None)
                ))
    except Exception as e:
        print(f"Error: Cannot read CSV file: {e}", file=sys.stderr)
        return []

    return results


def generate_template_csv(output_path: Path, vids: List[str]):
    """Generate a template CSV file for manual editing."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['vid', 'ok', 'msg', 'out', 'err'])

        for vid in vids:
            writer.writerow([vid, 'true', 'Remediated', '', ''])

    print(f"✓ Template CSV generated: {output_path}")
    print(f"  Edit this file and use: python generate_remediation.py --from-csv {output_path} --output results.json")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN GENERATION LOGIC
# ═══════════════════════════════════════════════════════════════════════════

def generate_simple_array(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate simple array format."""
    return results


def generate_standard_object(
    results: List[Dict[str, Any]],
    meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate standard object format with metadata."""
    if meta is None:
        meta = {
            "description": "Remediation results",
            "timestamp": get_timestamp(),
            "generated_by": "generate_remediation.py v1.0.0"
        }

    return {
        "meta": meta,
        "results": results
    }


def generate_multi_system(
    system_results: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Generate multi-system format."""
    return {
        "systems": system_results
    }


# ═══════════════════════════════════════════════════════════════════════════
# CLI COMMANDS
# ═══════════════════════════════════════════════════════════════════════════

def cmd_show_examples(args):
    """Show example JSON formats."""
    if args.format:
        fmt = args.format
        if fmt not in EXAMPLE_FORMATS:
            print(f"Error: Unknown format '{fmt}'", file=sys.stderr)
            print(f"Available formats: {', '.join(EXAMPLE_FORMATS.keys())}", file=sys.stderr)
            return 1

        print(f"═══ {EXAMPLE_FORMATS[fmt]['description']} ═══\n")
        print(json.dumps(EXAMPLE_FORMATS[fmt]['example'], indent=2))
    else:
        print("═══ SUPPORTED JSON FORMATS ═══\n")
        for name, info in EXAMPLE_FORMATS.items():
            print(f"Format: {name}")
            print(f"  {info['description']}\n")
            print(json.dumps(info['example'], indent=2))
            print("\n" + "─" * 80 + "\n")

    return 0


def cmd_generate_single(args):
    """Generate a single result."""
    if not validate_vid(args.vid):
        print(f"Error: Invalid VID format: {args.vid}", file=sys.stderr)
        print("Expected format: V-123456", file=sys.stderr)
        return 1

    result = create_result(
        vid=args.vid,
        ok=args.ok,
        msg=args.msg or ("Remediated" if args.ok else "Failed"),
        out=args.out or "",
        err=args.err or ""
    )

    output = generate_simple_array([result])

    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2))
        print(f"✓ Generated: {args.output}")
    else:
        print(json.dumps(output, indent=2))

    return 0


def cmd_generate_batch(args):
    """Generate multiple results from comma-separated VIDs."""
    vids = [v.strip() for v in args.batch.split(',')]

    results = []
    for vid in vids:
        if not validate_vid(vid):
            print(f"Warning: Skipping invalid VID: {vid}", file=sys.stderr)
            continue

        results.append(create_result(
            vid=vid,
            ok=args.all_ok if args.all_ok is not None else True,
            msg=args.msg or ("Remediated" if args.all_ok else "Not remediated"),
            out=args.out or "",
            err=args.err or ""
        ))

    if not results:
        print("Error: No valid VIDs provided", file=sys.stderr)
        return 1

    if args.format_type == "object":
        output = generate_standard_object(results)
    else:
        output = generate_simple_array(results)

    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2))
        print(f"✓ Generated {len(results)} results: {args.output}")
    else:
        print(json.dumps(output, indent=2))

    return 0


def cmd_from_csv(args):
    """Generate from CSV file."""
    csv_path = Path(args.from_csv)
    if not csv_path.exists():
        print(f"Error: CSV file not found: {csv_path}", file=sys.stderr)
        return 1

    results = read_csv_results(csv_path)
    if not results:
        print("Error: No valid results in CSV file", file=sys.stderr)
        return 1

    if args.format_type == "object":
        output = generate_standard_object(results, meta={
            "description": f"Results from {csv_path.name}",
            "timestamp": get_timestamp(),
            "source": str(csv_path)
        })
    else:
        output = generate_simple_array(results)

    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2))
        print(f"✓ Generated {len(results)} results from CSV: {args.output}")
    else:
        print(json.dumps(output, indent=2))

    return 0


def cmd_from_ckl(args):
    """Extract VIDs from CKL and generate template."""
    ckl_path = Path(args.from_ckl)
    if not ckl_path.exists():
        print(f"Error: CKL file not found: {ckl_path}", file=sys.stderr)
        return 1

    vids = extract_vids_from_ckl(ckl_path, args.status)
    if not vids:
        status_msg = f" with status '{args.status}'" if args.status else ""
        print(f"Error: No vulnerabilities found in CKL{status_msg}", file=sys.stderr)
        return 1

    print(f"✓ Found {len(vids)} vulnerabilities")

    if args.template_csv:
        # Generate CSV template for manual editing
        generate_template_csv(Path(args.template_csv), vids)
        return 0

    # Generate JSON with all VIDs marked as remediated
    results = [create_result(vid=vid, ok=True, msg="Remediated") for vid in vids]

    if args.format_type == "object":
        output = generate_standard_object(results, meta={
            "description": f"Results from {ckl_path.name}",
            "timestamp": get_timestamp(),
            "source": str(ckl_path),
            "status_filter": args.status
        })
    else:
        output = generate_simple_array(results)

    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2))
        print(f"✓ Generated {len(results)} results from CKL: {args.output}")
    else:
        print(json.dumps(output, indent=2))

    return 0


def cmd_multi_system(args):
    """Generate multi-system format from multiple CSV files."""
    system_results = {}

    for csv_file in args.multi_system:
        csv_path = Path(csv_file)
        if not csv_path.exists():
            print(f"Warning: Skipping missing file: {csv_path}", file=sys.stderr)
            continue

        # Use filename (without extension) as system name
        system_name = csv_path.stem
        results = read_csv_results(csv_path)

        if results:
            system_results[system_name] = results
            print(f"✓ Loaded {len(results)} results from {system_name}")

    if not system_results:
        print("Error: No valid results loaded", file=sys.stderr)
        return 1

    output = generate_multi_system(system_results)

    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2))
        total = sum(len(r) for r in system_results.values())
        print(f"✓ Generated multi-system file with {total} total results: {args.output}")
    else:
        print(json.dumps(output, indent=2))

    return 0


# ═══════════════════════════════════════════════════════════════════════════
# INTERACTIVE MODE
# ═══════════════════════════════════════════════════════════════════════════

def interactive_mode():
    """Interactive mode for generating remediation files."""
    print("═══ Remediation JSON Generator - Interactive Mode ═══\n")
    print("This tool generates JSON files for STIG_Script.py --apply-results\n")

    while True:
        print("\nSelect an option:")
        print("  1. Generate from CKL file (extract VIDs)")
        print("  2. Generate from CSV file")
        print("  3. Create template CSV for manual editing")
        print("  4. Show example formats")
        print("  5. Exit")

        choice = input("\nEnter choice (1-5): ").strip()

        if choice == "1":
            ckl_path = input("Enter CKL file path: ").strip()
            status = input("Filter by status (Open/Not_Reviewed/blank for all): ").strip() or None
            output_path = input("Output JSON file path: ").strip()

            if Path(ckl_path).exists():
                vids = extract_vids_from_ckl(Path(ckl_path), status)
                if vids:
                    results = [create_result(vid=vid, ok=True, msg="Remediated") for vid in vids]
                    output = generate_standard_object(results)
                    Path(output_path).write_text(json.dumps(output, indent=2))
                    print(f"✓ Generated {len(vids)} results: {output_path}")
                else:
                    print("No vulnerabilities found")
            else:
                print(f"Error: File not found: {ckl_path}")

        elif choice == "2":
            csv_path = input("Enter CSV file path: ").strip()
            output_path = input("Output JSON file path: ").strip()

            if Path(csv_path).exists():
                results = read_csv_results(Path(csv_path))
                if results:
                    output = generate_standard_object(results)
                    Path(output_path).write_text(json.dumps(output, indent=2))
                    print(f"✓ Generated {len(results)} results: {output_path}")
                else:
                    print("No valid results in CSV")
            else:
                print(f"Error: File not found: {csv_path}")

        elif choice == "3":
            ckl_path = input("Enter CKL file path (to extract VIDs): ").strip()
            csv_path = input("Output CSV template path: ").strip()

            if Path(ckl_path).exists():
                vids = extract_vids_from_ckl(Path(ckl_path))
                if vids:
                    generate_template_csv(Path(csv_path), vids)
                else:
                    print("No vulnerabilities found")
            else:
                print(f"Error: File not found: {ckl_path}")

        elif choice == "4":
            for name, info in EXAMPLE_FORMATS.items():
                print(f"\n{name}: {info['description']}")

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid choice")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Generate remediation JSON files for STIG_Script.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # General options
    parser.add_argument("-o", "--output", help="Output JSON file path (prints to stdout if omitted)")
    parser.add_argument(
        "--format-type",
        choices=["array", "object"],
        default="array",
        help="Output format type (default: array)"
    )

    # Show examples
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Show example JSON formats and exit"
    )
    parser.add_argument(
        "--format",
        choices=list(EXAMPLE_FORMATS.keys()),
        help="Show specific format example"
    )

    # Single result
    parser.add_argument("--vid", help="Generate single result for this VID")
    parser.add_argument("--ok", action="store_true", help="Mark as successful (for single result)")
    parser.add_argument("--msg", help="Result message")
    parser.add_argument("--out", help="Command output")
    parser.add_argument("--err", help="Error message")

    # Batch mode
    parser.add_argument("--batch", help="Comma-separated list of VIDs")
    parser.add_argument("--all-ok", action="store_true", help="Mark all as successful (batch mode)")

    # From CSV
    parser.add_argument("--from-csv", help="Generate from CSV file (vid,ok,msg,out,err)")

    # From CKL
    parser.add_argument("--from-ckl", help="Extract VIDs from CKL file")
    parser.add_argument("--status", help="Filter CKL by status (Open, Not_Reviewed, etc.)")
    parser.add_argument("--template-csv", help="Generate CSV template instead of JSON")

    # Multi-system
    parser.add_argument(
        "--multi-system",
        nargs="+",
        help="Generate multi-system format from multiple CSV files"
    )

    args = parser.parse_args()

    # Route to appropriate command
    if args.examples or args.format:
        return cmd_show_examples(args)
    elif args.vid:
        return cmd_generate_single(args)
    elif args.batch:
        return cmd_generate_batch(args)
    elif args.from_csv:
        return cmd_from_csv(args)
    elif args.from_ckl:
        return cmd_from_ckl(args)
    elif args.multi_system:
        return cmd_multi_system(args)
    else:
        # No arguments - run interactive mode
        interactive_mode()
        return 0


if __name__ == "__main__":
    sys.exit(main())
