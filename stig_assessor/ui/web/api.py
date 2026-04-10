"""Web API interface for STIG Assessor."""

import base64
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List

import xml.etree.ElementTree as ET
from stig_assessor.core.state import GLOBAL_STATE
from stig_assessor.evidence.manager import EVIDENCE
from stig_assessor.processor.processor import Proc
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro
from stig_assessor.xml.utils import XmlUtils


def _decode_to_temp(b64_str: str, suffix: str) -> Path:
    if not isinstance(b64_str, str) or not b64_str.strip():
        raise ValueError(f"Missing or invalid file content payload for {suffix}")
    try:
        # Normalize and fix padding if necessary for some non-standard b64 sources
        b64_str = b64_str.strip()
        padding = len(b64_str) % 4
        if padding:
            b64_str += "=" * (4 - padding)
        content_bytes = base64.b64decode(b64_str)
    except Exception as e:
        raise ValueError(f"Malformed base64 encoding: {e}")

    tf = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    path = Path(tf.name)
    tf.write(content_bytes)
    tf.close()
    GLOBAL_STATE.add_temp(path)
    return path


def _encode_from_temp(path: Path) -> str:
    if path.exists():
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    raise FileNotFoundError("Output file was not generated.")


def _cleanup_paths(paths: List[Path]) -> None:
    for path in paths:
        if path and path.exists():
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink()
                GLOBAL_STATE.remove_temp(path)
            except OSError:
                pass


def handle_ping(payload: dict) -> dict:
    return {"status": "ok", "message": "pong"}


def handle_xccdf_to_ckl(payload: dict) -> dict:
    """Handle conversion from XCCDF to CKL."""
    content_b64 = payload.get("xccdf_b64", "") or payload.get("content_b64", "")
    out_ext = payload.get("out_ext", ".ckl")
    filename = payload.get("filename", "upload.ckl")

    # Force extension replacement if it ends in .xml or something else
    filename = str(Path(filename).with_suffix(out_ext))

    asset = payload.get("asset", "ASSET")
    ip = payload.get("ip", "")
    mac = payload.get("mac", "")
    role = payload.get("role", "None")

    xccdf_path = None
    ckl_path = None

    try:
        xccdf_path = _decode_to_temp(content_b64, ".xml")
        with tempfile.NamedTemporaryFile(suffix=out_ext, delete=False) as tf_ckl:
            ckl_path = Path(tf_ckl.name)
        GLOBAL_STATE.add_temp(ckl_path)

        proc = Proc()
        result = proc.xccdf_to_ckl(
            xccdf=xccdf_path,
            out=ckl_path,
            asset=asset,
            ip=ip,
            mac=mac,
            role=role,
            dry=False,
        )

        out_b64 = _encode_from_temp(ckl_path)

        return {
            "status": "success",
            "message": f"Processed {result.get('processed', 0)} VULNs.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename,
                "processed": result.get("processed", 0),
                "skipped": result.get("skipped", 0),
                "errors": result.get("errors", []),
            },
        }
    finally:
        _cleanup_paths([xccdf_path, ckl_path])


def handle_apply_results(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    json_b64 = payload.get("results_b64", "") or payload.get("json_b64", "")
    filename = payload.get("filename", "updated.ckl")
    results_filename = payload.get("results_filename", "results.json")
    details_mode = payload.get("details_mode", "prepend")
    comment_mode = payload.get("comment_mode", "prepend")

    ckl_path = None
    json_path = None
    out_path = None

    # Use the actual file extension so CSV results are handled correctly
    results_ext = Path(results_filename).suffix or ".json"

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        json_path = _decode_to_temp(json_b64, results_ext)

        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)

        proc = FixResPro()
        imported, skipped = proc.load(json_path)

        if imported == 0 and not skipped:
            raise ValueError("No valid results loaded from JSON")

        result = proc.update_ckl(
            ckl_path,
            out_path,
            details_mode=details_mode,
            comment_mode=comment_mode,
        )

        out_b64 = _encode_from_temp(out_path)

        return {
            "status": "success",
            "message": f"Applied {imported} results.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename,
                "imported": imported,
                "skipped": skipped,
                "updated": result.get("updated", 0),
                "not_found": result.get("not_found", 0),
            },
        }
    finally:
        _cleanup_paths([ckl_path, json_path, out_path])


def handle_merge_ckls(payload: dict) -> dict:
    base_b64 = payload.get("base_b64", "")
    histories_b64 = payload.get("histories_b64", [])
    filename = payload.get("filename", "merged.ckl")
    preserve_history = payload.get("preserve_history", True)

    # Advanced merge options
    use_advanced = payload.get("use_advanced", False)
    status_filter = payload.get("status_filter") or None
    severity_filter = payload.get("severity_filter") or None
    vid_include = payload.get("vid_include") or None
    vid_exclude = payload.get("vid_exclude") or None
    vid_list = payload.get("vid_list") or None
    details_mode = payload.get("details_mode", "keep_history")
    comments_mode = payload.get("comments_mode", "keep_history")
    status_mode = payload.get("status_mode", "keep_history")
    conflict_resolution = payload.get("conflict_resolution", "prefer_history")

    base_path = None
    hist_paths = []
    out_path = None

    try:
        base_path = _decode_to_temp(base_b64, ".ckl")
        for hist_b64 in histories_b64:
            hist_paths.append(_decode_to_temp(hist_b64, ".ckl"))

        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)

        proc = Proc()

        if use_advanced:
            result = proc.merge_advanced(
                base=base_path,
                histories=hist_paths,
                out=out_path,
                preserve_history=preserve_history,
                status_filter=status_filter,
                severity_filter=severity_filter,
                vid_include=vid_include,
                vid_exclude=vid_exclude,
                vid_list=vid_list,
                details_mode=details_mode,
                comments_mode=comments_mode,
                status_mode=status_mode,
                conflict_resolution=conflict_resolution,
            )
        else:
            result = proc.merge(
                base=base_path,
                histories=hist_paths,
                out=out_path,
                preserve_history=preserve_history,
            )

        out_b64 = _encode_from_temp(out_path)

        processed = result.get("updated", 0) + result.get("skipped", 0)

        return {
            "status": "success",
            "message": f"Merge complete. {result.get('updated', 0)} vulnerabilities updated.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename,
                "processed": processed,
                "updated": result.get("updated", 0),
                "skipped": result.get("skipped", 0),
                "filtered": result.get("filtered", 0),
                "affected_vids": result.get("affected_vids", []),
            },
        }
    finally:
        _cleanup_paths([base_path, out_path] + hist_paths)


def handle_bp_list(payload: dict) -> dict:
    proc = Proc()
    bp_data = proc.boiler.list_all()
    return {"status": "success", "data": bp_data}


def handle_bp_set(payload: dict) -> dict:
    vid = payload.get("vid", "").strip()
    status = payload.get("status", "").strip()
    finding = payload.get("finding", "").strip()
    comment = payload.get("comment", "").strip()

    if not vid or not status:
        return {"status": "error", "message": "vid and status are required"}

    proc = Proc()
    proc.boiler.set(vid, status, finding, comment)
    return {
        "status": "success",
        "message": f"Updated boilerplate for {vid} / {status}",
    }


def handle_bp_delete(payload: dict) -> dict:
    vid = payload.get("vid", "").strip()
    status = payload.get("status")

    if not vid:
        return {"status": "error", "message": "vid is required"}

    proc = Proc()
    deleted = proc.boiler.delete(vid, status)
    return {
        "status": "success" if deleted else "error",
        "message": (
            f"Deleted boilerplate for {vid}" if deleted else "Boilerplate not found"
        ),
    }


def handle_bp_export(payload: dict) -> dict:
    """Export all boilerplates as base64 JSON for download."""
    proc = Proc()
    bp_b64 = proc.boiler.export_b64()
    return {
        "status": "success",
        "data": {"bp_b64": bp_b64},
        "message": "Boilerplates exported",
    }


def handle_bp_import(payload: dict) -> dict:
    """Import boilerplates from base64 JSON (merges with existing)."""
    bp_b64 = payload.get("bp_b64", "")
    if not bp_b64:
        return {"status": "error", "message": "bp_b64 is required"}

    proc = Proc()
    count = proc.boiler.import_b64(bp_b64)
    return {
        "status": "success",
        "message": f"Imported {count} VID template(s)",
    }


def handle_bp_reset(payload: dict) -> dict:
    """Reset all boilerplates to factory defaults."""
    proc = Proc()
    proc.boiler.reset_all()
    return {
        "status": "success",
        "message": "Boilerplates reset to factory defaults",
    }

def handle_evidence_summary(payload: dict) -> dict:
    return {"status": "success", "summary": EVIDENCE.summary()}


def handle_evidence_import(payload: dict) -> dict:
    vid = payload.get("vid", "").strip()
    desc = payload.get("description", "").strip()
    cat = payload.get("category", "general").strip()
    filename = payload.get("filename", "upload.bin").strip()
    b64_content = payload.get("content_b64", "")

    if not vid:
        return {"status": "error", "message": "vid required"}

    try:
        ext = Path(filename).suffix or ".bin"
        temp_path = _decode_to_temp(b64_content, ext)
        orig_name_path = temp_path.parent / filename
        if orig_name_path.exists():
            orig_name_path.unlink()
        temp_path.rename(orig_name_path)
        GLOBAL_STATE.add_temp(orig_name_path)

        saved_path = EVIDENCE.import_file(
            vid, orig_name_path, description=desc, category=cat
        )

        _cleanup_paths([orig_name_path, temp_path])
        return {
            "status": "success",
            "message": f"Evidence imported successfully for {vid}",
            "path": str(saved_path.name),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_evidence_package(payload: dict) -> dict:
    try:
        tf = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        tf.close()
        zip_path = Path(tf.name)
        GLOBAL_STATE.add_temp(zip_path)

        EVIDENCE.package(zip_path)

        b64_out = _encode_from_temp(zip_path)
        _cleanup_paths([zip_path])
        return {
            "status": "success",
            "package_b64": b64_out,
            "filename": "evidence_package.zip",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_extract_fixes(payload: dict) -> dict:
    b64_content = payload.get("b64_content", "") or payload.get("content_b64", "")
    filename = payload.get("filename", "upload.xml")
    
    ckl_b64 = payload.get("ckl_b64", "")
    status_filter = payload.get("status_filter", ["Open", "Not_Reviewed"])

    in_path = None
    ckl_path = None
    zip_path = None
    dir_path = Path(tempfile.mkdtemp())
    GLOBAL_STATE.add_temp(dir_path)

    enable_rollbacks = payload.get("enable_rollbacks", False)

    try:
        ext = Path(filename).suffix
        in_path = _decode_to_temp(b64_content, ext)

        if ckl_b64:
            ckl_path = _decode_to_temp(ckl_b64, ".ckl")

        extractor = FixExt(str(in_path), checklist=ckl_path)

        severity_filter = payload.get("severity_filter") or None
        vid_include_regex = payload.get("vid_include_regex") or None
        vid_exclude_regex = payload.get("vid_exclude_regex") or None
        vid_list = payload.get("vid_include") # This is often passed as 'vid_include' array from UI
        
        extractor.extract(
            status_filter=status_filter if ckl_path else None,
            severity_filter=severity_filter,
            vid_list=vid_list if isinstance(vid_list, list) else None,
            vid_include=vid_include_regex,
            vid_exclude=vid_exclude_regex,
        )

        extractor.to_json(dir_path / "fixes.json")
        extractor.to_csv(dir_path / "fixes.csv")
        extractor.to_bash(dir_path / "remediate.sh", dry_run=payload.get("dry_run", False))
        extractor.to_powershell(
            dir_path / "remediate.ps1",
            dry_run=payload.get("dry_run", False),
            enable_rollbacks=enable_rollbacks,
        )
        
        # Automated Evidence Gathering
        if payload.get("do_evidence", True):
            extractor.to_evidence_bash(dir_path / "gather_evidence.sh")
            extractor.to_evidence_powershell(dir_path / "GatherEvidence.ps1")

        # Generate HTML playbook by default now
        try:
            from stig_assessor.remediation.html_playbook import generate_html_playbook
            generate_html_playbook(extractor, dir_path / "remediation_playbook.html")
        except Exception:
            pass

        if payload.get("do_ansible", True):
            extractor.to_ansible(
                dir_path / "remediate.yml", dry_run=payload.get("dry_run", False)
            )

        zip_path_str = shutil.make_archive(
            str(dir_path) + "_archive", "zip", str(dir_path)
        )
        zip_path = Path(zip_path_str)
        GLOBAL_STATE.add_temp(zip_path)

        b64_out = _encode_from_temp(zip_path)

        return {
            "status": "success",
            "package_b64": b64_out,
            "filename": filename.replace(ext, "_fixes.zip"),
            "stats": extractor.stats_summary(),
        }
    finally:
        _cleanup_paths([in_path, ckl_path, zip_path])
        try:
            shutil.rmtree(dir_path)
        except Exception:
            pass


def handle_extract_preview(payload: dict) -> dict:
    """Quick preview: extract in memory and return a summary without writing files."""
    b64_content = payload.get("b64_content", "") or payload.get("content_b64", "")
    filename = payload.get("filename", "upload.xml")
    ckl_b64 = payload.get("ckl_b64", "")
    status_filter = payload.get("status_filter", ["Open", "Not_Reviewed"])

    in_path = None
    ckl_path = None

    try:
        ext = Path(filename).suffix
        in_path = _decode_to_temp(b64_content, ext)

        if ckl_b64:
            ckl_path = _decode_to_temp(ckl_b64, ".ckl")

        extractor = FixExt(str(in_path), checklist=ckl_path)

        severity_filter = payload.get("severity_filter") or None
        vid_include_regex = payload.get("vid_include_regex") or None
        vid_exclude_regex = payload.get("vid_exclude_regex") or None
        
        extractor.extract(
            status_filter=status_filter if ckl_path else None,
            severity_filter=severity_filter,
            vid_include=vid_include_regex,
            vid_exclude=vid_exclude_regex,
        )

        results = []
        for f in extractor.fixes:
            has_cmd = "Both" if f.fix_command and f.check_command else "Fix" if f.fix_command else "Check" if f.check_command else "None"
            results.append({
                "vid": f.vid,
                "severity": f.severity,
                "platform": f.platform,
                "has_cmd": has_cmd,
                "fix_text": f.fix_text or "",
                "check_text": f.check_text or "",
                "fix_command": f.fix_command or "",
                "check_command": f.check_command or ""
            })

        return {
            "status": "success",
            "data": {
                "fixes": results,
                "stats": extractor.stats_summary(),
            }
        }
    finally:
        _cleanup_paths([in_path, ckl_path])


def handle_diff(payload: dict) -> dict:
    ckl1_b64 = payload.get("ckl1_b64", "")
    ckl2_b64 = payload.get("ckl2_b64", "")
    ckl1_path = None
    ckl2_path = None

    try:
        ckl1_path = _decode_to_temp(ckl1_b64, ".ckl")
        ckl2_path = _decode_to_temp(ckl2_b64, ".ckl")

        proc = Proc()
        raw = proc.diff(str(ckl1_path), str(ckl2_path), output_format="json")

        # Also get a text-formatted summary for display
        text_result = proc.diff(str(ckl1_path), str(ckl2_path), output_format="summary")

        summary = raw.get("summary", {})

        # Normalise keys the frontend expects
        diff_data = dict(raw)
        diff_data["total_vulnerabilities"] = summary.get("total_in_baseline", 0)
        diff_data["changes_count"] = summary.get("changed", 0)
        diff_data["formatted_text"] = text_result.get("formatted_text", "")
        diff_data["only_in_baseline_count"] = summary.get("only_in_baseline", 0)
        diff_data["only_in_comparison_count"] = summary.get("only_in_comparison", 0)
        diff_data["unchanged_count"] = summary.get("unchanged", 0)

        return {"status": "success", "diff_data": diff_data}
    finally:
        _cleanup_paths([ckl1_path, ckl2_path])


def handle_stats(payload: dict) -> dict:
    """Generate stats with a response shape the frontend can consume.

    The Proc.generate_stats() method returns keys like ``by_status`` and
    ``by_severity``, but the web frontend historically expected
    ``status_counts`` and ``findings_details``.  This handler bridges the
    gap by building both the aggregate counts *and* the per-finding detail
    rows the Analytics table needs.
    """
    ckl_b64 = payload.get("ckl_b64", "")
    ckl_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        proc = Proc()

        # Get the raw JSON stats from the processor
        raw = proc.generate_stats(str(ckl_path), output_format="json")
        html_report = proc.generate_stats(str(ckl_path), output_format="html")

        # Build the status_counts dict the frontend expects
        by_status = raw.get("by_status", {})
        status_counts = {
            "NotAFinding": by_status.get("NotAFinding", 0),
            "Open": by_status.get("Open", 0),
            "Not_Applicable": by_status.get("Not_Applicable", 0),
            "Not_Reviewed": by_status.get("Not_Reviewed", 0),
        }

        try:
            findings_details = _build_analytics_details(proc, ckl_path)
        except Exception as e:
            from stig_assessor.core.logging import LOG
            LOG.e(f"Failed to extract per-finding detail rows: {e}")

        return {
            "status": "success",
            "stats_data": {
                "status_counts": status_counts,
                "findings_details": findings_details,
                "by_severity": raw.get("by_severity", {}),
                "by_status_and_severity": raw.get("by_status_and_severity", {}),
                "total_vulns": raw.get("total_vulns", 0),
                "reviewed": raw.get("reviewed", 0),
                "completion_pct": round(raw.get("completion_pct", 0), 1),
                "compliance_pct": round(raw.get("compliance_pct", 0), 1),
                "compliant": raw.get("compliant", 0),
                "file": raw.get("file", ""),
                "generated": raw.get("generated", ""),
                "html_report": html_report,
            },
        }
    finally:
        _cleanup_paths([ckl_path])


def _build_analytics_details(proc: Proc, ckl_path: Path) -> List[Dict[str, str]]:
    """Helper to extract flat finding detail rows for the frontend Analytics table."""
    details = []
    tree = proc._load_file_as_xml(ckl_path)
    root = tree.getroot()
    vulns = proc._extract_vuln_data(root)
    for vid, vdata in vulns.items():
        details.append({
            "vid": vid,
            "status": vdata.get("status", "Not_Reviewed"),
            "severity": vdata.get("severity", "medium"),
            "details": vdata.get("finding_details", ""),
            "rule_title": vdata.get("rule_title", ""),
            "check_content": vdata.get("check_content", ""),
            "fix_text": vdata.get("fix_text", ""),
            "comments": vdata.get("comments", ""),
        })
    return details


def handle_fleet_stats(payload: dict) -> dict:
    """Generate fleet statistics from a ZIP file containing multiple checklists."""
    zip_b64 = payload.get("zip_b64", "")
    zip_path = None

    try:
        if not zip_b64:
            raise ValueError("No ZIP payload provided.")

        zip_path = _decode_to_temp(zip_b64, ".zip")

        from stig_assessor.processor.fleet_stats import FleetStats

        fs = FleetStats()
        fleet_data = fs.process_zip(zip_path)

        return {"status": "success", "fleet_data": fleet_data}
    finally:
        _cleanup_paths([zip_path])


def handle_track_ckl(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    ckl_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        proc = Proc()
        if not proc.history.db:
            return {
                "status": "error",
                "message": "SQLite History DB is not initialized.",
            }

        tree = proc._load_file_as_xml(ckl_path)
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
            asset_name, "web_import.ckl", "STIG", results
        )
        return {
            "status": "success",
            "message": f"Successfully ingested {len(results)} findings into database.",
            "data": {"assessment_id": db_id, "asset_name": asset_name},
        }
    finally:
        _cleanup_paths([ckl_path])


def handle_show_drift(payload: dict) -> dict:
    asset_name = payload.get("asset_name", "").strip()
    if not asset_name:
        return {"status": "error", "message": "Asset name is required"}

    proc = Proc()
    if not proc.history.db:
        return {
            "status": "error",
            "message": "SQLite History DB is not initialized.",
        }

    with proc.history.db._get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM assessments WHERE asset_name = ? ORDER BY timestamp DESC LIMIT 1",
            (asset_name,),
        )
        row = cursor.fetchone()
        if not row:
            return {
                "status": "error",
                "message": f"No assessments found for asset '{asset_name}'",
            }
        latest_id = row[0]

    drift = proc.history.db.get_drift(asset_name, latest_id)
    if "error" in drift:
        return {"status": "error", "message": drift["error"]}

    return {"status": "success", "data": drift}


def handle_list_assets(payload: dict) -> dict:
    """List all tracked asset names from the SQLite history DB."""
    proc = Proc()
    if not proc.history.db:
        return {
            "status": "error",
            "message": "SQLite History DB is not initialized.",
        }

    try:
        with proc.history.db._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT DISTINCT asset_name FROM assessments ORDER BY asset_name"
            )
            assets = [row[0] for row in cursor.fetchall()]
        return {"status": "success", "data": {"assets": assets}}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_validate(payload: dict) -> dict:
    """Validate a CKL file for STIG Viewer compatibility."""
    ckl_b64 = payload.get("ckl_b64", "")
    ckl_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        proc = Proc()
        ok, errors, warnings, info = proc.validator.validate(ckl_path)

        return {
            "status": "success",
            "data": {
                "valid": ok,
                "errors": errors,
                "warnings": warnings,
                "info": info,
                "error_count": len(errors),
                "warning_count": len(warnings),
            },
        }
    finally:
        _cleanup_paths([ckl_path])


def handle_repair(payload: dict) -> dict:
    """Repair a corrupted CKL file."""
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "repaired.ckl")
    ckl_path = None
    out_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)

        proc = Proc()
        result = proc.repair(ckl_path, out_path)

        out_b64 = _encode_from_temp(out_path)

        return {
            "status": "success",
            "message": f"Applied {result.get('repairs', 0)} repairs.",
            "data": {
                "ckl_b64": out_b64,
                "filename": (
                    filename.replace(".ckl", "_repaired.ckl")
                    if ".ckl" in filename
                    else filename + "_repaired.ckl"
                ),
                "repairs": result.get("repairs", 0),
                "details": result.get("details", []),
            },
        }
    finally:
        _cleanup_paths([ckl_path, out_path])


def handle_verify_integrity(payload: dict) -> dict:
    """Verify checklist integrity with checksums and validation."""
    ckl_b64 = payload.get("ckl_b64", "")
    ckl_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        proc = Proc()
        result = proc.verify_integrity(ckl_path)

        return {"status": "success", "data": result}
    finally:
        _cleanup_paths([ckl_path])


def handle_export_poam(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "upload.ckl")
    
    ckl_path = None
    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        proc = Proc()
        csv_str = proc.export_poam(ckl_path)
        
        # Convert CSV string to base64 so it downloads nicely
        import base64
        csv_b64 = base64.b64encode(csv_str.encode("utf-8")).decode("utf-8")
        
        return {
            "status": "success",
            "message": "POAM generated successfully",
            "data": {
                "poam_b64": csv_b64,
                "filename": filename.replace(".ckl", "_poam.csv") if ".ckl" in filename else f"{filename}_poam.csv"
            }
        }
    finally:
        _cleanup_paths([ckl_path])


def handle_apply_waiver(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "upload.ckl")
    vids = payload.get("vids", [])
    approver = payload.get("approver", "")
    reason = payload.get("reason", "")
    valid_until = payload.get("valid_until", "")

    if not all([vids, approver, reason, valid_until]):
        return {"status": "error", "message": "Missing required waiver fields: vids, approver, reason, valid_until"}

    ckl_path = None
    out_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)

        proc = Proc()
        result = proc.apply_waivers(ckl_path, out_path, vids, approver, reason, valid_until)
        out_b64 = _encode_from_temp(out_path)

        return {
            "status": "success",
            "message": f"Successfully applied waivers to {result.get('updates', 0)} vulnerabilities.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename.replace(".ckl", "_waiver.ckl") if ".ckl" in filename else f"{filename}_waiver.ckl",
                "updates": result.get("updates", 0)
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        _cleanup_paths([ckl_path, out_path])


def handle_bulk_edit(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "upload.ckl")
    
    severity = payload.get("severity")
    # Make severity None if empty string to match backend signature
    if severity == "":
        severity = None
        
    regex_vid = payload.get("regex_vid")
    if regex_vid == "":
        regex_vid = None

    status_filter = payload.get("status_filter") or None
    new_status = payload.get("new_status")
    new_comment = payload.get("new_comment", "")
    new_finding = payload.get("new_finding", "")
    append_comment = payload.get("append_comment", False)
    append_finding = payload.get("append_finding", False)
    preview_mode = payload.get("preview", False)
    
    if not new_status:
        return {"status": "error", "message": "new_status is required"}
        
    ckl_path = None
    out_path = None
    
    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)
        
        proc = Proc()
        result = proc.bulk_edit(
            ckl_path,
            out_path,
            severity=severity,
            regex_vid=regex_vid,
            status_filter=status_filter,
            new_status=new_status,
            new_comment=new_comment,
            new_finding=new_finding,
            append_comment=append_comment,
            append_finding=append_finding,
            preview=preview_mode,
        )

        if preview_mode:
            return {
                "status": "success",
                "message": f"Preview: {result.get('updates', 0)} vulnerabilities would be affected.",
                "data": {
                    "preview": True,
                    "updates": result.get("updates", 0),
                    "affected_vids": result.get("affected_vids", []),
                },
            }

        out_b64 = _encode_from_temp(out_path)
        
        return {
            "status": "success",
            "message": f"Successfully updated {result.get('updates', 0)} vulnerabilities.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename.replace(".ckl", "_bulk_updated.ckl") if ".ckl" in filename else f"{filename}_updated.ckl",
                "updates": result.get("updates", 0),
                "affected_vids": result.get("affected_vids", []),
            }
        }
    finally:
        _cleanup_paths([ckl_path, out_path])


def handle_export_html(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "report.html")

    ckl_path = None
    out_path = None

    try:
        from stig_assessor.processor.html_report import generate_html_report
        
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)

        generate_html_report(ckl_path, out_path)

        out_b64 = _encode_from_temp(out_path)

        return {
            "status": "success",
            "message": "HTML Report generated successfully.",
            "data": {
                "html_b64": out_b64,
                "filename": filename.replace(".ckl", ".html") if ".ckl" in filename else filename,
            }
        }
    finally:
        _cleanup_paths([ckl_path, out_path])


def handle_assess_update(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "upload.ckl")
    vid = payload.get("vid", "")
    new_status = payload.get("status", "")
    new_details = payload.get("finding_details", "")
    new_comments = payload.get("comments", "")

    if not vid:
        return {"status": "error", "message": "vid is required"}
    
    ckl_path = None
    out_path = None
    
    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        
        proc = Proc()
        tree = proc._load_file_as_xml(ckl_path)
        root = tree.getroot()
        
        vulns = root.findall(".//VULN")
        updated = False
        
        for vuln in vulns:
            attrs = vuln.findall("VULN_ATTRIBUTE")
            if any(a.text == "Vuln_Num" for a in attrs):
                # Try to map attribute accurately
                # Note: VID lookup is performed below via STIG_DATA nodes which is more reliable
                vuln_vid = None
                for attr_node in vuln.findall("STIG_DATA"):
                    name_node = attr_node.find("VULN_ATTRIBUTE")
                    if name_node is not None and name_node.text == "Vuln_Num":
                        data_node = attr_node.find("ATTRIBUTE_DATA")
                        if data_node is not None:
                            vuln_vid = data_node.text
                            break
                            
                if vuln_vid == vid:
                    status_node = vuln.find("STATUS")
                    if status_node is not None:
                        status_node.text = new_status
                    else:
                        ET.SubElement(vuln, "STATUS").text = new_status
                        
                    finding_node = vuln.find("FINDING_DETAILS")
                    if finding_node is not None:
                        finding_node.text = new_details
                    else:
                        ET.SubElement(vuln, "FINDING_DETAILS").text = new_details
                        
                    comments_node = vuln.find("COMMENTS")
                    if comments_node is not None:
                        comments_node.text = new_comments
                    else:
                        ET.SubElement(vuln, "COMMENTS").text = new_comments
                        
                    updated = True
                    break
                    
        if not updated:
            return {"status": "error", "message": f"Vulnerability {vid} not found in this CKL."}
            
        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)
        
        # Write repaired checklist
        XmlUtils.indent_xml(root)
        proc._export_xml_to_file(root, out_path)
        
        out_b64 = _encode_from_temp(out_path)
        
        return {
            "status": "success",
            "message": f"Successfully updated {vid}.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename,
                "updated": 1
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        _cleanup_paths([ckl_path, out_path])


def handle_merge_preview(payload: dict) -> dict:
    """Preview merge changes without writing."""
    base_b64 = payload.get("base_b64", "")
    histories_b64 = payload.get("histories_b64", [])

    base_path = None
    hist_paths = []

    try:
        base_path = _decode_to_temp(base_b64, ".ckl")
        for hist_b64 in histories_b64:
            hist_paths.append(_decode_to_temp(hist_b64, ".ckl"))

        proc = Proc()
        result = proc.merge_preview(
            base=base_path,
            histories=hist_paths,
            status_filter=payload.get("status_filter") or None,
            severity_filter=payload.get("severity_filter") or None,
            vid_include=payload.get("vid_include") or None,
            vid_exclude=payload.get("vid_exclude") or None,
            vid_list=payload.get("vid_list") or None,
        )

        return {"status": "success", "data": result}
    finally:
        _cleanup_paths([base_path] + hist_paths)


def handle_bp_apply(payload: dict) -> dict:
    """Apply boilerplates to a CKL file."""
    ckl_b64 = payload.get("ckl_b64", "")
    filename = payload.get("filename", "upload.ckl")
    apply_mode = payload.get("apply_mode", "overwrite_empty")
    status_filter = payload.get("status_filter") or None
    severity_filter = payload.get("severity_filter") or None
    vid_include = payload.get("vid_include") or None
    date_override = payload.get("date_override") or None

    ckl_path = None
    out_path = None

    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")

        proc = Proc()
        tree = proc._load_file_as_xml(ckl_path)
        root = tree.getroot()

        result = proc.boiler.apply_to_checklist(
            root,
            status_filter=status_filter,
            severity_filter=severity_filter,
            apply_mode=apply_mode,
            vid_list=vid_include,
            date_override=date_override,
        )

        XmlUtils.indent_xml(root)

        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf:
            out_path = Path(tf.name)
        GLOBAL_STATE.add_temp(out_path)

        proc._export_xml_to_file(root, out_path)
        out_b64 = _encode_from_temp(out_path)

        return {
            "status": "success",
            "message": f"Applied boilerplates to {result.get('applied', 0)} vulnerabilities.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename,
                "applied": result.get("applied", 0),
                "skipped": result.get("skipped", 0),
                "affected_vids": result.get("affected_vids", []),
            },
        }
    finally:
        _cleanup_paths([ckl_path, out_path])


def handle_bp_preview(payload: dict) -> dict:
    """Preview boilerplate application without writing."""
    ckl_b64 = payload.get("ckl_b64", "")
    apply_mode = payload.get("apply_mode", "overwrite_empty")
    status_filter = payload.get("status_filter") or None
    severity_filter = payload.get("severity_filter") or None
    date_override = payload.get("date_override") or None

    ckl_path = None
    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        proc = Proc()
        tree = proc._load_file_as_xml(ckl_path)
        root = tree.getroot()

        result = proc.boiler.apply_to_checklist(
            root,
            status_filter=status_filter,
            severity_filter=severity_filter,
            apply_mode=apply_mode,
            date_override=date_override,
        )

        return {
            "status": "success",
            "data": {
                "applied": result.get("applied", 0),
                "skipped": result.get("skipped", 0),
                "affected_vids": result.get("affected_vids", []),
            },
        }
    finally:
        _cleanup_paths([ckl_path])


def handle_bp_search(payload: dict) -> dict:
    """Search boilerplate text."""
    query = payload.get("query", "").strip()
    if not query:
        return {"status": "error", "message": "query is required"}

    proc = Proc()
    results = proc.boiler.search(query)
    return {"status": "success", "data": {"results": results, "count": len(results)}}


def handle_bp_bulk_set(payload: dict) -> dict:
    """Bulk-set boilerplate for multiple VIDs."""
    vids = payload.get("vids", [])
    status = payload.get("status", "").strip()
    finding = payload.get("finding", "")
    comment = payload.get("comment", "")

    if not vids or not status:
        return {"status": "error", "message": "vids and status are required"}

    proc = Proc()
    count = proc.boiler.bulk_set(vids, status, finding, comment)
    return {"status": "success", "message": f"Set boilerplate for {count} VIDs"}


def handle_bp_duplicates(payload: dict) -> dict:
    """Find duplicate boilerplate templates."""
    proc = Proc()
    duplicates = proc.boiler.find_duplicates()
    return {"status": "success", "data": {"duplicates": duplicates, "count": len(duplicates)}}


def route_request(path: str, payload: dict) -> dict:
    """Route the request to the appropriate handler."""
    handlers = {
        "/api/v1/ping": handle_ping,
        "/api/v1/xccdf_to_ckl": handle_xccdf_to_ckl,
        "/api/v1/apply_results": handle_apply_results,
        "/api/v1/merge_ckls": handle_merge_ckls,
        "/api/v1/merge_preview": handle_merge_preview,
        "/api/v1/bp_list": handle_bp_list,
        "/api/v1/bp_set": handle_bp_set,
        "/api/v1/bp_delete": handle_bp_delete,
        "/api/v1/bp_export": handle_bp_export,
        "/api/v1/bp_import": handle_bp_import,
        "/api/v1/bp_reset": handle_bp_reset,
        "/api/v1/bp_apply": handle_bp_apply,
        "/api/v1/bp_preview": handle_bp_preview,
        "/api/v1/bp_search": handle_bp_search,
        "/api/v1/bp_bulk_set": handle_bp_bulk_set,
        "/api/v1/bp_duplicates": handle_bp_duplicates,
        "/api/v1/evidence/summary": handle_evidence_summary,
        "/api/v1/evidence/import": handle_evidence_import,
        "/api/v1/evidence/package": handle_evidence_package,
        "/api/v1/extract": handle_extract_fixes,
        "/api/v1/extract_preview": handle_extract_preview,
        "/api/v1/fleet_stats": handle_fleet_stats,
        "/api/v1/diff": handle_diff,
        "/api/v1/stats": handle_stats,
        "/api/v1/track_ckl": handle_track_ckl,
        "/api/v1/show_drift": handle_show_drift,
        "/api/v1/list_assets": handle_list_assets,
        "/api/v1/validate": handle_validate,
        "/api/v1/repair": handle_repair,
        "/api/v1/verify_integrity": handle_verify_integrity,
        "/api/v1/export_poam": handle_export_poam,
        "/api/v1/bulk_edit": handle_bulk_edit,
        "/api/v1/apply_waiver": handle_apply_waiver,
        "/api/v1/export_html": handle_export_html,
        "/api/v1/assess_update": handle_assess_update,
    }

    if path not in handlers:
        return {"status": "error", "message": f"Endpoint {path} not found"}

    try:
        return handlers[path](payload)
    except ValueError as ve:
        return {"status": "error", "message": f"Validation Error: {str(ve)}"}
    except Exception as e:
        import traceback

        from stig_assessor.core.logging import LOG

        LOG.e(f"API handler error for {path}: {traceback.format_exc()}")
        return {"status": "error", "message": f"Internal Error: {str(e)}"}
