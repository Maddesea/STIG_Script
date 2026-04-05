"""Web API interface for STIG Assessor."""

import base64
import tempfile
from pathlib import Path
from typing import List

from stig_assessor.core.state import GLOBAL_STATE
from stig_assessor.processor.processor import Proc
from stig_assessor.remediation.processor import FixResPro


def _decode_to_temp(b64_str: str, suffix: str) -> Path:
    if not b64_str:
        raise ValueError(f"Missing file content for {suffix}")
    try:
        content_bytes = base64.b64decode(b64_str)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {e}")
    
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
                path.unlink()
                GLOBAL_STATE.remove_temp(path)
            except Exception:
                pass


def handle_ping(payload: dict) -> dict:
    return {"status": "ok", "message": "pong"}


def handle_xccdf_to_ckl(payload: dict) -> dict:
    """Handle conversion from XCCDF to CKL."""
    content_b64 = payload.get("content_b64", "")
    filename = payload.get("filename", "upload.ckl")
    asset = payload.get("asset", "ASSET")
    ip = payload.get("ip", "")
    mac = payload.get("mac", "")
    role = payload.get("role", "None")

    xccdf_path = None
    ckl_path = None

    try:
        xccdf_path = _decode_to_temp(content_b64, ".xml")
        with tempfile.NamedTemporaryFile(suffix=".ckl", delete=False) as tf_ckl:
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
                "filename": filename.replace(".xml", ".ckl"),
                "processed": result.get("processed", 0),
                "skipped": result.get("skipped", 0),
                "errors": result.get("errors", []),
            },
        }
    finally:
        _cleanup_paths([xccdf_path, ckl_path])


def handle_apply_results(payload: dict) -> dict:
    ckl_b64 = payload.get("ckl_b64", "")
    json_b64 = payload.get("json_b64", "")
    filename = payload.get("filename", "updated.ckl")
    details_mode = payload.get("details_mode", "prepend")
    comment_mode = payload.get("comment_mode", "prepend")

    ckl_path = None
    json_path = None
    out_path = None
    
    try:
        ckl_path = _decode_to_temp(ckl_b64, ".ckl")
        json_path = _decode_to_temp(json_b64, ".json")
        
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
                "not_found": result.get("not_found", 0)
            }
        }
    finally:
        _cleanup_paths([ckl_path, json_path, out_path])


def handle_merge_ckls(payload: dict) -> dict:
    base_b64 = payload.get("base_b64", "")
    histories_b64 = payload.get("histories_b64", [])
    filename = payload.get("filename", "merged.ckl")
    preserve_history = payload.get("preserve_history", True)

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
        result = proc.merge(
            base=base_path,
            histories=hist_paths,
            out=out_path,
            preserve_history=preserve_history
        )
        
        out_b64 = _encode_from_temp(out_path)
        
        return {
            "status": "success",
            "message": "Merge complete.",
            "data": {
                "ckl_b64": out_b64,
                "filename": filename,
                "processed": result.get("processed", 0)
            }
        }
    finally:
        _cleanup_paths([base_path, out_path] + hist_paths)


def route_request(path: str, payload: dict) -> dict:
    """Route the request to the appropriate handler."""
    handlers = {
        "/api/v1/ping": handle_ping,
        "/api/v1/xccdf_to_ckl": handle_xccdf_to_ckl,
        "/api/v1/apply_results": handle_apply_results,
        "/api/v1/merge_ckls": handle_merge_ckls,
    }

    if path not in handlers:
        return {"status": "error", "message": f"Endpoint {path} not found"}

    try:
        return handlers[path](payload)
    except Exception as e:
        # Extract traceback if STIGError or general error
        return {"status": "error", "message": str(e)}
