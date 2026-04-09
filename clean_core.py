import re
from pathlib import Path

def clean_core():
    core_path = Path(r"c:\Users\Madden\Desktop\_Personal_GitHub_Repos\STIG_Script\stig_assessor\ui\gui\core.py")
    if not core_path.exists():
        print("Error: core.py not found at", core_path)
        return

    content = core_path.read_text(encoding="utf-8")

    # Patterns to remove
    patterns = [
        # Match all tabs definitions: _tab_create to the end of _tab_drift
        r"(?s)        def _tab_create\(self, frame\):.*?def _tab_repair\(self, frame\):",
        r"(?s)        def _tab_repair\(self, frame\):.*?def _do_verify_integrity\(self\):",
        # Match all specific actions from _do_verify_integrity to the end
        r"(?s)        def _do_verify_integrity\(self\):.*?def _tab_about\(self, frame\):",  # Wait, wait, don't delete _tab_about if it exists!
    ]

    # Let's do it method by method via exact regex match
    methods_to_remove = [
        "_tab_create", "_tab_merge", "_tab_extract", "_tab_results", "_add_results_files", "_paste_results_files", 
        "_remove_results_file", "_clear_results_files", "_do_results", "_tab_evidence", "_tab_validate", "_tab_compare", 
        "_tab_analytics", "_tab_drift", "_tab_repair", "_tab_batch", "_tab_boilerplates",
        "_browse_create_xccdf", "_browse_create_out", "_browse_merge_base", "_browse_merge_out", "_browse_extract_xccdf", 
        "_browse_extract_out", "_browse_results_json", "_browse_results_ckl", "_browse_results_out", "_browse_validate_ckl",
        "_do_create", "_add_merge_hist", "_remove_merge_hist", "_clear_merge_hist", "_do_merge", "_do_extract", 
        "_import_evidence", "_export_evidence", "_package_evidence", "_import_evidence_package", "_do_validate",
        "_bp_refresh_vids", "_on_bp_vid_select", "_on_bp_status_select", "_load_bp_editor", "_bp_add_vid", "_bp_save", "_bp_delete",
        "_do_verify_integrity", "_do_repair", "_do_batch_convert", "_do_diff_tab", "_do_stats_tab", "_do_track_ckl", "_do_show_drift",
        "_refresh_evidence_summary"
    ]

    for method in methods_to_remove:
        # Regex to match method signature and its body (indented by 8 spaces, until the next '        def ')
        pattern = re.compile(r"        def " + method + r"\(self.*?\):\n(?:(?: {12,}.*\n)|(?: {8,}\w.*\n)|(?:\s*\n))*", re.DOTALL)
        content, count = pattern.subn("", content)
        if count:
            print(f"Removed method: {method}")

    # Write back
    core_path.write_text(content, encoding="utf-8")
    print("\nCleanup complete! Dead code eliminated successfully.")

if __name__ == "__main__":
    clean_core()
