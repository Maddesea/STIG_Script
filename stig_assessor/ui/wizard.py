"""Interactive CLI Wizard for STIG Assessor."""

import os
import sys
from typing import Callable, List, Tuple
from pathlib import Path

from stig_assessor.core.constants import VERSION
from stig_assessor.core.logging import format_color
from stig_assessor.processor.processor import Proc

class InteractiveWizard:
    def __init__(self):
        self.proc = Proc()
        self.running = True

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _print_header(self):
        self._clear_screen()
        print(format_color("=" * 60, "blue"))
        print(format_color(f"  STIG ASSESSOR - INTERACTIVE WIZARD v{VERSION}", "cyan"))
        print(format_color("=" * 60, "blue"))
        print()

    def _prompt(self, message: str, required: bool = True) -> str:
        while True:
            val = input(format_color(f"? {message}: ", "yellow")).strip()
            if not val and required:
                print(format_color("This field is required.", "red"))
                continue
            return val

    def _menu(self, title: str, options: List[Tuple[str, Callable]]) -> None:
        self._print_header()
        print(format_color(title, "green"))
        print("-" * 60)
        
        for idx, (label, _) in enumerate(options, 1):
            print(f" {format_color(str(idx), 'cyan')}. {label}")
            
        print(f" {format_color('0', 'cyan')}. Exit")
        print("-" * 60)
        
        while True:
            choice = input(format_color("Select an option: ", "yellow")).strip()
            if choice == '0':
                self.running = False
                return
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    options[idx][1]()
                    return
                else:
                    print(format_color("Invalid selection.", "red"))
            except ValueError:
                print(format_color("Please enter a number.", "red"))

    def _pause(self):
        print()
        input(format_color("Press Enter to continue...", "blue"))

    # Actions
    def build_checklist(self):
        self._print_header()
        print(format_color("=== Build Checklist ===", "green"))
        xccdf = self._prompt("Path to DISA XCCDF XML")
        if not os.path.isfile(xccdf):
            print(format_color("Error: File not found.", "red"))
            self._pause()
            return
            
        asset = self._prompt("Target Asset Name", required=True)
        out_dir = self._prompt("Output Directory (leave empty to use current)", required=False)
        apply_bp = self._prompt("Apply boilerplate templates? (y/n)", required=True).lower().startswith('y')
        
        if not out_dir:
            out_dir = "."
            
        out_file = str(Path(out_dir) / f"{asset}_output.ckl")
        
        print(format_color(f"\nGenerating {out_file}...", "cyan"))
        try:
            res = self.proc.xccdf_to_ckl(xccdf, out_file, asset=asset, apply_boilerplate=apply_bp)
            print(format_color(f"\nSuccess! Processed {res.get('processed', 0)} rules.", "green"))
        except Exception as e:
            print(format_color(f"\nError: {e}", "red"))
        
        self._pause()

    def merge_checklists(self):
        self._print_header()
        print(format_color("=== Merge Checklists ===", "green"))
        base = self._prompt("Path to Base CKL/CKLB")
        hists_str = self._prompt("Paths to History CKL/CKLBs (comma-separated)")
        
        hists = [h.strip() for h in hists_str.split(",") if h.strip()]
        out_file = self._prompt("Output merged file path")
        
        print(format_color(f"\nMerging {len(hists)} history files into {out_file}...", "cyan"))
        try:
            res = self.proc.merge(base, hists, out_file)
            print(format_color(f"\nSuccess! Updated {res.get('updated', 0)} findings.", "green"))
        except Exception as e:
            print(format_color(f"\nError: {e}", "red"))
            
        self._pause()

    def extract_playbooks(self):
        self._print_header()
        print(format_color("=== Extract Remediation Playbooks ===", "green"))
        xccdf = self._prompt("Path to DISA XCCDF XML")
        out_dir = self._prompt("Output Directory")
        
        try:
            os.makedirs(out_dir, exist_ok=True)
            from stig_assessor.remediation.extractor import FixExt
            print(format_color(f"\nExtracting scripts to {out_dir}...", "cyan"))
            
            extractor = FixExt(xccdf)
            extractor.extract()
            # Generate all default formats (and our new HTML Playbook if it exists)
            extractor.to_bash(os.path.join(out_dir, "remediate.sh"))
            extractor.to_powershell(os.path.join(out_dir, "remediate.ps1"), enable_rollbacks=False)
            extractor.to_ansible(os.path.join(out_dir, "remediate.yml"))
            
            # Use safe module reload/call logic since we'll build HTML playbook soon
            try:
                from stig_assessor.remediation.html_playbook import generate_html_playbook
                generate_html_playbook(extractor, os.path.join(out_dir, "remediation_playbook.html"))
            except ImportError:
                pass

            print(format_color("\nSuccess! Playbooks generated.", "green"))
        except Exception as e:
            print(format_color(f"\nError: {e}", "red"))
            
        self._pause()

    def compare_checklists(self):
        self._print_header()
        print(format_color("=== Compare Checklists (Diff) ===", "green"))
        ckl1 = self._prompt("Path to Baseline CKL (Before)")
        ckl2 = self._prompt("Path to Target CKL (After)")
        
        print(format_color("\nComparing checklists...", "cyan"))
        try:
            res = self.proc.diff(ckl1, ckl2)
            print(format_color(f"\nDifferences found: {len(res.get('changes', []))}", "yellow"))
            
            try:
                from stig_assessor.processor.html_diff import generate_html_diff
                out_html = Path(ckl1).with_name(f"{Path(ckl1).stem}_diff.html")
                generate_html_diff(ckl1, ckl2, str(out_html))
                print(format_color(f"Graphical HTML rendering saved to: {out_html}", "green"))
            except ImportError:
                import json
                print(format_color(json.dumps(res, indent=2), "green"))
                
        except Exception as e:
            print(format_color(f"\nError: {e}", "red"))
            
        self._pause()

    def run(self):
        options = [
            ("Build new Checklist from Benchmark", self.build_checklist),
            ("Merge Historical Checklists", self.merge_checklists),
            ("Extract Remediation Playbooks", self.extract_playbooks),
            ("Compare Checklists (Graphical Diff)", self.compare_checklists),
        ]
        
        while self.running:
            self._menu("Main Menu", options)

def launch_wizard():
    wizard = InteractiveWizard()
    try:
        wizard.run()
    except KeyboardInterrupt:
        print("\n\nExiting Wizard.")
        sys.exit(0)
