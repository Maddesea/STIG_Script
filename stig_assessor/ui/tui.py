"""Terminal User Interface (TUI) for STIG Assessor.

Provides a completely headless, interactive curses-based UI for sysadmins
operating in air-gapped terminal environments.
"""

import curses
import os
import sys

from stig_assessor.core.constants import VERSION
from stig_assessor.core.logging import LOG
from stig_assessor.processor.processor import Proc


class AssessorTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.proc = Proc()
        self.current_idx = 0
        
        self.menu_items = [
            ("Convert XCCDF to CKL", self._run_convert),
            ("Merge Checklists", self._run_merge),
            ("Apply Boilerplates", self._run_boilerplate),
            ("Apply Automated Waivers", self._run_waiver),
            ("Extract Remediation Playbook", self._run_extract),
            ("Generate Compliance Stats", self._run_stats),
            ("Generate HTML Report", self._run_html),
            ("Generate Fleet Stats", self._run_fleet),
            ("Exit", self._exit_app)
        ]

    def _safe_addstr(self, y: int, x: int, text: str, attr: int = 0) -> None:
        """Safely write to curses, truncating if it exceeds screen bounds."""
        h, w = self.stdscr.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w:
            return
        
        # Truncate text to fit the remaining width
        max_len = w - x - 1
        if max_len <= 0:
            return
            
        safe_text = text[:max_len]
        try:
            self.stdscr.addstr(y, x, safe_text, attr)
        except curses.error:
            pass  # Ignore drawing errors at edge of screen

    def draw(self):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        title = "STIG ASSESSOR Headless Control Panel"
        self._safe_addstr(1, max(0, w // 2 - len(title) // 2), title, curses.A_BOLD | curses.A_UNDERLINE)
        
        instruction = "Use UP/DOWN arrows to navigate. Press ENTER to select."
        self._safe_addstr(3, max(0, w // 2 - len(instruction) // 2), instruction, curses.A_DIM)

        start_y = 5
        for idx, (label, _) in enumerate(self.menu_items):
            x = max(0, w // 2 - 15)
            y = start_y + (idx * 2)
            
            if y >= h - 2:
                break # Avoid bounds
            
            if idx == self.current_idx:
                self.stdscr.attron(curses.color_pair(1))
                self._safe_addstr(y, x, f"► {label}")
                self.stdscr.attroff(curses.color_pair(1))
            else:
                self._safe_addstr(y, x, f"  {label}")

        # Status Bar
        footer = f"STIG Assessor v{VERSION} | Air-Gap Mode Active"
        self._safe_addstr(h - 1, max(0, w // 2 - len(footer) // 2), footer, curses.A_REVERSE)

        self.stdscr.refresh()

    def run(self):
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.curs_set(0)  # Hide cursor

        while True:
            self.draw()
            key = self.stdscr.getch()

            if key == curses.KEY_RESIZE:
                continue
            elif key == curses.KEY_UP and self.current_idx > 0:
                self.current_idx -= 1
            elif key == curses.KEY_DOWN and self.current_idx < len(self.menu_items) - 1:
                self.current_idx += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                action = self.menu_items[self.current_idx][1]
                action()

    def _prompt_input(self, prompt: str) -> str:
        h, w = self.stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)
        self.stdscr.clear()
        
        prompt_x = max(0, w//2 - len(prompt)//2 - 10)
        self._safe_addstr(h//2, prompt_x, f"{prompt}: ")
        self.stdscr.refresh()
        
        try:
            input_val = self.stdscr.getstr(h//2, min(w-2, prompt_x + len(prompt) + 2), 256)
            res = input_val.decode("utf-8").strip()
        except curses.error:
            res = ""
        
        curses.noecho()
        curses.curs_set(0)
        return res

    def _show_msg(self, title: str, msg: str):
        h, w = self.stdscr.getmaxyx()
        self.stdscr.clear()
        self._safe_addstr(h//2 - 2, max(0, w//2 - len(title)//2), title, curses.A_BOLD)
        self._safe_addstr(h//2, max(0, w//2 - len(msg)//2), msg)
        self._safe_addstr(h//2 + 2, max(0, w//2 - 12), "Press ANY KEY to return.", curses.A_DIM)
        self.stdscr.refresh()
        self.stdscr.getch()

    def _run_convert(self):
        x_path = self._prompt_input("Path to XCCDF file")
        if not os.path.exists(x_path):
            self._show_msg("Error", "File not found.")
            return
            
        c_path = self._prompt_input("Output Directory (leave blank for same folder)")
        out_path = c_path if c_path else os.path.dirname(os.path.abspath(x_path))
        
        asset_name = self._prompt_input("Target Asset Name")
        if not asset_name:
            asset_name = "ASSET"
            
            
        self.stdscr.clear()
        self._safe_addstr(2, 2, "Converting... Please wait.")
        self.stdscr.refresh()
        
        try:
            res = self.proc.xccdf_to_ckl(xccdf=x_path, out=os.path.join(out_path, f"{asset_name}_output.ckl"), asset=asset_name)
            self._show_msg("Success", f"Processed {res.get('processed', 0)} rules.")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_merge(self):
        base_path = self._prompt_input("Base Checklist Path")
        hist_path = self._prompt_input("History Checklist Path (or comma-separated list)")
        
        if not os.path.exists(base_path):
            self._show_msg("Error", "Base checklist not found.")
            return
            
        histories = [h.strip() for h in hist_path.split(',')]
        
        try:
            _ = self.proc.merge(base=base_path, histories=histories, out="merged_output.ckl")
            self._show_msg("Success", "Merged successfully. Saved to merged_output.ckl")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_boilerplate(self):
        vid = self._prompt_input("Vulnerability ID (e.g. V-12345)")
        if not vid:
            return
        status = self._prompt_input("Status (NotAFinding, Open, Not_Reviewed, Not_Applicable)")
        finding = self._prompt_input("Finding Details text")
        comment = self._prompt_input("Comments text")
        
        try:
            self.proc.boiler.set(vid, status, finding, comment)
            self._show_msg("Success", f"Stored boilerplate for {vid} -> {status}")
        except Exception as e:
            self._show_msg("Error", str(e))
        
    def _run_waiver(self):
        ckl_path = self._prompt_input("Path to target CKL file")
        vids = self._prompt_input("Comma-separated list of STIG V-IDs (e.g. V-123, V-456)").split(",")
        approver = self._prompt_input("Approver Name / Reference ID")
        reason = self._prompt_input("Reason / Justification")
        until = self._prompt_input("Valid Until (Date)")
        
        vids = [v.strip() for v in vids if v.strip()]
        
        try:
            res = self.proc.apply_waivers(ckl_path, ckl_path, vids, approver, reason, until)
            self._show_msg("Success", f"Applied waivers to {res['updates']} findings.")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_extract(self):
        x_path = self._prompt_input("Path to STIG XCCDF XML")
        out_dir = self._prompt_input("Output Directory")
        
        try:
            os.makedirs(out_dir, exist_ok=True)
            from stig_assessor.remediation.extractor import FixExt
            extractor = FixExt(x_path)
            extractor.extract()
            extractor.to_json(os.path.join(out_dir, "fixes.json"))
            extractor.to_csv(os.path.join(out_dir, "fixes.csv"))
            extractor.to_bash(os.path.join(out_dir, "remediate.sh"))
            extractor.to_powershell(os.path.join(out_dir, "remediate.ps1"), enable_rollbacks=False)
            extractor.to_ansible(os.path.join(out_dir, "remediate.yml"))
            self._show_msg("Success", "Playbooks generated successfully.")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_stats(self):
        ckl_path = self._prompt_input("Path to CKL file")
        if not os.path.exists(ckl_path):
            self._show_msg("Error", "File not found.")
            return

        try:
            out_file = ckl_path + ".stats.txt"
            stats = self.proc.generate_stats(ckl_path, output_format="text")
            with open(out_file, "w") as f:
                f.write(stats)
            self._show_msg("Success", f"Stats generated to {out_file}")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_html(self):
        ckl_path = self._prompt_input("Path to CKL/CKLB file")
        if not os.path.exists(ckl_path):
            self._show_msg("Error", "File not found.")
            return

        try:
            from stig_assessor.processor.html_report import generate_html_report
            out_file = os.path.splitext(ckl_path)[0] + ".html"
            generate_html_report(ckl_path, out_file)
            self._show_msg("Success", f"HTML Report generated at {out_file}")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_fleet(self):
        target_dir = self._prompt_input("Path to Directory or ZIP containing CKLs")
        if not os.path.exists(target_dir):
            self._show_msg("Error", "Path not found.")
            return

        try:
            from stig_assessor.processor.fleet_stats import FleetStats
            import json
            fs = FleetStats()
            if os.path.isfile(target_dir) and target_dir.lower().endswith(".zip"):
                stats = fs.process_zip(target_dir)
            else:
                stats = fs.process_directory(target_dir)
            
            out_file = os.path.join(os.path.dirname(os.path.abspath(target_dir)), "fleet_stats.json")
            with open(out_file, "w") as f:
                json.dump(stats, f, indent=2)
            
            self._show_msg("Success", f"Fleet stats analyzed {stats['total_assets']} assets. Saved to {out_file}")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _exit_app(self):
        sys.exit(0)


def start_tui():
    """Bootstrap wrapper for the curses UI."""
    try:
        curses.wrapper(lambda stdscr: AssessorTUI(stdscr).run())
    except Exception as e:
        LOG.e(f"Fatal TUI failure: {e}")
        sys.exit(1)
