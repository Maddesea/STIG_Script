"""Terminal User Interface (TUI) for STIG Assessor.

Provides a completely headless, interactive curses-based UI for sysadmins
operating in air-gapped terminal environments.
"""

import curses
import os
import sys

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
            ("Exit", self._exit_app)
        ]

    def draw(self):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        title = "STIG ASSESSOR Headless Control Panel"
        self.stdscr.addstr(1, w // 2 - len(title) // 2, title, curses.A_BOLD | curses.A_UNDERLINE)
        
        instruction = "Use UP/DOWN arrows to navigate. Press ENTER to select."
        self.stdscr.addstr(3, w // 2 - len(instruction) // 2, instruction, curses.A_DIM)

        start_y = 6
        for idx, (label, _) in enumerate(self.menu_items):
            x = w // 2 - 15
            y = start_y + (idx * 2)
            
            if idx == self.current_idx:
                self.stdscr.attron(curses.color_pair(1))
                self.stdscr.addstr(y, x, f"► {label}")
                self.stdscr.attroff(curses.color_pair(1))
            else:
                self.stdscr.addstr(y, x, f"  {label}")

        self.stdscr.refresh()

    def run(self):
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.curs_set(0)  # Hide cursor

        while True:
            self.draw()
            key = self.stdscr.getch()

            if key == curses.KEY_UP and self.current_idx > 0:
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
        self.stdscr.addstr(h//2, w//2 - len(prompt)//2 - 10, f"{prompt}: ")
        self.stdscr.refresh()
        
        res = self.stdscr.getstr(h//2, w//2 - len(prompt)//2 + 2, 256).decode("utf-8").strip()
        
        curses.noecho()
        curses.curs_set(0)
        return res

    def _show_msg(self, title: str, msg: str):
        h, w = self.stdscr.getmaxyx()
        self.stdscr.clear()
        self.stdscr.addstr(h//2 - 2, w//2 - len(title)//2, title, curses.A_BOLD)
        self.stdscr.addstr(h//2, w//2 - len(msg)//2, msg)
        self.stdscr.addstr(h//2 + 2, w//2 - 12, "Press ANY KEY to return.", curses.A_DIM)
        self.stdscr.refresh()
        self.stdscr.getch()

    def _run_convert(self):
        x_path = self._prompt_input("Path to XCCDF file")
        if not os.path.exists(x_path):
            self._show_msg("Error", "File not found.")
            return
            
        c_path = self._prompt_input("Output Directory (leave blank for same folder)")
        out_path = c_path if c_path else os.path.dirname(os.path.abspath(x_path))
        
        self.stdscr.clear()
        self.stdscr.addstr(2, 2, "Converting... Please wait.")
        self.stdscr.refresh()
        
        try:
            res = self.proc.xccdf_to_ckl(x_path, out_file=os.path.join(out_path, "output.ckl"))
            self._show_msg("Success", f"Converted {len(res.get('vulnerabilities', []))} rules.")
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
            _ = self.proc.merge(base_path, histories, out_file="merged_output.ckl")
            self._show_msg("Success", "Merged successfully. Saved to merged_output.ckl")
        except Exception as e:
            self._show_msg("Error", str(e))

    def _run_boilerplate(self):
        self._show_msg("Boilerplate Ops", "Please use the CLI or Web UI for complete boilerplate management.")
        
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
            _ = self.proc.extract_fixes(x_path, out_dir, ansible=True)
            self._show_msg("Success", "Playbooks generated.")
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
