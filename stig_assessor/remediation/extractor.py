"""Fix extraction from XCCDF benchmarks with multi-format export."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import string
import xml.etree.ElementTree as ET
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import VERSION
from stig_assessor.core.logging import LOG
from stig_assessor.exceptions import ParseError
from stig_assessor.io.file_ops import FO
from stig_assessor.xml.sanitizer import San
from stig_assessor.xml.utils import XmlUtils

from .models import Fix

EXCESSIVE_NEWLINE_RE = re.compile(r"\n\s*\n\s*\n+")
WHITESPACE_RE = re.compile(r"\s+")
SAFE_VID_RE = re.compile(r"[^A-Za-z0-9_]")


class FixExt:
    """Fix extractor with enhanced command parsing."""

    # ═══ PATTERN 1: Code blocks (markdown style) ═══
    CODE_BLOCK = re.compile(
        r"""
        ```                                      # Opening backticks
        (?:bash|sh|shell|zsh|powershell|ps1|ps|cmd|bat) # Optional language identifier
        \s*                                      # Optional whitespace
        (.*?)                                    # Capture the actual code
        ```                                      # Closing backticks
    """,
        re.DOTALL | re.IGNORECASE | re.VERBOSE,
    )

    TRIPLE_TICK = re.compile(
        r"""
        ```    # Opening backticks
        (.*?)  # Capture content lazy
        ```    # Closing backticks
    """,
        re.DOTALL | re.VERBOSE,
    )

    # ═══ PATTERN 2: Shell prompts ═══
    SHELL_PROMPT = re.compile(
        r"""
        ^              # Start of line
        (?:\$|\#|>)    # Shell prompt character ($ or # or >)
        \s*            # Optional whitespace
        (.+)           # Capture the command
    """,
        re.MULTILINE | re.VERBOSE,
    )

    POWERSHELL_PROMPT = re.compile(
        r"""
        ^                      # Start of line
        (?:
            PS\ [^>]+>         # 'PS C:\path>' format
            |                  # OR
            \w:\\[^>]*>        # 'C:\path>' format
        )
        \s*                    # Optional whitespace
        (.+)                   # Capture the command
    """,
        re.MULTILINE | re.VERBOSE,
    )

    # ═══ PATTERN 3: Bullet-style commands ═══
    BULLET_CMD = re.compile(
        r"""
        ^                       # Start of line
        (?:[-*+]|\d+\.)         # Bullet list indicator (-, *, +, or 1.)
        \s*                     # Whitespace
        (?:Run|Execute)         # Action verb
        \s*[:\-]?\s*            # Optional colon or dash
        (.+)                    # Capture the command
    """,
        re.MULTILINE | re.VERBOSE,
    )

    # ═══ PATTERN 4: Inline code ═══
    INLINE_CMD = re.compile(
        r"""
        `       # Opening backtick
        ([^`]+) # Capture content that isn't a backtick
        `       # Closing backtick
    """,
        re.VERBOSE,
    )

    # ═══ PATTERN 5: "Run the following command" blocks ═══
    RUN_CMD_PATTERN = re.compile(
        r"""
        (?:run|execute|use|enter|type)           # Action verb
        \s+(?:the\s+)?(?:following\s+)?          # Optional transition text
        (?:command|commands?)                    # Target noun
        [\s:]+                                   # Whitespace or colon
        \n                                       # Must be followed by newline
        (.+?)                                    # Capture the command payload lazy
        (?:\n\n|\Z)                              # Stop at double newline or end of string
    """,
        re.IGNORECASE | re.DOTALL | re.VERBOSE,
    )

    # ═══ PATTERN 6: Common Unix commands ═══
    UNIX_CMD_PATTERN = re.compile(
        r"""
        ^                                        # Start of line
        \s*                                      # Optional indent
        (?:sudo\s+)?                             # Optional sudo prefix
        (?:chmod|chown|chgrp|systemctl|service|  # Match common unix command binaries
        grep|sed|awk|find|rpm|yum|dnf|apt-get|
        apt|mount|umount|useradd|usermod|passwd|
        groupadd|ln|cp|mv|rm|mkdir|touch|cat|
        echo|vi|nano|gsettings|dconf|auditctl|
        ausearch|aureport|restorecon|semanage|
        setsebool|firewall-cmd)
        \s+                                      # Required whitespace
        .+                                       # Capture arguments
    """,
        re.MULTILINE | re.VERBOSE,
    )

    # ═══ PATTERN 7: PowerShell cmdlets ═══
    PS_CMDLET_PATTERN = re.compile(
        r"""
        ^                                        # Start of line
        \s*                                      # Optional indent
        (?:Set-|Get-|New-|Remove-|Add-|          # PowerShell verb prefix
        Enable-|Disable-|Test-|Invoke-)
        [A-Za-z]+                                # PowerShell noun
        (?:                                      # One or more arguments:
            \s+                                  # Separator
            -[A-Za-z]+                           # Argument flag
            \s+                                  # Separator
            [^\n]+                               # Argument payload
        )+
    """,
        re.MULTILINE | re.VERBOSE,
    )

    # ═══ PATTERN 8: Registry commands ═══
    REG_CMD_PATTERN = re.compile(
        r"""
        ^                                        # Start of line
        \s*                                      # Optional indent
        reg(?:\.exe)?                            # 'reg' or 'reg.exe'
        \s+                                      # Spacing
        (?:add|delete|query|import|export)       # Registry sub-command
        \s+                                      # Spacing
        .+                                       # the rest of the arguments
    """,
        re.MULTILINE | re.IGNORECASE | re.VERBOSE,
    )

    # ═══ PATTERN 9: File editing instructions ═══
    EDIT_FILE_PATTERN = re.compile(
        r"""
        (?:edit|modify|update|change)            # Action verb
        \s+(?:the\s+)?                           # Optional transition
        (?:file|configuration)\s+                # Target noun
        ([/\w.-]+(?:/[\w.-]+)*)                  # Capture filesystem path
    """,
        re.IGNORECASE | re.VERBOSE,
    )

    # ═══ PATTERN 10: Windows Group Policy paths ═══
    GPO_PATTERN = re.compile(
        r"""
        (?:Computer\ Configuration|              # Standard GPO roots
        User\ Configuration)
        \s*>>?\s*                                # Separator (> or >>)
        .+?                                      # Node element
        (?:>>?\s*.+?)*                           # Additional nodes
    """,
        re.IGNORECASE | re.VERBOSE,
    )

    # ═══ PATTERN 11: Multi-line command blocks ═══
    MULTILINE_PATTERN = re.compile(
        r"""
        (?:^|\n)                                 # Start of line or string
        (                                        # START capture:
            (?:                                    # Group for multi-line repetitions
                (?:sudo\s+)?                         # Optional sudo
                (?:\w+(?:/\w+)*|\w+)                 # Optional path or binary name
                \s+                                  # Spacing
                [^\n]+                               # Arguments
                \n?                                  # Optional line break
            ){2,}                                  # Must be at least 2 lines of commands
        )                                        # END capture
    """,
        re.MULTILINE | re.VERBOSE,
    )

    # ═══ PATTERN 12: Commands after colons ═══
    COLON_CMD_PATTERN = re.compile(
        r"""
        (?:Command|Solution|Fix|                 # Keyword trigger
        Remediation|Action)
        :\s*                                     # Colon and whitespace
        \n?                                      # Optional immediate newline
        (.+?)                                    # Capture payload lazy
        (?:\n\n|\Z)                              # Stop at double newline or end
    """,
        re.IGNORECASE | re.DOTALL | re.VERBOSE,
    )

    def __init__(self, xccdf: Union[str, Path]):
        """
        Initialize fix extractor.

        Args:
            xccdf: Path to XCCDF benchmark file

        Raises:
            FileError: If XCCDF file doesn't exist or is invalid
        """
        self.xccdf = San.path(xccdf, exist=True, file=True)
        self.ns: Dict[str, str] = {}
        self.fixes: List[Fix] = []
        self._text_cache: Dict[Any, str] = {}
        self.stats = {
            "total_groups": 0,
            "with_fix": 0,
            "with_command": 0,
            "platforms": defaultdict(int),
        }

    # ---------------------------------------------------------------- extract
    def extract(self) -> List[Fix]:
        """
        Extract all fixes from XCCDF.

        Returns:
            List of Fix objects

        Raises:
            ParseError: If XCCDF cannot be parsed
        """
        with LOG.context(op="extract_fix", file=self.xccdf.name):
            LOG.i("Extracting fix information")

            try:
                tree = FO.parse_xml(self.xccdf)
                root = tree.getroot()
            except (ParseError, OSError, ValueError) as exc:
                raise ParseError(f"Unable to parse XCCDF: {exc}") from exc

            self.ns = self._namespace(root)
            groups = self._groups(root)
            if not groups:
                raise ParseError("No vulnerability groups found in XCCDF")

            self.stats["total_groups"] = len(groups)
            for idx, group in enumerate(groups, 1):
                with suppress(ValueError, AttributeError, KeyError):
                    fix = self._parse_group(group)
                    if fix:
                        self.fixes.append(fix)
                        self.stats["with_fix"] += 1
                        if fix.fix_command:
                            self.stats["with_command"] += 1
                        self.stats["platforms"][fix.platform] += 1

            LOG.i(
                f"Extracted {len(self.fixes)} fixes "
                f"({self.stats['with_command']} with actionable commands)"
            )
            return self.fixes

    # ---------------------------------------------------------------- helpers
    def _namespace(self, root: ET.Element) -> Dict[str, str]:
        """Extract XML namespace from root element."""
        if "}" in root.tag:
            uri = root.tag.split("}")[0][1:]
            return {"ns": uri}
        return {}

    def _groups(self, root: ET.Element) -> List[ET.Element]:
        """Find all valid vulnerability groups in XCCDF."""
        search = ".//ns:Group" if self.ns else ".//Group"
        groups = root.findall(search, self.ns)
        valid: List[ET.Element] = []
        for group in groups:
            rule = group.find("ns:Rule", self.ns) if self.ns else group.find("Rule")
            if rule is not None:
                valid.append(group)
        return valid

    def _parse_group(self, group) -> Optional[Fix]:
        """
        Parse a single vulnerability group into a Fix object.

        Args:
            group: XML element representing a vulnerability group

        Returns:
            Fix object or None if parsing fails
        """
        vid = group.get("id", "")
        if not vid:
            return None
        try:
            vid = San.vuln(vid)
        except (Exception,):
            # San.vuln raises ValidationError for invalid VIDs — documented broad
            # catch since this is a non-critical skip path during group parsing
            return None

        rule = group.find("ns:Rule", self.ns) if self.ns else group.find("Rule")
        if rule is None:
            return None

        rule_id = rule.get("id", "unknown")
        severity = San.sev(rule.get("severity", "medium"))

        def find(tag: str):
            return rule.find(f"ns:{tag}", self.ns) if self.ns else rule.find(tag)

        def findall(tag: str):
            return rule.findall(f"ns:{tag}", self.ns) if self.ns else rule.findall(tag)

        def text(elem) -> str:
            if elem is None:
                return ""
            if elem.text and elem.text.strip():
                return elem.text.strip()
            try:
                return ET.tostring(elem, encoding="unicode", method="text").strip()
            except (TypeError, ValueError, AttributeError) as exc:
                LOG.w(f"Failed to extract text from XML element {elem.tag}: {exc}")
                return ""

        title = text(find("title"))
        rule_version = text(find("version"))

        group_title_elem = (
            group.find("ns:title", self.ns) if self.ns else group.find("title")
        )
        group_title = text(group_title_elem) if group_title_elem is not None else vid

        # Extract fix text
        fix_elem = find("fixtext")
        fix_text = ""
        if fix_elem is not None:
            fix_text = XmlUtils.extract_text_content(fix_elem)
            if not fix_text.strip():
                LOG.w(f"{vid}: Empty fixtext extracted, checking attributes")
                fix_text = fix_elem.get("fixref", "") or fix_elem.get("id", "")

        if not fix_text.strip():
            LOG.d(f"{vid}: Skipping - no fix text available")
            return None

        # Extract check content
        check_elem = find("check")
        check_text = ""
        check_command = None
        if check_elem is not None:
            check_content = (
                check_elem.find("ns:check-content", self.ns)
                if self.ns
                else check_elem.find("check-content")
            )
            if check_content is not None:
                check_text = XmlUtils.extract_text_content(check_content)
                check_command = self._extract_command(check_text)

        # Extract fix command
        fix_command = self._extract_command(fix_text)

        cci_refs: List[str] = []
        legacy_refs: List[str] = []
        for ident in findall("ident"):
            ident_text = text(ident)
            if not ident_text:
                continue
            system = (ident.get("system") or "").lower()
            if "cci" in system:
                cci_refs.append(ident_text)
            elif "legacy" in system:
                legacy_refs.append(ident_text)

        platform = self._detect_platform(fix_text, fix_command)

        return Fix(
            vid=vid,
            rule_id=rule_id,
            severity=severity,
            title=title,
            group_title=group_title,
            fix_text=fix_text,
            fix_command=fix_command,
            check_command=check_command,
            platform=platform,
            rule_version=rule_version,
            cci=cci_refs,
            legacy=legacy_refs,
        )

    def _extract_markdown_patterns(
        self, text_block: str, candidates: List[str]
    ) -> None:
        """Extract commands derived from markdown blocks and inline code."""
        for pattern in (self.CODE_BLOCK, self.TRIPLE_TICK):
            candidates.extend(pattern.findall(text_block))
        candidates.extend(self.INLINE_CMD.findall(text_block))

    def _extract_prompt_patterns(self, text_block: str, candidates: List[str]) -> None:
        """Extract commands matching terminal prompts or bulleted list prefixes."""
        candidates.extend(self.SHELL_PROMPT.findall(text_block))
        candidates.extend(self.POWERSHELL_PROMPT.findall(text_block))
        candidates.extend(self.BULLET_CMD.findall(text_block))

    def _extract_keyword_patterns(self, text_block: str, candidates: List[str]) -> None:
        """Extract commands guided by textual action instructions (e.g. 'Run this command:')."""
        for match in self.RUN_CMD_PATTERN.finditer(text_block):
            cmd_block = match.group(1).strip()
            if cmd_block and len(cmd_block) > 5:
                candidates.append(cmd_block)

        for match in self.COLON_CMD_PATTERN.finditer(text_block):
            cmd = match.group(1).strip()
            if 5 < len(cmd) < 500:
                candidates.append(cmd)

    def _extract_system_patterns(self, text_block: str, candidates: List[str]) -> None:
        """Extract lines directly matching known UNIX or PowerShell executables."""
        candidates.extend(self.UNIX_CMD_PATTERN.findall(text_block))
        candidates.extend(self.PS_CMDLET_PATTERN.findall(text_block))
        candidates.extend(self.REG_CMD_PATTERN.findall(text_block))
        for match in self.MULTILINE_PATTERN.finditer(text_block):
            block = match.group(1).strip()
            if any(
                cmd in block
                for cmd in [
                    "chmod",
                    "chown",
                    "systemctl",
                    "grep",
                    "sed",
                    "echo",
                    "Set-",
                    "Get-",
                ]
            ):
                candidates.append(block)

    def _extract_config_patterns(self, text_block: str, candidates: List[str]) -> None:
        """Extract pseudo-commands for file editing and GPO configurations."""
        for match in self.EDIT_FILE_PATTERN.finditer(text_block):
            file_path = match.group(1)
            candidates.append(f"# Edit file: {file_path}\nvi {file_path}")

        gpo_matches = self.GPO_PATTERN.findall(text_block)
        for gpo_path in gpo_matches:
            clean_path = gpo_path.replace(">>", "\\").strip()
            candidates.append(f"# Group Policy:\n# {clean_path}")

    def _cleanup_commands(self, candidates: List[str]) -> Optional[str]:
        """Filter, normalize, and validate extracted candidate commands."""
        commands: List[str] = []
        seen = set()

        for cand in candidates:
            if isinstance(cand, tuple):
                cand = cand[-1]

            lines = []
            for line in cand.strip().splitlines():
                line = line.strip()
                if not line or (
                    line.startswith("#")
                    and not any(cmd in line for cmd in ["chmod", "chown", "Edit"])
                ):
                    continue
                lines.append(line)

            cmd = "\n".join(lines)
            if len(cmd) < 5 or len(cmd) > 2000:
                continue

            cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
            if cmd_hash in seen:
                continue
            seen.add(cmd_hash)
            commands.append(cmd)

        if not commands:
            return None
        return max(commands, key=lambda x: len(x)).strip()

    def _extract_command(self, text_block: str) -> Optional[str]:
        """
        Main routing function for command extraction. Matches text blocks
        against various extraction strategies and returns optimal command payload.
        """
        text_block = text_block or ""
        if len(text_block) < 5:
            return None

        candidates: List[str] = []
        self._extract_markdown_patterns(text_block, candidates)
        self._extract_prompt_patterns(text_block, candidates)
        self._extract_keyword_patterns(text_block, candidates)
        self._extract_system_patterns(text_block, candidates)
        self._extract_config_patterns(text_block, candidates)

        return self._cleanup_commands(candidates)

    def _detect_platform(self, text_block: str, cmd: Optional[str]) -> str:
        """
        Detect target platform from fix text and commands.

        Args:
            text_block: Full fix text
            cmd: Extracted command

        Returns:
            Platform identifier: windows, linux, network, or generic
        """
        combined = f"{text_block}\n{cmd or ''}".lower()
        if any(
            token in combined
            for token in (
                "powershell",
                "set-mdp",
                "new-item",
                "registry",
                "gpo",
                "windows",
            )
        ):
            return "windows"
        if any(
            token in combined
            for token in (
                "systemctl",
                "chmod",
                "chown",
                "/etc/",
                "apt-get",
                "yum",
                "dnf",
                "rpm",
                "bash",
            )
        ):
            return "linux"
        if any(
            token in combined
            for token in (
                "cisco",
                "ios",
                "switchport",
                "interface",
                "router",
                "show running-config",
            )
        ):
            return "network"
        return "generic"

    # ---------------------------------------------------------------- export
    def to_json(self, path: Union[str, Path]) -> None:
        """
        Export fixes to JSON format.

        Args:
            path: Output JSON file path
        """
        path = San.path(path, mkpar=True)
        payload = {
            "meta": {
                "source": str(self.xccdf),
                "generated": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
                "stats": {
                    "total_groups": self.stats["total_groups"],
                    "with_fix": self.stats["with_fix"],
                    "with_command": self.stats["with_command"],
                    "platforms": dict(self.stats["platforms"]),
                },
            },
            "fixes": [fix.as_dict() for fix in self.fixes],
        }
        with FO.atomic(path) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        LOG.i(f"Fixes exported to JSON: {path}")

    def to_csv(self, path: Union[str, Path]) -> None:
        """
        Export fixes to CSV format.

        Args:
            path: Output CSV file path
        """
        path = San.path(path, mkpar=True)
        fieldnames = [
            "Vuln_ID",
            "Rule_ID",
            "Severity",
            "Title",
            "Group_Title",
            "Platform",
            "Has_Fix_Command",
            "Has_Check_Command",
            "Fix_Command",
            "Check_Command",
            "CCI",
        ]
        with FO.atomic(path) as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for fix in self.fixes:
                writer.writerow(
                    {
                        "Vuln_ID": fix.vid,
                        "Rule_ID": fix.rule_id,
                        "Severity": fix.severity,
                        "Title": fix.title[:120],
                        "Group_Title": fix.group_title[:80],
                        "Platform": fix.platform,
                        "Has_Fix_Command": "Yes" if fix.fix_command else "No",
                        "Has_Check_Command": ("Yes" if fix.check_command else "No"),
                        "Fix_Command": (fix.fix_command or "")[:500],
                        "Check_Command": (fix.check_command or "")[:200],
                        "CCI": "; ".join(fix.cci[:5]),
                    }
                )
        LOG.i(f"Fixes exported to CSV: {path}")

    def to_bash(
        self,
        path: Union[str, Path],
        severity_filter: Optional[List[str]] = None,
        dry_run: bool = False,
    ) -> None:
        """
        Generate Bash remediation script.

        Args:
            path: Output .sh file path
            severity_filter: List of severity levels to include (e.g., ['high', 'medium'])
            dry_run: Generate dry-run script (doesn't execute commands)
        """
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.fix_command
            and fix.platform in ("linux", "generic")
            and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Linux/generic fixes with commands found")
            return

        class BashTemplate(string.Template):
            delimiter = "%"

        header_tmpl = BashTemplate("""#!/usr/bin/env bash
# Auto-generated remediation script
# Generated: %{dt}
# Mode: %{mode}

set -euo pipefail

DRY_RUN=%{dry_run}
LOG_FILE="stig_fix_$$(date +%%Y%%m%%d_%%H%%M%%S).log"
RESULT_FILE="stig_results_$$(date +%%Y%%m%%d_%%H%%M%%S).json"

echo "Remediation started" | tee -a "$LOG_FILE"
declare -i PASS=0 FAIL=0 SKIP=0
declare -a RESULTS=()

record_result() {
  local vid="$1"
  local ok="$2"
  local msg="$3"
  RESULTS+=('{"vid":"'"$vid"'","ok":'"$ok"',"msg":"'"${msg//\\"/\\\\\\"}"'","ts":"'"$$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"'"}')
}
""")

        lines: List[str] = [
            header_tmpl.substitute(
                dt=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                mode="DRY RUN" if dry_run else "LIVE",
                dry_run="1" if dry_run else "0",
            )
        ]

        live_fix_tmpl = BashTemplate(
            """echo "[%{idx}/%{total}] %{vid} - %{title}" | tee -a "$LOG_FILE"
{
%{cmd}
} >>"$LOG_FILE" 2>&1
if [ $? -eq 0 ]; then
  echo "  ✔ Success" | tee -a "$LOG_FILE"
  record_result "%{vid}" true "success"
  ((PASS++))
else
  echo "  ✘ Failed" | tee -a "$LOG_FILE"
  record_result "%{vid}" false "failed"
  ((FAIL++))
fi
"""
        )

        dry_fix_tmpl = BashTemplate(
            """echo "[%{idx}/%{total}] %{vid} - %{title}" | tee -a "$LOG_FILE"
echo "  [DRY-RUN] Would execute:
%{cmd}" | tee -a "$LOG_FILE"
record_result "%{vid}" true "dry_run"
((PASS++))
"""
        )

        for idx, fix in enumerate(fixes, 1):
            if dry_run:
                lines.append(
                    dry_fix_tmpl.substitute(
                        idx=idx,
                        total=len(fixes),
                        vid=fix.vid,
                        title=fix.title[:60],
                        cmd=fix.fix_command,
                    )
                )
            else:
                indented_cmd = "\n".join(
                    f"  {line}" for line in fix.fix_command.splitlines()
                )
                lines.append(
                    live_fix_tmpl.substitute(
                        idx=idx,
                        total=len(fixes),
                        vid=fix.vid,
                        title=fix.title[:60],
                        cmd=indented_cmd,
                    )
                )

        lines.extend(
            [
                'echo "Summary: PASS=$PASS FAIL=$FAIL SKIP=$SKIP" | tee -a "$LOG_FILE"',
                'printf \'{\\n  "meta": {\\n    "generated": "%s",\\n    "mode": "%s",\\n    "total": %d,\\n    "pass": %d,\\n    "fail": %d,\\n    "skip": %d\\n  },\\n  "results": [\\n\' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$DRY_RUN" -eq 1 ] && echo \'dry\' || echo \'live\')" $((PASS+FAIL+SKIP)) $PASS $FAIL $SKIP > "$RESULT_FILE"',
                'for i in "${!RESULTS[@]}"; do',
                '  printf \'    %s%s\\n\' "${RESULTS[$i]}" $([ "$i" -lt $(( ${#RESULTS[@]} - 1 )) ] && echo \',\' ) >> "$RESULT_FILE"',
                "done",
                "printf '  ]\\n}\\n' >> \"$RESULT_FILE\"",
                'echo "Results saved to $RESULT_FILE" | tee -a "$LOG_FILE"',
            ]
        )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        if not Cfg.IS_WIN:
            try:
                os.chmod(path, 0o750)
            except OSError as err:
                LOG.w(
                    f"Could not safely set executable permissions on {path} (Check context rights): {err}"
                )
        LOG.i(f"Bash remediation script generated: {path} ({len(fixes)} fixes)")

    def to_powershell(
        self,
        path: Union[str, Path],
        severity_filter: Optional[List[str]] = None,
        dry_run: bool = False,
        enable_rollbacks: bool = False,
    ) -> None:
        """
        Generate PowerShell remediation script.

        Args:
            path: Output .ps1 file path
            severity_filter: List of severity levels to include
            dry_run: Generate dry-run script (uses -WhatIf)
            enable_rollbacks: If True, generate registry rollback exports before executing fixes.
        """
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.fix_command
            and fix.platform in ("windows", "generic")
            and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Windows/generic fixes with commands found")
            return

        class PsTemplate(string.Template):
            delimiter = "%"

        header_tmpl = PsTemplate("""#requires -RunAsAdministrator
# Generated: %{dt}
# Mode: %{mode}
# Rollbacks Enabled: %{rollbacks}

$$ErrorActionPreference = 'Stop'
$$DryRun = %{dry_run}
$$Log = "stig_fix_$$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$$Results = @()
Start-Transcript -Path $$Log -Append | Out-Null
%{rollback_block}

function Add-Result([string]$$Vid, [bool]$$Success, [string]$$Message) {
    $$Results += [pscustomobject]@{
        vid = $$Vid;
        ok = $$Success;
        msg = $$Message;
        ts = [DateTime]::UtcNow.ToString('o')
    }
}
""")
        rollback_block = ""
        if enable_rollbacks and not dry_run:
            rollback_block = """
Write-Host "Creating pre-flight Registry Backups for HKLM\\Software and HKLM\\System..."
$$RollbackDir = "stig_rollback_$$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $$RollbackDir | Out-Null
try {
    cmd /c "reg export HKLM\\SOFTWARE `\"$$RollbackDir\\HKLM_SOFTWARE.reg`\" /y >nul 2>&1"
    cmd /c "reg export HKLM\\SYSTEM `\"$$RollbackDir\\HKLM_SYSTEM.reg`\" /y >nul 2>&1"
    Write-Host "Registry backup created at $$RollbackDir"
} catch {
    Write-Warning "Failed to create registry backup: $$($$_.Exception.Message)"
}
"""

        lines: List[str] = [
            header_tmpl.substitute(
                dt=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                mode="DRY RUN" if dry_run else "LIVE",
                rollbacks="YES" if enable_rollbacks else "NO",
                rollback_block=rollback_block,
                dry_run="$$true" if dry_run else "$$false",
            )
        ]

        live_fix_tmpl = PsTemplate("""Write-Host "[%{idx}/%{total}] %{vid} - %{title}"
try {
%{cmd}
    Write-Host "  ✔ Success"
    Add-Result "%{vid}" $$true "success"
} catch {
    Write-Warning "  ✘ Failed: $$($$_.Exception.Message)"
    Add-Result "%{vid}" $$false $$_.Exception.Message
}
""")

        dry_fix_tmpl = PsTemplate("""Write-Host "[%{idx}/%{total}] %{vid} - %{title}"
Write-Host "  [DRY-RUN] Would execute:`n%{cmd}"
Add-Result "%{vid}" $$true "dry_run"
Continue
""")

        for idx, fix in enumerate(fixes, 1):
            if dry_run:
                lines.append(
                    dry_fix_tmpl.substitute(
                        idx=idx,
                        total=len(fixes),
                        vid=fix.vid,
                        title=fix.title[:60],
                        cmd=fix.fix_command,
                    )
                )
            else:
                indented_cmd = "\n".join(
                    f"    {line}" for line in fix.fix_command.splitlines()
                )
                lines.append(
                    live_fix_tmpl.substitute(
                        idx=idx,
                        total=len(fixes),
                        vid=fix.vid,
                        title=fix.title[:60],
                        cmd=indented_cmd,
                    )
                )

        lines.extend(
            [
                "Stop-Transcript | Out-Null",
                "[pscustomobject]@{",
                "    meta = @{",
                "        generated = [DateTime]::UtcNow.ToString('o');",
                "        mode = if ($$DryRun) { 'dry' } else { 'live' };",
                "        total = $$Results.Count;",
                "        pass = ($$Results | Where-Object { $$_.ok }).Count;",
                "        fail = ($$Results | Where-Object { -not $$_.ok }).Count;",
                "    };",
                "    results = $$Results",
                "} | ConvertTo-Json -Depth 10 | Out-File \"stig_results_$$(Get-Date -Format 'yyyyMMdd_HHmmss').json\" -Encoding utf8",
            ]
        )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        LOG.i(f"PowerShell remediation script generated: {path} ({len(fixes)} fixes)")

    def to_ansible(
        self,
        path: Union[str, Path],
        severity_filter: Optional[List[str]] = None,
        dry_run: bool = False,
    ) -> None:
        """
        Generate Ansible remediation playbook.

        Args:
            path: Output .yml file path
            severity_filter: List of severity levels to include
            dry_run: Generate dry-run playbooks using the debug module
        """
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.fix_command
            and fix.platform in ("linux", "generic")
            and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Linux/generic fixes with commands found for Ansible")
            return

        lines: List[str] = [
            "---",
            "# Auto-generated STIG Remediation Playbook",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Mode: {'DRY RUN' if dry_run else 'LIVE'}",
            "",
            "- name: Validate and Remediate STIG Findings",
            "  hosts: all",
            "  become: yes",
            "  tasks:",
        ]

        for idx, fix in enumerate(fixes, 1):
            title_escaped = fix.title[:60].replace('"', '\\"')
            if dry_run:
                # Just debug print
                indented_cmd = "\n".join(
                    f"          {line}" for line in fix.fix_command.splitlines()
                )
                lines.extend(
                    [
                        f'    - name: "[{idx}/{len(fixes)}] [DRY-RUN] {fix.vid} - {title_escaped}"',
                        "      ansible.builtin.debug:",
                        "        msg: |",
                        "          Would execute:",
                        indented_cmd,
                        "",
                    ]
                )
            else:
                indented_cmd = "\n".join(
                    f"        {line}" for line in fix.fix_command.splitlines()
                )
                lines.extend(
                    [
                        f'    - name: "[{idx}/{len(fixes)}] {fix.vid} - {title_escaped}"',
                        "      ansible.builtin.shell: |",
                        indented_cmd,
                        "      register: stig_fix_" + fix.vid.replace("-", "_").lower(),
                        "      ignore_errors: true",
                        "      tags:",
                        f"        - {fix.vid.lower()}",
                        "",
                    ]
                )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines) + "\n")

        LOG.i(f"Ansible remediation playbook generated: {path} ({len(fixes)} fixes)")

    def stats_summary(self) -> Dict[str, Any]:
        """
        Get extraction statistics summary.

        Returns:
            Dictionary with extraction statistics
        """
        return {
            "total_groups": self.stats["total_groups"],
            "with_fix": self.stats["with_fix"],
            "with_command": self.stats["with_command"],
            "platforms": dict(self.stats["platforms"]),
        }
