"""Fix extraction from XCCDF benchmarks with multi-format export."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import Fix

# TODO: These imports will be available when other teams complete their modules
# For now, these are placeholders - the actual implementations exist in STIG_Script.py
# Team 1 (Core Infrastructure) - lines 188-704
# from stig_assessor.core.logging import LOG
# from stig_assessor.core.config import Cfg

# Team 2 (XML Foundation) - lines 705-1229
# from stig_assessor.xml.sanitizer import San

# Team 3 (File Operations) - lines 1230-1475
# from stig_assessor.io.file_ops import FO

# TEMPORARY: Import from original monolith until modules are available
try:
    # When running in modularized environment
    from stig_assessor.core.logging import LOG
    from stig_assessor.core.config import Cfg
    from stig_assessor.xml.sanitizer import San
    from stig_assessor.io.file_ops import FO
except ImportError:
    # Fallback to original monolith for development
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from STIG_Script import LOG, Cfg, San, FO

# Version constant (will move to core/constants.py)
VERSION = "7.3.0"


class FixExt:
    """Fix extractor with enhanced command parsing."""

    # Regex patterns for command extraction
    CODE_BLOCK = re.compile(r"```(?:bash|sh|shell|zsh|powershell|ps1|ps|cmd|bat)\s*(.*?)```", re.DOTALL | re.IGNORECASE)
    TRIPLE_TICK = re.compile(r"```(.*?)```", re.DOTALL)
    SHELL_PROMPT = re.compile(r"(?m)^(?:\$|#|>)\s*(.+)")
    POWERSHELL_PROMPT = re.compile(r"(?m)^(?:PS [^>]+>|\w:\\[^>]*>)\s*(.+)")
    BULLET_CMD = re.compile(r"(?m)^(?:[-*+]|\d+\.)\s*(?:Run|Execute)\s*[:\-]?\s*(.+)")
    INLINE_CMD = re.compile(r"`([^`]+)`")
    COMMAND_LINE = re.compile(r"(?m)^\s*(?:#|sudo)\s+(.+)$")
    PLAIN_COMMAND = re.compile(r"(?:run|execute|use)\s+(?:the\s+)?(?:following\s+)?(?:command|commands?)[\s:]+(.+?)(?:\n|$)", re.IGNORECASE)
    CONFIG_FILE = re.compile(r"(?:edit|modify|update)\s+(?:the\s+)?(?:file\s+)?([/\w.-]+(?:/[\w.-]+)*)", re.IGNORECASE)
    SCRIPT_BLOCK = re.compile(r"(?:#!/bin/(?:bash|sh)|@echo off)(.*?)(?=\n\n|\Z)", re.DOTALL)
    SERVICE_CMD = re.compile(r"^\s*(?:systemctl|service)\s+(?:start|stop|restart|enable|disable|status)\s+\S+", re.MULTILINE)
    AUDIT_CMD = re.compile(r"^\s*(?:auditctl|ausearch|aureport)\s+.+", re.MULTILINE)
    SELINUX_CMD = re.compile(r"^\s*(?:semanage|setsebool|restorecon|chcon|getenforce|setenforce)\s+.+", re.MULTILINE)


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
        LOG.ctx(op="extract_fix", file=self.xccdf.name)
        LOG.i("Extracting fix information")

        try:
            tree = FO.parse_xml(self.xccdf)
            root = tree.getroot()
        except Exception as exc:
            from stig_assessor.exceptions import ParseError
            raise ParseError(f"Unable to parse XCCDF: {exc}") from exc

        self.ns = self._namespace(root)
        groups = self._groups(root)
        if not groups:
            from stig_assessor.exceptions import ParseError
            raise ParseError("No vulnerability groups found in XCCDF")

        self.stats["total_groups"] = len(groups)
        for idx, group in enumerate(groups, 1):
            with suppress(Exception):
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
        LOG.clear()
        return self.fixes

    # ---------------------------------------------------------------- helpers
    def _namespace(self, root: Any) -> Dict[str, str]:
        """Extract XML namespace from root element."""
        if "}" in root.tag:
            uri = root.tag.split("}")[0][1:]
            return {"ns": uri}
        return {}

    def _groups(self, root: Any) -> List[Any]:
        """Find all valid vulnerability groups in XCCDF."""
        search = ".//ns:Group" if self.ns else ".//Group"
        groups = root.findall(search, self.ns)
        valid: List[Any] = []
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
        except Exception:
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
            except Exception as exc:
                LOG.w(f"Failed to extract text from XML element {elem.tag}: {exc}")
                return ""

        title = text(find("title"))
        rule_version = text(find("version"))

        group_title_elem = group.find("ns:title", self.ns) if self.ns else group.find("title")
        group_title = text(group_title_elem) if group_title_elem is not None else vid

        # Extract fix text
        fix_elem = find("fixtext")
        fix_text = ""
        if fix_elem is not None:
            fix_text = self._collect_text(fix_elem)
            if not fix_text.strip():
                LOG.w(f"{vid}: Empty fixtext extracted, checking attributes")
                fix_text = fix_elem.get('fixref', '') or fix_elem.get('id', '')

        if not fix_text.strip():
            LOG.d(f"{vid}: Skipping - no fix text available")
            return None

        # Extract check content
        check_elem = find("check")
        check_text = ""
        check_command = None
        if check_elem is not None:
            check_content = check_elem.find("ns:check-content", self.ns) if self.ns else check_elem.find("check-content")
            if check_content is not None:
                check_text = self._collect_text(check_content)
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


    def _collect_text(self, elem: Any) -> str:
        """
        Enhanced text extraction with proper mixed content handling.

        Handles XCCDF elements that contain plain text, nested elements,
        and preserves command formatting.
        """
        if elem is None:
            return ""

        # Method 1: itertext() with proper newline preservation
        try:
            parts: List[str] = []
            # Collect all text including from nested elements
            for text_fragment in elem.itertext():
                if text_fragment:
                    # Only strip leading/trailing whitespace, preserve internal structure
                    cleaned = text_fragment.strip()
                    if cleaned:
                        parts.append(cleaned)

            if parts:
                # Join with newlines to preserve command structure
                result = '\n'.join(parts)
                # Clean up excessive blank lines but keep structure
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"itertext() extraction failed: {exc}")

        # Method 2: Manual traversal for complex mixed content
        try:
            def extract_text_recursive(element) -> List[str]:
                texts = []
                if element.text:
                    txt = element.text.strip()
                    if txt:
                        texts.append(txt)
                for child in element:
                    # Recursively get text from children
                    texts.extend(extract_text_recursive(child))
                    # Get tail text (text after child element)
                    if child.tail:
                        tail = child.tail.strip()
                        if tail:
                            texts.append(tail)
                return texts

            parts = extract_text_recursive(elem)
            if parts:
                result = '\n'.join(parts)
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"Recursive extraction failed: {exc}")

        # Method 3: Direct text attribute (simple elements only)
        if elem.text and elem.text.strip():
            return elem.text.strip()

        # Method 4: Last resort - tostring
        try:
            text_content = ET.tostring(elem, encoding='unicode', method='text')
            if text_content and text_content.strip():
                # Clean up excessive whitespace
                text_content = re.sub(r'\s+', ' ', text_content)
                return text_content.strip()
        except Exception as exc:
            LOG.d(f"tostring() extraction failed: {exc}")

        return ""


    def _extract_command(self, text_block: str) -> Optional[str]:
        """
        Enhanced command extraction supporting multiple STIG fixtext formats.

        Handles:
        - Shell commands (with or without prompts)
        - PowerShell commands
        - Windows Group Policy paths
        - Configuration file edits
        - Multi-line command sequences
        - Registry modifications
        """
        text_block = text_block or ""
        if len(text_block) < 5:
            return None

        candidates: List[str] = []

        # ═══ PATTERN 1: Code blocks (markdown style) ═══
        for pattern in (self.CODE_BLOCK, self.TRIPLE_TICK):
            candidates.extend(pattern.findall(text_block))

        # ═══ PATTERN 2: Shell prompts ═══
        candidates.extend(self.SHELL_PROMPT.findall(text_block))
        candidates.extend(self.POWERSHELL_PROMPT.findall(text_block))

        # ═══ PATTERN 3: Bullet-style commands ═══
        candidates.extend(self.BULLET_CMD.findall(text_block))

        # ═══ PATTERN 4: Inline code ═══
        candidates.extend(self.INLINE_CMD.findall(text_block))

        # ═══ PATTERN 5: "Run the following command" blocks ═══
        # Matches: "Run the following command:" followed by actual commands
        run_command_pattern = re.compile(
            r"(?:run|execute|use|enter|type)\s+(?:the\s+)?(?:following\s+)?(?:command|commands?)[\s:]+\n(.+?)(?:\n\n|\Z)",
            re.IGNORECASE | re.DOTALL
        )
        for match in run_command_pattern.finditer(text_block):
            cmd_block = match.group(1).strip()
            if cmd_block and len(cmd_block) > 5:
                candidates.append(cmd_block)

        # ═══ PATTERN 6: Common Unix/Linux commands ═══
        # Matches lines with common system commands
        unix_cmd_pattern = re.compile(
            r"^\s*(?:sudo\s+)?(?:chmod|chown|chgrp|systemctl|service|grep|sed|awk|find|rpm|yum|dnf|apt-get|"
            r"apt|mount|umount|useradd|usermod|passwd|groupadd|ln|cp|mv|rm|mkdir|touch|cat|echo|vi|nano|"
            r"gsettings|dconf|auditctl|ausearch|aureport|restorecon|semanage|setsebool|firewall-cmd)\s+.+",
            re.MULTILINE
        )
        candidates.extend(unix_cmd_pattern.findall(text_block))

        # ═══ PATTERN 7: PowerShell cmdlets ═══
        # Matches PowerShell commands
        ps_cmdlet_pattern = re.compile(
            r"^\s*(?:Set-|Get-|New-|Remove-|Add-|Enable-|Disable-|Test-|Invoke-)[A-Za-z]+(?:\s+-[A-Za-z]+\s+[^\n]+)+",
            re.MULTILINE
        )
        candidates.extend(ps_cmdlet_pattern.findall(text_block))

        # ═══ PATTERN 8: Registry commands (Windows) ═══
        # Matches reg.exe commands
        reg_cmd_pattern = re.compile(
            r"^\s*reg(?:\.exe)?\s+(?:add|delete|query|import|export)\s+.+",
            re.MULTILINE | re.IGNORECASE
        )
        candidates.extend(reg_cmd_pattern.findall(text_block))

        # ═══ PATTERN 9: File editing instructions ═══
        # Matches "Edit the file /path/to/file" and extracts the file path
        edit_file_pattern = re.compile(
            r"(?:edit|modify|update|change)\s+(?:the\s+)?(?:file|configuration)\s+([/\w.-]+(?:/[\w.-]+)*)",
            re.IGNORECASE
        )
        for match in edit_file_pattern.finditer(text_block):
            file_path = match.group(1)
            # Create a simple edit command
            candidates.append(f"# Edit file: {file_path}\nvi {file_path}")

        # ═══ PATTERN 10: Windows Group Policy paths ═══
        # These aren't executable but are important configuration instructions
        gpo_pattern = re.compile(
            r"(?:Computer Configuration|User Configuration)\s*>>?\s*.+?(?:>>?\s*.+?)*",
            re.IGNORECASE
        )
        gpo_matches = gpo_pattern.findall(text_block)
        if gpo_matches:
            # Format as a configuration instruction
            for gpo_path in gpo_matches:
                clean_path = gpo_path.replace('>>', '\\').strip()
                candidates.append(f"# Group Policy:\n# {clean_path}")

        # ═══ PATTERN 11: Multi-line command blocks ═══
        # Matches blocks that look like shell scripts (multiple lines with commands)
        multiline_pattern = re.compile(
            r"(?:^|\n)((?:(?:sudo\s+)?(?:\w+(?:/\w+)*|\w+)\s+[^\n]+\n?){2,})",
            re.MULTILINE
        )
        for match in multiline_pattern.finditer(text_block):
            block = match.group(1).strip()
            # Verify it looks like commands (has common command words)
            if any(cmd in block for cmd in ['chmod', 'chown', 'systemctl', 'grep', 'sed', 'echo', 'Set-', 'Get-']):
                candidates.append(block)

        # ═══ PATTERN 12: Commands after colons ═══
        # Matches: "Command: something" or "Solution: do this"
        colon_cmd_pattern = re.compile(
            r"(?:Command|Solution|Fix|Remediation|Action):\s*\n?(.+?)(?:\n\n|\Z)",
            re.IGNORECASE | re.DOTALL
        )
        for match in colon_cmd_pattern.finditer(text_block):
            cmd = match.group(1).strip()
            if len(cmd) > 5 and len(cmd) < 500:  # Reasonable command length
                candidates.append(cmd)

        # ═══ CLEANUP: Remove comments, filter, and deduplicate ═══
        commands: List[str] = []
        seen = set()

        for cand in candidates:
            if isinstance(cand, tuple):
                cand = cand[-1]

            # Clean up the command
            lines = []
            for line in cand.strip().splitlines():
                line = line.strip()
                # Skip empty lines and pure comment lines
                if not line or (line.startswith('#') and not any(cmd in line for cmd in ['chmod', 'chown', 'Edit'])):
                    continue
                lines.append(line)

            cmd = '\n'.join(lines)

            # Validation: must meet minimum criteria
            if len(cmd) < 5:
                continue
            if len(cmd) > 2000:  # Too long, probably not a command
                continue

            # Deduplicate using SHA256 instead of MD5 for security
            cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
            if cmd_hash in seen:
                continue
            seen.add(cmd_hash)

            commands.append(cmd)

        if not commands:
            return None

        # Return the longest/most substantial command
        return max(commands, key=lambda x: len(x)).strip()


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
        if any(token in combined for token in ("powershell", "set-mdp", "new-item", "registry", "gpo", "windows")):
            return "windows"
        if any(token in combined for token in ("systemctl", "chmod", "chown", "/etc/", "apt-get", "yum", "dnf", "rpm", "bash")):
            return "linux"
        if any(token in combined for token in ("cisco", "ios", "switchport", "interface", "router", "show running-config")):
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
        with FO.atomic(path) as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
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
            )
            for fix in self.fixes:
                writer.writerow(
                    [
                        fix.vid,
                        fix.rule_id,
                        fix.severity,
                        fix.title[:120],
                        fix.group_title[:80],
                        fix.platform,
                        "Yes" if fix.fix_command else "No",
                        "Yes" if fix.check_command else "No",
                        (fix.fix_command or "")[:500],
                        (fix.check_command or "")[:200],
                        "; ".join(fix.cci[:5]),
                    ]
                )
        LOG.i(f"Fixes exported to CSV: {path}")

    def to_bash(self, path: Union[str, Path], severity_filter: Optional[List[str]] = None, dry_run: bool = False) -> None:
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
            if fix.fix_command and fix.platform in ("linux", "generic") and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Linux/generic fixes with commands found")
            return

        lines: List[str] = [
            "#!/usr/bin/env bash",
            "# Auto-generated remediation script",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Mode: {'DRY RUN' if dry_run else 'LIVE'}",
            "",
            "set -euo pipefail",
            "",
            "DRY_RUN=" + ("1" if dry_run else "0"),
            "LOG_FILE=\"stig_fix_$(date +%Y%m%d_%H%M%S).log\"",
            "RESULT_FILE=\"stig_results_$(date +%Y%m%d_%H%M%S).json\"",
            "",
            "echo \"Remediation started\" | tee -a \"$LOG_FILE\"",
            "declare -i PASS=0 FAIL=0 SKIP=0",
            "declare -a RESULTS=()",
            "",
            "record_result() {",
            "  local vid=\"$1\"",
            "  local ok=\"$2\"",
            "  local msg=\"$3\"",
            "  RESULTS+=('{\"vid\":\"'\"$vid\"'\",\"ok\":'\"$ok\"',\"msg\":\"'\"${msg//\"/\\\"}\"'\",\"ts\":\"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\"}')",
            "}",
            "",
        ]

        for idx, fix in enumerate(fixes, 1):
            safe_vid = re.sub(r"[^A-Za-z0-9_]", "_", fix.vid)
            lines.append(f"echo \"[{idx}/{len(fixes)}] {fix.vid} - {fix.title[:60]}\" | tee -a \"$LOG_FILE\"")
            if dry_run:
                lines.append(f"echo \"  [DRY-RUN] Would execute:\n{fix.fix_command}\" | tee -a \"$LOG_FILE\"")
                lines.append(f"record_result \"{fix.vid}\" true \"dry_run\"")
                lines.append("((PASS++))")
                lines.append("")
                continue

            lines.append(
                "{\n" + "\n".join(f"  {line}" for line in fix.fix_command.splitlines()) + "\n} >>\"$LOG_FILE\" 2>&1"
            )
            lines.append("if [ $? -eq 0 ]; then")
            lines.append("  echo \"  ✔ Success\" | tee -a \"$LOG_FILE\"")
            lines.append(f"  record_result \"{fix.vid}\" true \"success\"")
            lines.append("  ((PASS++))")
            lines.append("else")
            lines.append("  echo \"  ✘ Failed\" | tee -a \"$LOG_FILE\"")
            lines.append(f"  record_result \"{fix.vid}\" false \"failed\"")
            lines.append("  ((FAIL++))")
            lines.append("fi")
            lines.append("")

        lines.extend(
            [
                "echo \"Summary: PASS=$PASS FAIL=$FAIL SKIP=$SKIP\" | tee -a \"$LOG_FILE\"",
                "printf '{\\n  \"meta\": {\\n    \"generated\": \"%s\",\\n    \"mode\": \"%s\",\\n    \"total\": %d,\\n    \"pass\": %d,\\n    \"fail\": %d,\\n    \"skip\": %d\\n  },\\n  \"results\": [\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"$([ \"$DRY_RUN\" -eq 1 ] && echo 'dry' || echo 'live')\" $((PASS+FAIL+SKIP)) $PASS $FAIL $SKIP > \"$RESULT_FILE\"",
                "for i in \"${!RESULTS[@]}\"; do",
                "  printf '    %s%s\\n' \"${RESULTS[$i]}\" $([ \"$i\" -lt $(( ${#RESULTS[@]} - 1 )) ] && echo ',' ) >> \"$RESULT_FILE\"",
                "done",
                "printf '  ]\\n}\\n' >> \"$RESULT_FILE\"",
                "echo \"Results saved to $RESULT_FILE\" | tee -a \"$LOG_FILE\"",
            ]
        )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        if not Cfg.IS_WIN:
            with suppress(Exception):
                os.chmod(path, 0o750)

        LOG.i(f"Bash remediation script generated: {path} ({len(fixes)} fixes)")

    def to_powershell(self, path: Union[str, Path], severity_filter: Optional[List[str]] = None, dry_run: bool = False) -> None:
        """
        Generate PowerShell remediation script.

        Args:
            path: Output .ps1 file path
            severity_filter: List of severity levels to include
            dry_run: Generate dry-run script (uses -WhatIf)
        """
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.fix_command and fix.platform in ("windows", "generic") and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Windows/generic fixes with commands found")
            return

        lines: List[str] = [
            "#requires -RunAsAdministrator",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Mode: {'DRY RUN' if dry_run else 'LIVE'}",
            "",
            "$ErrorActionPreference = 'Stop'",
            f"$DryRun = {'$true' if dry_run else '$false'}",
            "$Log = \"stig_fix_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\"",
            "$Results = @()",
            "Start-Transcript -Path $Log -Append | Out-Null",
            "",
            "function Add-Result([string]$Vid, [bool]$Success, [string]$Message) {",
            "    $Results += [pscustomobject]@{",
            "        vid = $Vid;",
            "        ok = $Success;",
            "        msg = $Message;",
            "        ts = [DateTime]::UtcNow.ToString('o')",
            "    }",
            "}",
            "",
        ]

        for idx, fix in enumerate(fixes, 1):
            lines.append(f"Write-Host \"[{idx}/{len(fixes)}] {fix.vid} - {fix.title[:60]}\"")
            if dry_run:
                lines.append(f"Write-Host \"  [DRY-RUN] Would execute:`n{fix.fix_command}\"")
                lines.append(f"Add-Result \"{fix.vid}\" $true \"dry_run\"")
                lines.append("Continue")
                lines.append("")
                continue

            lines.append("try {")
            for line in fix.fix_command.splitlines():
                lines.append(f"    {line}")
            lines.append(f"    Write-Host \"  ✔ Success\"")
            lines.append(f"    Add-Result \"{fix.vid}\" $true \"success\"")
            lines.append("} catch {")
            lines.append("    Write-Warning \"  ✘ Failed: $($_.Exception.Message)\"")
            lines.append(f"    Add-Result \"{fix.vid}\" $false $_.Exception.Message")
            lines.append("}")
            lines.append("")

        lines.extend(
            [
                "Stop-Transcript | Out-Null",
                "[pscustomobject]@{",
                "    meta = @{",
                "        generated = [DateTime]::UtcNow.ToString('o');",
                "        mode = if ($DryRun) { 'dry' } else { 'live' };",
                "        total = $Results.Count;",
                "        pass = ($Results | Where-Object { $_.ok }).Count;",
                "        fail = ($Results | Where-Object { -not $_.ok }).Count;",
                "    };",
                "    results = $Results",
                "} | ConvertTo-Json -Depth 10 | Out-File \"stig_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json\" -Encoding utf8",
            ]
        )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        LOG.i(f"PowerShell remediation script generated: {path} ({len(fixes)} fixes)")

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
