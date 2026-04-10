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

    # ═══ PATTERN 2.1: Network CLI prompts (Cisco, Juniper, etc.) ═══
    NETWORK_PROMPT = re.compile(
        r"""
        ^                      # Start of line
        [\w.-]+                # Hostname
        (?:\([\w.-]+\))?       # Optional (config) or (config-if)
        [#>]?                  # Optional prompt char before actual command
        \s*                    # Optional whitespace
        (?![#>\s])             # Ensure we don't just capture a prompt
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

    def __init__(self, xccdf: Union[str, Path], checklist: Optional[Union[str, Path]] = None):
        """
        Initialize fix extractor.

        Args:
            xccdf: Path to XCCDF benchmark file
            checklist: Optional path to assessment CKL/CKLB file for status filtering

        Raises:
            FileError: If XCCDF file doesn't exist or is invalid
        """
        self.xccdf = San.path(xccdf, exist=True, file=True)
        self.checklist_path = (
            San.path(checklist, exist=True, file=True) if checklist else None
        )
        self.statuses: Dict[str, str] = {}  # VID -> Status
        self.ns: Dict[str, str] = {}
        self.fixes: List[Fix] = []
        self._text_cache: Dict[Any, str] = {}
        self.stats = {
            "total_groups": 0,
            "with_fix": 0,
            "with_command": 0,
            "platforms": defaultdict(int),
        }

        if self.checklist_path:
            self._load_statuses()

    # ---------------------------------------------------------------- extract
    def extract(
        self,
        status_filter: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None,
        vid_list: Optional[List[str]] = None,
        vid_include: Optional[str] = None,
        vid_exclude: Optional[str] = None,
    ) -> List[Fix]:
        """
        Extract all fixes from XCCDF, optionally filtering by checklist status
        and/or severity.

        Args:
            status_filter: Optional list of statuses to include (e.g. ['Open', 'Not_Reviewed']).
                          Only applies if a checklist was provided during initialization.
            severity_filter: Optional list of severities to include (e.g. ['high', 'medium']).

        Returns:
            List of Fix objects

        Raises:
            ParseError: If XCCDF cannot be parsed
        """
        self.fixes = []  # Reset
        self.stats["with_fix"] = 0
        self.stats["with_command"] = 0
        self.stats["with_check"] = 0
        self.stats["platforms"] = defaultdict(int)
        self.stats["by_severity"] = defaultdict(int)
        self.stats["manual_review"] = []

        status_set = {s.lower() for s in status_filter} if status_filter else None
        sev_set = {s.lower() for s in severity_filter} if severity_filter else None

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
            
            # --- Setup Filtering ---
            is_all = False
            if status_filter:
                status_set = {s.lower().strip() for s in status_filter}
                if "all" in status_set:
                    is_all = True
            else:
                status_set = None

            sev_set = {s.lower() for s in severity_filter} if severity_filter else None
            
            import re as _re
            vid_inc_re = _re.compile(vid_include) if vid_include else None
            vid_exc_re = _re.compile(_re.escape(vid_exclude)) if vid_exclude else None
            # Actually, vid_exclude is usually a regex search too
            if vid_exclude:
                try:
                    vid_exc_re = _re.compile(vid_exclude)
                except _re.error:
                    vid_exc_re = _re.compile(_re.escape(vid_exclude))
            
            vid_list_set = {v.strip().upper() for v in vid_list} if vid_list else None

            for idx, group in enumerate(groups, 1):
                with suppress(ValueError, AttributeError, KeyError):
                    fix = self._parse_group(group)
                    if not fix:
                        continue

                    # VID List Filter
                    if vid_list_set and fix.vid not in vid_list_set:
                        continue
                    
                    # VID Regex Filters
                    if vid_inc_re and not vid_inc_re.search(fix.vid):
                        continue
                    if vid_exc_re and vid_exc_re.search(fix.vid):
                        continue

                    # Severity filter
                    if sev_set and fix.severity.lower() not in sev_set:
                        continue

                    # Universal Status Filter
                    include = True
                    if not is_all and status_set and self.checklist_path:
                        current_status = self.statuses.get(fix.vid, "not_reviewed").lower().replace(" ", "_").strip()
                        if current_status not in status_set:
                            include = False

                    if include:
                        self.fixes.append(fix)
                        self.stats["with_fix"] += 1
                        self.stats["by_severity"][fix.severity.lower()] += 1
                        if fix.fix_command:
                            self.stats["with_command"] += 1
                        if fix.check_command:
                            self.stats["with_check"] += 1
                        if not fix.fix_command and not fix.check_command:
                            self.stats["manual_review"].append(fix.vid)
                        self.stats["platforms"][fix.platform] += 1

            filter_msg = []
            if is_all:
                filter_msg.append("ALL checks")
            elif status_filter:
                filter_msg.append(f"Status: {', '.join(status_filter)}")
            if severity_filter:
                filter_msg.append(f"Severity: {', '.join(severity_filter)}")
            if vid_list:
                filter_msg.append(f"VID List: {len(vid_list)} items")
            if vid_include:
                filter_msg.append(f"Inc: {vid_include}")
            
            filter_str = f" [Filtered by: {' | '.join(filter_msg)}]" if filter_msg else ""

            LOG.i(
                f"Extracted {len(self.fixes)} fixes "
                f"({self.stats['with_command']} with actionable commands)"
                f"{filter_str}"
            )
            return self.fixes

    def _load_statuses(self) -> None:
        """Extract vulnerability statuses from provided checklist."""
        if not self.checklist_path:
            return
        try:
            if self.checklist_path.suffix.lower() == ".cklb":
                data = FO.parse_cklb(self.checklist_path)
                reviews = data.get("reviews", [])
                for rev in reviews:
                    vid = rev.get("Vuln_Num") or rev.get("vid")
                    status = rev.get("status")
                    if vid and status:
                        self.statuses[San.vuln(str(vid))] = str(status).strip()
            else:
                tree = FO.parse_xml(self.checklist_path)
                root = tree.getroot()
                for vuln in root.findall(".//VULN"):
                    vid = None
                    for sd in vuln.findall("STIG_DATA"):
                        if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num":
                            vid = sd.findtext("ATTRIBUTE_DATA")
                            break
                    status_node = vuln.find("STATUS")
                    if vid and status_node is not None:
                        status = (status_node.text or "").strip()
                        if status:
                            self.statuses[San.vuln(str(vid))] = status
            LOG.i(f"Loaded {len(self.statuses)} statuses from {self.checklist_path.name}")
        except Exception as e:
            LOG.w(f"Failed to load statuses from checklist: {e}")

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

        # Enhance with structured description metadata
        desc_node = find("description")
        desc_text = text(desc_node) if desc_node is not None else ""
        meta = XmlUtils.parse_description(desc_text)

        check_node = find("check")
        check_text_raw = ""
        if check_node is not None:
            ct = check_node.find("ns:check-content", self.ns) if self.ns else check_node.find("check-content")
            check_text_raw = text(ct) if ct is not None else ""

        return Fix(
            vid=vid,
            rule_id=rule_id,
            severity=severity,
            title=title,
            group_title=group_title,
            fix_text=fix_text_raw,
            fix_command=fix_command,
            check_command=check_command,
            platform=platform,
            rule_version=rule_version,
            cci=cci_refs,
            legacy=legacy_refs,
            discussion=meta.get("discussion", ""),
            mitigation=meta.get("mitigation", ""),
            check_text=check_text_raw,
            false_positives=meta.get("false_positives", ""),
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
        candidates.extend(self.NETWORK_PROMPT.findall(text_block))
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

mkdir -p evidence
echo "Remediation started (Output mapping to evidence/ folder)" | tee -a "$LOG_FILE"
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
# ═══ EVIDENCE CAPTURE ═══
EVID_LOG="evidence/%{vid}_out.log"
echo "--- PRE-FIX CHECK ---" > "$EVID_LOG"
%{check_block} >> "$EVID_LOG" 2>&1 || true

# ═══ FIX ═══
echo "--- APPLYING FIX ---" >> "$EVID_LOG"
{
%{cmd}
} >> "$EVID_LOG" 2>&1
if [ $? -eq 0 ]; then
  echo "  ✔ Remediation Success" | tee -a "$LOG_FILE"
  # ═══ VERIFY ═══
  echo "--- POST-FIX VERIFY ---" >> "$EVID_LOG"
  %{check_block} >> "$EVID_LOG" 2>&1 && echo "  ✔ Evidence: Check now PASSES" | tee -a "$LOG_FILE" || echo "  ! Evidence: Manual check required" | tee -a "$LOG_FILE"
  record_result "%{vid}" true "success"
  ((PASS++))
else
  echo "  ✘ Remediation Failed (See $EVID_LOG)" | tee -a "$LOG_FILE"
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
            check_block = ""
            verify_block = ""
            if fix.check_command:
                check_block = fix.check_command

                verify_block = f"""echo "  [VERIFY] Running post-fix verification..." | tee -a "$LOG_FILE"
{{
{indented_check}
}} >>"$LOG_FILE" 2>&1 && echo "  ✔ Evidence: Check now PASSES (CLOSED)" | tee -a "$LOG_FILE" || echo "  ! Evidence: Check still FAILS" | tee -a "$LOG_FILE" """

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
                        check_block=check_block,
                        verify_block=verify_block
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

$$ErrorActionPreference = 'Continue'
$$DryRun = %{dry_run}
$$Log = "stig_fix_$$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$$Results = @()
if (-not (Test-Path "evidence")) { New-Item -ItemType Directory -Path "evidence" | Out-Null }
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

        live_fix_tmpl = PsTemplate("""Write-Host "[%{idx}/%{total}] %{vid} - %{title}" -ForegroundColor Cyan
$$EvidLog = "evidence\\%{vid}_out.log"
"--- PRE-FIX CHECK ---" | Out-File $$EvidLog -Encoding utf8
try { %{check_block} | Out-File $$EvidLog -Append -Encoding utf8 } catch { "Check failed: $$($$_)" | Out-File $$EvidLog -Append }

# ═══ FIX ═══
"--- APPLYING FIX ---" | Out-File $$EvidLog -Append -Encoding utf8
try {
%{cmd} | Out-File $$EvidLog -Append -Encoding utf8
    Write-Host "  ✔ Remediation Success" -ForegroundColor Green
    
    # ═══ VERIFY ═══
    "--- POST-FIX VERIFY ---" | Out-File $$EvidLog -Append -Encoding utf8
    try { 
        %{check_block} | Out-File $$EvidLog -Append -Encoding utf8
        Write-Host "  ✔ Evidence: Check now PASSES" -ForegroundColor Green
    } catch { 
        Write-Host "  ! Evidence: Manual verification suggested" -ForegroundColor Yellow
    }
    Add-Result "%{vid}" $$true "success"
} catch {
    Write-Warning "  ✘ Remediation Failed: $$($$_.Exception.Message)"
    "ERROR: $$($$_.Exception.Message)" | Out-File $$EvidLog -Append -Encoding utf8
    Add-Result "%{vid}" $$false $$_.Exception.Message
}
""")

        dry_fix_tmpl = PsTemplate("""Write-Host "[%{idx}/%{total}] %{vid} - %{title}"
Write-Host "  [DRY-RUN] Would execute:`n%{cmd}"
Add-Result "%{vid}" $$true "dry_run"
Continue
""")

        for idx, fix in enumerate(fixes, 1):
            check_block = ""
            verify_block = ""
            if fix.check_command:
                indented_check = "\n".join(f"    {line}" for line in fix.check_command.splitlines())
                check_block = f"""Write-Host "  [CHECK] Running evidence collection..."
try {{
{indented_check}
}} catch {{ Write-Host "  ! Check command failed (Expected if finding is OPEN)" }}"""

                verify_block = f"""Write-Host "  [VERIFY] Running post-fix verification..."
try {{
{indented_check}
    Write-Host "  ✔ Evidence: Check now PASSES (CLOSED)" -ForegroundColor Green
}} catch {{ Write-Host "  ! Evidence: Check still FAILS" -ForegroundColor Yellow }}"""

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
                        check_block=check_block,
                        verify_block=verify_block
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

    def to_evidence_bash(
        self,
        path: Union[str, Path],
    ) -> None:
        """
        Generate Bash evidence gathering script.

        Args:
            path: Output .sh file path
        """
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.check_command and fix.platform in ("linux", "generic")
        ]
        if not fixes:
            LOG.w("No Linux/generic fixes with check commands found")
            return

        class BashTemplate(string.Template):
            delimiter = "%"

        header = BashTemplate("""#!/usr/bin/env bash
# Auto-generated evidence gathering script
# Generated: %{dt}

EVIDENCE_DIR="stig_evidence_$$(date +%%Y%%m%%d_%%H%%M%%S)"
mkdir -p "$EVIDENCE_DIR"
LOG_FILE="$EVIDENCE_DIR/gathering.log"
MANIFEST="$EVIDENCE_DIR/manifest.csv"

echo "Evidence gathering started" | tee -a "$LOG_FILE"
echo "VID,Status,Output_File" > "$MANIFEST"

run_check() {
  local vid="$1"
  local title="$2"
  local out_file="$EVIDENCE_DIR/$${vid}.txt"
  
  echo "[*] Gathering evidence for $vid - $title" | tee -a "$LOG_FILE"
  echo "--- EVIDENCE FOR $vid ---" > "$out_file"
  echo "Title: $title" >> "$out_file"
  echo "Timestamp: $$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" >> "$out_file"
  echo "------------------------" >> "$out_file"
  return 0
}
""").substitute(dt=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

        lines = [header]
        
        check_tmpl = BashTemplate("""
run_check "%{vid}" "%{title}"
{
%{cmd}
} >>"$EVIDENCE_DIR/%{vid}.txt" 2>&1
if [ $? -eq 0 ]; then
  echo "%{vid},PASS,$EVIDENCE_DIR/%{vid}.txt" >> "$MANIFEST"
else
  echo "%{vid},FAIL,$EVIDENCE_DIR/%{vid}.txt" >> "$MANIFEST"
fi
""")

        for fix in fixes:
            lines.append(
                check_tmpl.substitute(
                    vid=fix.vid,
                    title=fix.title[:60].replace('"', '\\"'),
                    cmd=fix.check_command
                )
            )

        lines.append('\necho "Evidence gathering complete. Results in $EVIDENCE_DIR"')

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))
        
        if not Cfg.IS_WIN:
            with suppress(OSError):
                os.chmod(path, 0o750)
        LOG.i(f"Bash evidence script generated: {path} ({len(fixes)} checks)")

    def to_evidence_powershell(
        self,
        path: Union[str, Path],
    ) -> None:
        """
        Generate PowerShell evidence gathering script.

        Args:
            path: Output .ps1 file path
        """
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.check_command and fix.platform == "windows"
        ]
        if not fixes:
            LOG.w("No Windows fixes with check commands found")
            return

        class PsTemplate(string.Template):
            delimiter = "%"

        header = PsTemplate("""# Auto-generated evidence gathering script
# Generated: %{dt}

$EvidenceDir = "stig_evidence_$$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
$LogFile = "$EvidenceDir/gathering.log"
$Manifest = "$EvidenceDir/manifest.csv"

"VID,Status,Output_File" | Out-File $Manifest -Encoding utf8
Write-Host "Evidence gathering started. Logging to $LogFile"

function Run-Check {
    param($vid, $title, $cmd)
    $outFile = "$EvidenceDir/$($vid).txt"
    Write-Host "[*] Gathering evidence for $vid - $title"
    "--- EVIDENCE FOR $vid ---" | Out-File $outFile -Encoding utf8
    "Title: $title" | Out-File $outFile -Append
    "Timestamp: $$(Get-Date -Format 'o')" | Out-File $outFile -Append
    "------------------------" | Out-File $outFile -Append
    
    try {
        Invoke-Expression $cmd | Out-File $outFile -Append
        "$vid,PASS,$outFile" | Out-File $Manifest -Append
    } catch {
        "Error: $$($$_.Exception.Message)" | Out-File $outFile -Append
        "$vid,FAIL,$outFile" | Out-File $Manifest -Append
    }
}
""").substitute(dt=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

        lines = [header]

        for fix in fixes:
            cmd_escaped = fix.check_command.replace('"', '`"').replace('$', '`$')
            lines.append(
                f'Run-Check -vid "{fix.vid}" -title "{fix.title[:60]}" -cmd @\'\n{fix.check_command}\n\'@'
            )

        lines.append('\nWrite-Host "Evidence gathering complete. Results in $EvidenceDir"')

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))
        
        LOG.i(f"PowerShell evidence script generated: {path} ({len(fixes)} checks)")

    def stats_summary(self) -> Dict[str, Any]:
        """
        Get enhanced extraction statistics summary.

        Returns:
            Dictionary with extraction statistics including severity
            breakdown, actionability metrics, and manual review list.
        """
        manual_review = self.stats.get("manual_review", [])
        return {
            "total_groups": self.stats["total_groups"],
            "with_fix": self.stats["with_fix"],
            "with_command": self.stats["with_command"],
            "with_check": self.stats.get("with_check", 0),
            "with_both": sum(
                1 for f in self.fixes if f.fix_command and f.check_command
            ),
            "platforms": dict(self.stats["platforms"]),
            "by_severity": dict(self.stats.get("by_severity", {})),
            "manual_review_count": len(manual_review),
            "manual_review_vids": manual_review[:50],
            "filtered": len(self.fixes),
        }

    def to_markdown(self, path: Union[str, Path]) -> str:
        """
        Export fixes as a structured Markdown remediation runbook.

        Organized by severity → platform → VID for team use.

        Args:
            path: Output file path.

        Returns:
            Path to the generated file.
        """
        path = Path(path)
        lines = [
            f"# STIG Remediation Runbook",
            f"",
            f"**Source:** `{self.xccdf.name}`  ",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Total Fixes:** {len(self.fixes)}  ",
            f"**Actionable Commands:** {self.stats['with_command']}  ",
            f"",
            "---",
            "",
        ]

        # Group by severity then platform
        by_sev: Dict[str, Dict[str, List[Fix]]] = {}
        for fix in self.fixes:
            sev = fix.severity.upper()
            plat = fix.platform
            if sev not in by_sev:
                by_sev[sev] = {}
            if plat not in by_sev[sev]:
                by_sev[sev][plat] = []
            by_sev[sev][plat].append(fix)

        sev_order = ["HIGH", "MEDIUM", "LOW"]
        for sev in sev_order:
            if sev not in by_sev:
                continue
            cat = {"HIGH": "I", "MEDIUM": "II", "LOW": "III"}.get(sev, "?")
            total_in_sev = sum(len(v) for v in by_sev[sev].values())
            lines.append(f"## CAT {cat} — {sev} ({total_in_sev} findings)")
            lines.append("")

            for platform, fixes in sorted(by_sev[sev].items()):
                lines.append(f"### Platform: {platform} ({len(fixes)} fixes)")
                lines.append("")

                for fix in fixes:
                    status_tag = ""
                    if self.statuses.get(fix.vid):
                        status_tag = f" `{self.statuses[fix.vid]}`"
                    lines.append(f"#### {fix.vid}{status_tag} — {fix.title[:100]}")
                    lines.append("")

                    if fix.fix_command:
                        lines.append("**Fix Command:**")
                        lines.append(f"```")
                        lines.append(fix.fix_command)
                        lines.append(f"```")
                        lines.append("")

                    if fix.check_command:
                        lines.append("**Check Command:**")
                        lines.append(f"```")
                        lines.append(fix.check_command)
                        lines.append(f"```")
                        lines.append("")

                    if not fix.fix_command and not fix.check_command:
                        lines.append(f"**Manual Review Required**")
                        lines.append("")
                        if fix.fix_text:
                            lines.append(f"> {fix.fix_text[:300]}")
                            lines.append("")

                    lines.append("- [ ] Completed")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        LOG.i(f"Markdown runbook generated: {path} ({len(self.fixes)} fixes)")
        return str(path)


__all__ = ["FixExt"]

