"""MITRE inference, command-line heuristics, and text signals (Splunk ES / Falcon parity hooks)."""

from __future__ import annotations

import re
from typing import Any


_TACTIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("initial_access", re.compile(r"phish|spear|drive[\s-]?by|exploit|cve-\d", re.I)),
    ("execution", re.compile(r"powershell|cmd\.exe|rundll32|mshta|wscript|cscript|regsvr32", re.I)),
    ("persistence", re.compile(r"schtasks|cron|launchctl|run\s*key|startup|service\s+create", re.I)),
    ("privilege_escalation", re.compile(r"token|uac|sudo|getsystem|elevat", re.I)),
    ("defense_evasion", re.compile(r"obfuscat|encode|xor|amsi|unhook|disable|tamper", re.I)),
    ("credential_access", re.compile(r"mimikatz|lsass|sam|hashdump|keylog|brute", re.I)),
    ("discovery", re.compile(r"net\s+view|whoami|nltest|ldap|adfind|bloodhound", re.I)),
    ("lateral_movement", re.compile(r"psexec|wmic|winrm|rdp|smb|ssh|dcom", re.I)),
    ("collection", re.compile(r"compress|archive|clipboard|screen\s*cap", re.I)),
    ("exfiltration", re.compile(r"upload|dns\s*exfil|https.*post|mega\.nz|dropbox", re.I)),
    ("command_and_control", re.compile(r"beacon|callback|c2|tor|ngrok|reverse\s*shell", re.I)),
]

_TECHNIQUE_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("T1566", re.compile(r"phish|attachment|macro", re.I)),
    ("T1059", re.compile(r"powershell|bash|python|script", re.I)),
    ("T1021", re.compile(r"rdp|remote\s*desktop|winrm|ssh", re.I)),
    ("T1078", re.compile(r"impersonat|pass[\s-]?the[\s-]?hash|golden\s*ticket", re.I)),
    ("T1486", re.compile(r"encrypt|ransom|bitcoin|decryptor", re.I)),
    ("T1190", re.compile(r"exploit|sql\s*inj| deserialization|log4j", re.I)),
]


def infer_mitre_from_text(text: str) -> tuple[list[str], list[str]]:
    if not text:
        return [], []
    tactics = [name for name, pat in _TACTIC_PATTERNS if pat.search(text)]
    techs = [tid for tid, pat in _TECHNIQUE_HINTS if pat.search(text)]
    return sorted(set(tactics)), sorted(set(techs))


def elevation_score_from_command_line(cmd: str | None) -> float:
    if not cmd:
        return 0.0
    c = cmd.lower()
    score = 0.0
    if "runas" in c or "/elevated" in c:
        score += 0.35
    if "token" in c and "priv" in c:
        score += 0.35
    if "sekurlsa" in c or "mimikatz" in c:
        score += 0.5
    return min(1.0, score)


def supply_chain_hint_from_command_line(cmd: str | None) -> tuple[str | None, str | None]:
    """Return (ecosystem, package_guess) for npm/pip/go mod style installs."""
    if not cmd:
        return None, None
    m = re.search(r"npm\s+install\s+([^\s]+)", cmd, re.I)
    if m:
        return "npm", m.group(1).strip("\"'")
    m = re.search(r"pip(?:3)?\s+install\s+([^\s]+)", cmd, re.I)
    if m:
        return "pip", m.group(1).strip("\"'")
    m = re.search(r"go\s+get\s+([^\s]+)", cmd, re.I)
    if m:
        return "go", m.group(1).strip("\"'")
    return None, None


def splunk_risk_tags(raw: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    st = str(raw.get("sourcetype") or raw.get("source") or "").lower()
    if "auth" in st or "vpn" in st:
        tags.append("authentication_volume")
    if "proxy" in st or "web" in st:
        tags.append("web_proxy")
    if "endpoint" in st or "sysmon" in st or "win_event_log" in st:
        tags.append("endpoint_telemetry")
    return tags
