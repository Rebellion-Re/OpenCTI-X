import re
from typing import List, Dict, Any

class MitreTagger:
    TECHNIQUE_RULES: Dict[str, Dict[str, Any]] = {
        "T1059.001": {
            "name": "PowerShell",
            "tactic": "Execution",
            "regex": re.compile(r'\b(powershell|pwsh|invoke-expression|iex|downloadstring)\b', re.I)
        },
        "T1059.003": {
            "name": "Windows Command Shell",
            "tactic": "Execution",
            "regex": re.compile(r'\b(cmd\.exe|\/c\s+dir|\/c\s+copy|\/c\s+net\s+user)\b', re.I)
        },
        "T1486": {
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "regex": re.compile(r'\b(encrypt(ed|ion)?|ransom\s*note|\.locked|decryptor|vssadmin\s+delete\s+shadows)\
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "regex": re.compile(r'\b(mimikatz|lsass|procdump|sekurlsa|sam\s+hive|ntds\.dit)\b', re.I)
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Defense Evasion",
            "regex": re.compile(r'\b(compromised\s+credentials|default\s+password|credential\s+stuffing)\b', re.I)
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "regex": re.compile(r'\b(remote\s+code\s+execution|rce|zero-day|cve-202[0-9]-[0-9]+)\b', re.I)
        }
    }

    @classmethod
    def tag_text(cls, text: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for tid, data in cls.TECHNIQUE_RULES.items():
            if data["regex"].search(text):
                matches.append({
                    "technique_id": tid,
                    "technique_name": data["name"],
                    "tactic": data["tactic"]
                })
        return matches
