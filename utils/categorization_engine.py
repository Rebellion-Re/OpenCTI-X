"""
ThreatFusion CTI - Behavioral TTP & Categorization Engine
Maps text artifacts to MITRE ATT&CK techniques, tactics, and operational categories.
"""

import re
from typing import List, Dict, Any


class CategorizationEngine:
    BEHAVIOR_RULES = [
        {
            "technique_id": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "patterns": [
                r"\bphishing\b", r"\bmalicious\s+attachment\b", r"\bmacro-enabled\b",
                r"\biso\s+image\b", r"\blnk\s+file\b", r"\bspear-?phishing\b"
            ]
        },
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "patterns": [
                r"\bexploit(ed|ing)?\s+vulnerability\b", r"\bzero-day\b", r"\brce\b",
                r"\bremote\s+code\s+execution\b", r"\bpublic-facing\b"
            ]
        },
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "patterns": [
                r"\bpowershell\.exe\b", r"\bpwsh\b", r"\bdownloadstring\b",
                r"\binvoke-expression\b", r"\b-enc\s+[a-zA-Z0-9+/=]{10,}\b", r"\biex\b"
            ]
        },
        {
            "technique_id": "T1059.003",
            "technique_name": "Windows Command Shell",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "patterns": [
                r"\bcmd\.exe\b", r"\b/c\s+net\s+user\b", r"\b/c\s+ping\b",
                r"\b/c\s+echo\b", r"\bbatch\s+script\b"
            ]
        },
        {
            "technique_id": "T1047",
            "technique_name": "Windows Management Instrumentation",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "patterns": [
                r"\bwmic\.exe\b", r"\bwmic\s+process\s+call\s+create\b",
                r"\bmanagementobjectsearcher\b", r"\bwmi\s+query\b"
            ]
        },
        {
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys / Startup Folder",
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "patterns": [
                r"currentversion\\run", r"currentversion\\runonce",
                r"\bstartup\s+folder\b", r"\breg\s+add\b.*run"
            ]
        },
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task",
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "patterns": [
                r"\bschtasks\.exe\b", r"\b/create\s+/tn\b", r"\bscheduled\s+task\b"
            ]
        },
        {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "patterns": [
                r"\bprocess\s+injection\b", r"\bprocess\s+hollowing\b",
                r"\bcreateremotethread\b", r"\bvirtualallocex\b", r"\bwriteprocessmemory\b"
            ]
        },
        {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "patterns": [
                r"\bobfuscat(ed|ion)\b", r"\bbase64-encoded\b", r"\bxor\s+encrypt(ed|ion)\b",
                r"\bpacking\b", r"\bpacked\s+with\s+upx\b"
            ]
        },
        {
            "technique_id": "T1562.001",
            "technique_name": "Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "patterns": [
                r"\bdisable\s+(defender|antivirus|edr|security)\b",
                r"\bset-mppreference\s+-disablerealtime\b",
                r"\bstop-service\b.*(windefend|sentinel|crowdstrike)"
            ]
        },
        {
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "patterns": [
                r"\blsass\.exe\b", r"\bsekurlsa::logonpasswords\b",
                r"\bprocdump.*lsass\b", r"\bcomsvcs\.dll.*minidump\b"
            ]
        },
        {
            "technique_id": "T1555",
            "technique_name": "Credentials from Password Stores",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "patterns": [
                r"\bcredential\s+stealer\b", r"\bbrowser\s+passwords\b",
                r"\blogin\s+data\b", r"\bvaultcli\.dll\b"
            ]
        },
        {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "patterns": [
                r"\bsysteminfo\.exe\b", r"\buname\s+-a\b", r"\bwhoami\b",
                r"\bnet\s+view\b", r"\bhostname\b"
            ]
        },
        {
            "technique_id": "T1087",
            "technique_name": "Account Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "patterns": [
                r"\bnet\s+user\b", r"\bnet\s+group\s+.*domain admins.*\b",
                r"\bget-aduser\b", r"\bdsquery\s+user\b"
            ]
        },
        {
            "technique_id": "T1021.002",
            "technique_name": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "patterns": [
                r"\bpsexec\b", r"\bc\$\b", r"\badmin\$\b", r"\bipc\$\b",
                r"\bsmb\s+traffic\b", r"\bport\s+445\b"
            ]
        },
        {
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop Protocol",
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "patterns": [
                r"\brdp\b", r"\bremote\s+desktop\b", r"\bmstsc\.exe\b", r"\bport\s+3389\b"
            ]
        },
        {
            "technique_id": "T1071.001",
            "technique_name": "Web Protocols (HTTP/S)",
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "patterns": [
                r"\bc2\s+beaconing\b", r"\bc2\s+over\s+https?\b",
                r"\bpost\s+request\s+to\s+c2\b", r"\buser-agent\s+header\b"
            ]
        },
        {
            "technique_id": "T1573",
            "technique_name": "Encrypted Channel",
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "patterns": [
                r"\btls\s+tunnel\b", r"\bcustom\s+encryption\b",
                r"\brsa\s+handshake\b", r"\baes-256\s+encrypted\s+c2\b"
            ]
        },
        {
            "technique_id": "T1567",
            "technique_name": "Exfiltration Over Web Service",
            "tactic": "Exfiltration",
            "tactic_id": "TA0010",
            "patterns": [
                r"\bexfiltrat(ed|ion)\b", r"\bmeganz\b", r"\brclone\b",
                r"\bdropbox\s+api\b", r"\bdiscord\s+webhook\b", r"\btelegram\s+bot\b"
            ]
        },
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "patterns": [
                r"\bransomware\b", r"\bencrypt(ed|ion)?\b", r"\bransom\s+note\b",
                r"\bvssadmin\s+delete\s+shadows\b", r"\bwbadmin\s+delete\s+catalog\b",
                r"\bvolume\s+shadow\b"
            ]
        },
        {
            "technique_id": "T1490",
            "technique_name": "Inhibit System Recovery",
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "patterns": [
                r"\bdelete\s+shadows\b", r"\bbcdedit\s+/set\b",
                r"\brecoveryenabled\s+no\b", r"\bignoreallfailures\b"
            ]
        }
    ]

    def __init__(self) -> None:
        self.compiled_rules = []
        for rule in self.BEHAVIOR_RULES:
            compiled_patterns = [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
            self.compiled_rules.append({
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic": rule["tactic"],
                "tactic_id": rule["tactic_id"],
                "patterns": compiled_patterns
            })

    def analyze_behaviors_and_ttps(self, text: str) -> Dict[str, Any]:
        matched_techniques = {}
        matched_tactics = set()
        ttp_descriptions = []

        for rule in self.compiled_rules:
            hits = 0
            for pat in rule["patterns"]:
                if pat.search(text):
                    hits += 1

            if hits > 0:
                tid = rule["technique_id"]
                matched_tactics.add(rule["tactic"])
                matched_techniques[tid] = {
                    "technique_id": tid,
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"],
                    "tactic_id": rule["tactic_id"],
                    "confidence": min(100.0, 50.0 + (hits * 15.0))
                }
                ttp_descriptions.append(f"{tid} ({rule['technique_name']}) - {rule['tactic']}")

        return {
            "mitre_techniques": list(matched_techniques.values()),
            "mitre_tactics": sorted(list(matched_tactics)),
            "ttps": ttp_descriptions
        }

    def determine_threat_category(
        self,
        actors: List[str],
        malware: List[str],
        cves: List[str],
        techniques: List[Dict[str, Any]],
        text: str
    ) -> str:
        tech_ids = {t["technique_id"] for t in techniques}
        text_lower = text.lower()

        if "T1486" in tech_ids or "T1490" in tech_ids or "ransomware" in text_lower:
            return "RANSOMWARE"

        if any(act.startswith("APT") or "Group" in act or "Bear" in act or "Chollima" in act for act in actors):
            return "APT_ESPIONAGE"

        if len(cves) > 0 and ("T1190" in tech_ids or "exploit" in text_lower or "zero-day" in text_lower):
            return "VULNERABILITY_EXPLOIT"

        if len(malware) > 0:
            return "COMMODITY_MALWARE"

        return "OSINT_ADVISORY"
