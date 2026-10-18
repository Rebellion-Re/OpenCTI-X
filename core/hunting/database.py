"""
ThreatFusion CTI - Threat Hunting Database Engine
Manages Sigma, KQL, Splunk SPL, and YARA detection signatures.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from config.settings import SIGNATURES_DIR
from config.logging_config import setup_logger

logger = setup_logger("HuntDatabase")


class HuntDatabase:
    """Repository and search engine for detection rules and hunting logic."""

    DEFAULT_QUERIES = [
        {
            "query_id": "HUNT-001",
            "name": "PowerShell Encoded Command & DownloadString",
            "platform": "Azure Sentinel (KQL)",
            "technique_id": "T1059.001",
            "severity": "High",
            "query": (
                "DeviceProcessEvents\n"
                "| where FileName in~ ('powershell.exe', 'pwsh.exe')\n"
                "| where ProcessCommandLine has_any ('DownloadString', 'Invoke-Expression', 'IEX', '-enc', '-encodedcommand')\n"
                "| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine"
            )
        },
        {
            "query_id": "HUNT-002",
            "name": "LSASS Memory Dump via Native Utilities",
            "platform": "Splunk (SPL)",
            "technique_id": "T1003.001",
            "severity": "Critical",
            "query": (
                'index=windows EventCode=10 TargetImage="*\\lsass.exe" '
                'GrantedAccess IN ("0x1010", "0x1410", "0x1F0FFF") '
                '| stats count by _time, Computer, SourceImage, TargetImage, GrantedAccess'
            )
        },
        {
            "query_id": "HUNT-003",
            "name": "Suspicious Scheduled Task Creation via Schtasks",
            "platform": "Sigma / Generic",
            "technique_id": "T1053.005",
            "severity": "Medium",
            "query": (
                "title: Suspicious Scheduled Task Creation\n"
                "status: production\n"
                "description: Detects scheduled task creation invoking cmd or powershell\n"
                "logsource:\n"
                "    category: process_creation\n"
                "    product: windows\n"
                "detection:\n"
                "    selection:\n"
                "        Image|endswith: '\\schtasks.exe'\n"
                "        CommandLine|contains: '/create'\n"
                "    condition: selection"
            )
        },
        {
            "query_id": "HUNT-004",
            "name": "Cobalt Strike Beacon HTTP/S Malleable C2",
            "platform": "Splunk (SPL)",
            "technique_id": "T1071.001",
            "severity": "High",
            "query": (
                'index=network sourcetype="pan:traffic" OR sourcetype="zeek:http" '
                'uri_path IN ("/api/v1*", "/submit.php*", "/telemetry*") '
                '| stats count, sum(bytes_out) as total_out by src_ip, dest_ip, http_user_agent'
            )
        }
    ]

    def __init__(self, signatures_dir: Optional[Path] = None) -> None:
        self.signatures_dir = signatures_dir or SIGNATURES_DIR
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        self.signatures: List[Dict[str, Any]] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Loads and indexes rule signatures from disk, seeding defaults if empty."""
        self.signatures = list(self.DEFAULT_QUERIES)

        for file_path in self.signatures_dir.glob("**/*.*"):
            if file_path.suffix.lower() in [".json", ".yaml", ".yml", ".kql", ".spl", ".yar", ".yara"]:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        raw_content = f.read()

                    self.signatures.append({
                        "query_id": f"FILE-{file_path.stem}",
                        "name": file_path.stem.replace("_", " ").title(),
                        "platform": file_path.suffix.lower().lstrip(".").upper(),
                        "technique_id": "N/A",
                        "severity": "Informational",
                        "query": raw_content,
                    })
                except Exception as e:
                    logger.warning(f"Failed to read signature {file_path.name}: {e}")

    def load_all_queries(self) -> pd.DataFrame:
        """Returns all loaded detection queries as a DataFrame for UI consumption."""
        if not self.signatures:
            return pd.DataFrame(columns=["query_id", "name", "platform", "technique_id", "severity", "query"])
        return pd.DataFrame(self.signatures)

    def get_all_rules(self) -> pd.DataFrame:
        """Alias for load_all_queries."""
        return self.load_all_queries()

    def search_rules(self, query: str) -> pd.DataFrame:
        """Searches rules by query string across name, platform, and content."""
        if not query:
            return self.load_all_queries()

        q = query.lower()
        matched = [
            r for r in self.signatures
            if q in r.get("name", "").lower() or q in r.get("platform", "").lower() or q in r.get("query", "").lower()
        ]
        if not matched:
            return pd.DataFrame(columns=["query_id", "name", "platform", "technique_id", "severity", "query"])
        return pd.DataFrame(matched)

    def get_rule_by_id(self, query_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single rule definition by its identifier."""
        for rule in self.signatures:
            if rule.get("query_id") == query_id:
                return rule
        return None
