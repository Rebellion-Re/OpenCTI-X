"""
ThreatFusion CTI - Threat Hunting Query Database
Maintains multi-dialect query store (KQL, SPL, FQL, Sigma, YARA, Regex)
and provides vectorized analytical lookups.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import pandas as pd

from config.settings import SIGNATURES_DIR, PROCESSED_DATA_DIR, PARQUET_COMPRESSION_CODEC
from config.logging_config import setup_logger
from core.hunting.schema import HuntQueryRecord

logger = setup_logger("HuntDatabase")


class HuntDatabase:
    SUPPORTED_LANGUAGES = ["KQL", "SPL", "FQL", "SIGMA", "YARA", "REGEX"]

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.sig_dir = base_dir or SIGNATURES_DIR
        self.parquet_path = PROCESSED_DATA_DIR / "signatures.parquet"
        self._ensure_repo_layout()

    def _ensure_repo_layout(self) -> None:
        """Creates distinct directory trees for each hunting language."""
        for lang in self.SUPPORTED_LANGUAGES:
            (self.sig_dir / lang.lower()).mkdir(parents=True, exist_ok=True)
        PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def save_query(self, record: HuntQueryRecord) -> None:
        """
        Saves the raw query into its language vault and updates the Parquet table.
        """
        lang = record.language.upper()
        if lang not in self.SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported hunt query language: {lang}")

        # 1. Save raw file into directory vault
        ext_map = {
            "KQL": "kql", "SPL": "spl", "FQL": "fql",
            "SIGMA": "yml", "YARA": "yar", "REGEX": "json"
        }
        filename = f"{record.rule_id}.{ext_map[lang]}"
        file_path = self.sig_dir / lang.lower() / filename

        with open(file_path, "w", encoding="utf-8") as f:
            if lang == "REGEX":
                json.dump(record.to_dict(), f, indent=2)
            else:
                f.write(record.query_content)

        # 2. Update Lakehouse Parquet Table
        df_existing = self.load_all_queries()
        new_row = pd.DataFrame([record.to_dict()])

        if df_existing.empty:
            df_combined = new_row
        else:
            df_combined = pd.concat(
                [df_existing[df_existing["rule_id"] != record.rule_id], new_row],
                ignore_index=True
            )

        df_combined.to_parquet(self.parquet_path, compression=PARQUET_COMPRESSION_CODEC)
        logger.info(f"Persisted hunt query [{record.rule_id}] {record.title} ({lang})")

    def load_all_queries(self) -> pd.DataFrame:
        """Reads all hunt signatures from the columnar Parquet store."""
        if not self.parquet_path.exists():
            return pd.DataFrame(columns=[
                "rule_id", "title", "description", "language", "query_content",
                "severity", "status", "mitre_techniques", "mitre_tactics",
                "associated_actors", "associated_malware", "associated_campaigns",
                "data_sources", "false_positives", "author", "created_at", "updated_at"
            ])
        try:
            return pd.read_parquet(self.parquet_path)
        except Exception as e:
            logger.error(f"Failed to read hunt parquet database: {e}")
            return pd.DataFrame()

    def get_query_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        df = self.load_all_queries()
        if df.empty:
            return None
        match = df[df["rule_id"] == rule_id.strip()]
        if not match.empty:
            return match.iloc[0].to_dict()
        return None

    def seed_default_knowledge_base(self) -> None:
        """Populates the database with real production hunting queries across all dialects."""
        if self.parquet_path.exists() and len(self.load_all_queries()) > 0:
            return

        logger.info("Seeding default hunt signatures across KQL, SPL, FQL, Sigma, YARA, and Regex...")
        default_queries = [
            # KQL 1: PowerShell Download C2
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("KQL", "Suspicious PowerShell DownloadString Execution"),
                title="Suspicious PowerShell DownloadString Execution",
                description="Hunts for WebClient DownloadString or IEX cradle commands pulling remote payloads.",
                language="KQL",
                query_content=(
                    "DeviceProcessEvents\n"
                    "| where Timestamp > ago(7d)\n"
                    "| where FileName in~ ('powershell.exe', 'pwsh.exe')\n"
                    "| where ProcessCommandLine has_any ('DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr
                    "    and ProcessCommandLine has_any ('iex', 'Invoke-Expression', '-enc', '-encodedcommand')\n"
                    "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine,
                ),
                severity="HIGH",
                status="PRODUCTION",
                mitre_techniques=["T1059.001", "T1105"],
                mitre_tactics=["Execution", "Command and Control"],
                associated_actors=["APT28", "Lazarus Group", "FIN7"],
                associated_malware=["Cobalt Strike", "Emotet", "Qakbot"],
                associated_campaigns=["Operation StealPast"],
                data_sources=["Endpoint Process Telemetry", "Microsoft Defender for Endpoint"],
                false_positives=["Legitimate software deployment scripts using WebClient"]
            ),
            # KQL 2: LSASS Memory Dumping via Minidump
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("KQL", "LSASS Memory Dump via Comsvcs DLL"),
                title="LSASS Memory Dump via Comsvcs DLL",
                description="Detects abuse of rundll32 calling comsvcs.dll MiniDump export to dump LSASS process mem
                language="KQL",
                query_content=(
                    "DeviceProcessEvents\n"
                    "| where Timestamp > ago(14d)\n"
                    "| where FileName =~ 'rundll32.exe'\n"
                    "| where ProcessCommandLine has 'comsvcs' and ProcessCommandLine has 'MiniDump'\n"
                    "| project Timestamp, DeviceName, AccountCustomProperties, ProcessCommandLine, InitiatingProcess
                ),
                severity="CRITICAL",
                status="PRODUCTION",
                mitre_techniques=["T1003.001"],
                mitre_tactics=["Credential Access"],
                associated_actors=["APT29", "APT41", "LockBit"],
                associated_malware=["Mimikatz"],
                associated_campaigns=["SolarWinds Supply Chain"],
                data_sources=["Endpoint Process Telemetry"]
            ),
            # SPL 1: Lateral Movement via PsExec Service Creation
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("SPL", "PsExec Lateral Movement Service Execution"),
                title="PsExec Lateral Movement Service Execution",
                description="Identifies service installation of PsExec or renamed variations executing remote comman
                language="SPL",
                query_content=(
                    'index=windows EventCode=7045 Service_Name="PSEXESVC" OR Image_Path="*PSEXESVC.exe*"\n'
                    '| stats count min(_time) as first_seen max(_time) as last_seen by host, Service_Name, Image_Pat
                    '| eval duration=last_seen-first_seen\n'
                    '| sort - count'
                ),
                severity="HIGH",
                status="PRODUCTION",
                mitre_techniques=["T1543.003", "T1021.002"],
                mitre_tactics=["Persistence", "Lateral Movement"],
                associated_actors=["APT28", "Sandworm", "Wizard Spider"],
                associated_malware=["PsExec", "Impacket"],
                associated_campaigns=[],
                data_sources=["Windows System Event Log"]
            ),
            # LogScale FQL 1: Defense Evasion - Shadow Copy Deletion
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("FQL", "Volume Shadow Copy Deletion via VSSAdmin"),
                title="Volume Shadow Copy Deletion via VSSAdmin",
                description="Detects command-line execution disabling recovery or deleting shadow volumes.",
                language="FQL",
                query_content=(
                    '#event.module = "endpoint" AND #event.dataset = "process"\n'
                    '| ProcessCommandLine = /(vssadmin(\\.exe)?\\s+delete\\s+shadows|wmic(\\.exe)?\\s+shadowcopy\\s+
                    '| groupby([ComputerName, UserName], function=[count(), min(@timestamp), max(@timestamp)])'
                ),
                severity="CRITICAL",
                status="PRODUCTION",
                mitre_techniques=["T1490", "T1486"],
                mitre_tactics=["Impact"],
                associated_actors=["LockBit", "BlackCat", "Conti"],
                associated_malware=["LockBit 3.0", "ALPHV"],
                associated_campaigns=[],
                data_sources=["Humio Endpoint Stream", "CrowdStrike Falcon Process Events"]
            ),
            # Sigma 1: Scheduled Task Creation for Persistence
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("SIGMA", "Suspicious Scheduled Task Registering Script Execution
                title="Suspicious Scheduled Task Registering Script Execution",
                description="Hunts for schtasks.exe creating tasks designed to execute script engines.",
                language="SIGMA",
                query_content=(
                    "title: Suspicious Scheduled Task Script Engine Execution\n"
                    "id: a4c89012-45e1-4567-9102-349812903847\n"
                    "status: production\n"
                    "description: Detects creation of scheduled tasks targeting cmd, powershell, wscript, or mshta.\
                    "logsource:\n"
                    "    category: process_creation\n"
                    "    product: windows\n"
                    "detection:\n"
                    "    selection:\n"
                    "        Image|endswith: '\\schtasks.exe'\n"
                    "        CommandLine|contains:\n"
                    "            - '/create'\n"
                    "            - '/tn'\n"
                    "        CommandLine|contains|any:\n"
                    "            - 'powershell'\n"
                    "            - 'cmd.exe'\n"
                    "            - 'mshta.exe'\n"
                    "            - 'wscript.exe'\n"
                    "            - 'cscript.exe'\n"
                    "    condition: selection\n"
                    "level: high"
                ),
                severity="HIGH",
                status="PRODUCTION",
                mitre_techniques=["T1053.005"],
                mitre_tactics=["Persistence", "Execution"],
                associated_actors=["APT29", "APT41"],
                associated_malware=[],
                associated_campaigns=[],
                data_sources=["Windows Security 4688", "Sysmon Event ID 1"]
            ),
            # YARA 1: Cobalt Strike Beacon In-Memory Configuration
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("YARA", "CobaltStrike_Beacon_Memory_Signatures"),
                title="CobaltStrike Beacon Memory Signatures",
                description="Detects decrypted Cobalt Strike C2 reflective loaders and stage buffers.",
                language="YARA",
                query_content=(
                    "rule CobaltStrike_Beacon_Strings {\n"
                    "    meta:\n"
                    "        author = \"ThreatFusion CTI Research\"\n"
                    "        description = \"Detects unencrypted Cobalt Strike Beacon configurations and payloads\"\
                    "        threat_actor = \"APT28, APT29, Lazarus Group\"\n"
                    "        mitre_technique = \"T1071.001, T1055\"\n"
                    "    strings:\n"
                    "        $beacon_watermark = { 2e 2f 2e 2f 2e 2f 2e 2f }\n"
                    "        $pipe1 = \"\\\\\\\\.\\\\pipe\\\\msagent_\"\n"
                    "        $pipe2 = \"\\\\\\\\.\\\\pipe\\\\status_\"\n"
                    "        $str_http = \"/api/v1/telemetry\" ascii\n"
                    "        $cmd_arg = \"%s as %s\\\\%s: %d\" ascii\n"
                    "    condition:\n"
                    "        uint16(0) == 0x5A4D and (2 of ($pipe*) or ($beacon_watermark and $cmd_arg))\n"
                    "}"
                ),
                severity="CRITICAL",
                status="PRODUCTION",
                mitre_techniques=["T1071.001", "T1055"],
                mitre_tactics=["Command and Control", "Defense Evasion"],
                associated_actors=["APT28", "APT29", "Lazarus Group"],
                associated_malware=["Cobalt Strike"],
                associated_campaigns=["Operation StealPast"],
                data_sources=["Memory Forensics", "Process Virtual Memory Dumps"]
            ),
            # REGEX 1: Obfuscated Base64 Encoded Command Lines
            HuntQueryRecord(
                rule_id=HuntQueryRecord.generate_id("REGEX", "Base64 Obfuscated Execution String"),
                title="Base64 Obfuscated Execution String",
                description="High-precision regex to extract inline base64 blocks within command shell logs.",
                language="REGEX",
                query_content=r"(?:-[eE](?:nc|ncode[dD]?[cC]ommand)?\s+)([A-Za-z0-9+/]{40,}={0,2})",
                severity="MEDIUM",
                status="PRODUCTION",
                mitre_techniques=["T1027", "T1059.001"],
                mitre_tactics=["Defense Evasion", "Execution"],
                associated_actors=["APT41", "FIN7"],
                associated_malware=["Qakbot"],
                associated_campaigns=[],
                data_sources=["CLI Process Argument Logs", "Sysmon 1"]
            )
        ]

        for q in default_queries:
            self.save_query(q)
