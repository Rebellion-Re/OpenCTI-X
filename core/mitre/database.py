"""
ThreatFusion CTI - MITRE ATT&CK Parquet Knowledge Base
Manages tabular schemas, indexed lookups, and fast DuckDB analytical joins.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import duckdb
from config.settings import PROCESSED_DATA_DIR, PARQUET_COMPRESSION_CODEC
from config.logging_config import setup_logger
from core.mitre.downloader import MitreDownloader

logger = setup_logger("MitreDatabase")


class MitreDatabase:
    # Official Enterprise ATT&CK 14 Tactics in execution order
    TACTIC_ORDER = [
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery", "lateral-movement",
        "collection", "command-and-control", "exfiltration", "impact"
    ]

    TACTIC_DISPLAY_NAMES = {
        "initial-access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "defense-evasion": "Defense Evasion",
        "credential-access": "Credential Access",
        "discovery": "Discovery",
        "lateral-movement": "Lateral Movement",
        "collection": "Collection",
        "command-and-control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
        "reconnaissance": "Reconnaissance",
        "resource-development": "Resource Development"
    }

    def __init__(self, storage_dir: Optional[Path] = None) -> None:
        self.storage_dir = storage_dir or PROCESSED_DATA_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.duck_conn = duckdb.connect(database=":memory:")
        self.techniques_parquet = self.storage_dir / "mitre_techniques.parquet"
        self.relations_parquet = self.storage_dir / "mitre_relations.parquet"
        self.groups_parquet = self.storage_dir / "mitre_groups.parquet"
        self.software_parquet = self.storage_dir / "mitre_software.parquet"

    def sync_from_upstream(self, force_refresh: bool = False) -> None:
        """
        Fetches, parses, and persists structured ATT&CK Parquet tables.
        """
        downloader = MitreDownloader()
        bundle = downloader.fetch_stix_bundle(force_refresh=force_refresh)
        parsed = downloader.parse_bundle(bundle)

        id_map = parsed["id_map"]

        # Techniques DataFrame
        df_tech = pd.DataFrame(parsed["techniques"])
        df_tech.to_parquet(self.techniques_parquet, compression=PARQUET_COMPRESSION_CODEC)

        # Groups DataFrame
        df_groups = pd.DataFrame(parsed["groups"])
        df_groups.to_parquet(self.groups_parquet, compression=PARQUET_COMPRESSION_CODEC)

        # Software DataFrame
        df_software = pd.DataFrame(parsed["software"])
        df_software.to_parquet(self.software_parquet, compression=PARQUET_COMPRESSION_CODEC)

        # Resolve STIX ID relationships to Canonical IDs
        mapped_relations: List[Dict[str, Any]] = []
        for rel in parsed["relationships"]:
            s_ref = rel["source_ref"]
            t_ref = rel["target_ref"]

            s_obj = id_map.get(s_ref)
            t_obj = id_map.get(t_ref)

            if not s_obj or not t_obj:
                continue

            s_id = s_obj.get("technique_id") or s_obj.get("group_id") or s_obj.get("software_id") or s_obj.get("camp
            t_id = t_obj.get("technique_id") or t_obj.get("group_id") or t_obj.get("software_id") or t_obj.get("camp
            mapped_relations.append({
                "source_id": s_id,
                "source_name": s_obj.get("name", ""),
                "source_type": s_ref.split("--")[0],
                "relationship": rel["relationship_type"],
                "target_id": t_id,
                "target_name": t_obj.get("name", ""),
                "target_type": t_ref.split("--")[0],
                "description": rel["description"]
            })

        df_rel = pd.DataFrame(mapped_relations)
        df_rel.to_parquet(self.relations_parquet, compression=PARQUET_COMPRESSION_CODEC)
        logger.info("Successfully updated all MITRE Parquet tables.")

    def get_techniques(self) -> pd.DataFrame:
        if not self.techniques_parquet.exists():
            self.sync_from_upstream()
        return pd.read_parquet(self.techniques_parquet)

    def get_relations(self) -> pd.DataFrame:
        if not self.relations_parquet.exists():
            self.sync_from_upstream()
        return pd.read_parquet(self.relations_parquet)

    def get_groups(self) -> pd.DataFrame:
        if not self.groups_parquet.exists():
            self.sync_from_upstream()
        return pd.read_parquet(self.groups_parquet)

    def get_software(self) -> pd.DataFrame:
        if not self.software_parquet.exists():
            self.sync_from_upstream()
        return pd.read_parquet(self.software_parquet)
