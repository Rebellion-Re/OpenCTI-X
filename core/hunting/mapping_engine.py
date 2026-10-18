"""
ThreatFusion CTI - Hunt Relationship Mapping Engine
Correlates detection content with MITRE Techniques, Threat Actors, Malware, and Campaigns.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
from core.hunting.database import HuntDatabase
from config.logging_config import setup_logger

logger = setup_logger("HuntMappingEngine")


class HuntMappingEngine:
    def __init__(self, db: Optional[HuntDatabase] = None) -> None:
        self.db = db or HuntDatabase()

    def get_queries_by_mitre_technique(self, technique_id: str) -> pd.DataFrame:
        """Finds all hunting queries targeting a given technique (e.g., T1059.001)."""
        df = self.db.load_all_queries()
        if df.empty:
            return df

        target = technique_id.strip().upper()
        mask = df["mitre_techniques"].apply(
            lambda techs: any(t.upper() == target or t.upper().startswith(f"{target}.") for t in (techs if isinstanc
        )
        return df[mask]

    def get_queries_by_actor(self, actor_name: str) -> pd.DataFrame:
        """Finds all hunting queries mapped to a threat actor or group."""
        df = self.db.load_all_queries()
        if df.empty:
            return df

        target = actor_name.strip().lower()
        mask = df["associated_actors"].apply(
            lambda actors: any(target in a.lower() for a in (actors if isinstance(actors, (list, tuple)) else []))
        )
        return df[mask]

    def get_queries_by_malware(self, malware_name: str) -> pd.DataFrame:
        """Finds all hunting queries addressing a specific malware strain."""
        df = self.db.load_all_queries()
        if df.empty:
            return df

        target = malware_name.strip().lower()
        mask = df["associated_malware"].apply(
            lambda mal: any(target in m.lower() for m in (mal if isinstance(mal, (list, tuple)) else []))
        )
        return df[mask]

    def get_queries_by_campaign(self, campaign_name: str) -> pd.DataFrame:
        """Finds all hunting queries correlated with an intrusion campaign."""
        df = self.db.load_all_queries()
        if df.empty:
            return df

        target = campaign_name.strip().lower()
        mask = df["associated_campaigns"].apply(
            lambda camps: any(target in c.lower() for c in (camps if isinstance(camps, (list, tuple)) else []))
        )
        return df[mask]

    def compute_coverage_matrix(self) -> Dict[str, Any]:
        """
        Calculates detection coverage across tactics, techniques, actors, and malware.
        """
        df = self.db.load_all_queries()
        if df.empty:
            return {
                "total_queries": 0,
                "language_distribution": {},
                "technique_coverage_count": 0,
                "actor_coverage_count": 0,
                "malware_coverage_count": 0
            }

        lang_dist = df["language"].value_counts().to_dict()

        # Unique techniques
        all_techs = set()
        for t_list in df["mitre_techniques"].dropna():
            if isinstance(t_list, (list, tuple)):
                all_techs.update(t_list)

        # Unique actors
        all_actors = set()
        for a_list in df["associated_actors"].dropna():
            if isinstance(a_list, (list, tuple)):
                all_actors.update(a_list)

        # Unique malware
        all_malware = set()
        for m_list in df["associated_malware"].dropna():
            if isinstance(m_list, (list, tuple)):
                all_malware.update(m_list)

        return {
            "total_queries": len(df),
            "language_distribution": lang_dist,
            "technique_coverage_count": len(all_techs),
            "actor_coverage_count": len(all_actors),
            "malware_coverage_count": len(all_malware),
            "unique_techniques": sorted(list(all_techs)),
            "unique_actors": sorted(list(all_actors)),
            "unique_malware": sorted(list(all_malware))
        }
