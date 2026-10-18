"""
ThreatFusion CTI - MITRE Entity Mapping Engine
Correlates Techniques with Adversaries, Malware Strains, and Intrusion Campaigns.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
from core.mitre.database import MitreDatabase


class MitreMappingEngine:
    def __init__(self, db: Optional[MitreDatabase] = None) -> None:
        self.db = db or MitreDatabase()

    def get_techniques_for_actor(self, actor_name: str) -> pd.DataFrame:
        """
        Retrieves all techniques used by an actor (via canonical name or alias).
        """
        df_rel = self.db.get_relations()
        df_tech = self.db.get_techniques()

        # Filter relationships where source matches actor name
        query = """
        SELECT r.target_id as technique_id, t.name as technique_name,
               t.tactics, t.is_subtechnique, r.description as evidence
        FROM df_rel r
        JOIN df_tech t ON r.target_id = t.technique_id
        WHERE LOWER(r.source_name) = LOWER(?)
          AND r.relationship = 'uses'
          AND r.target_type = 'attack-pattern'
        """
        conn = self.db.duck_conn
        return conn.execute(query, [actor_name.strip()]).df()

    def get_techniques_for_malware(self, malware_name: str) -> pd.DataFrame:
        """
        Retrieves all techniques exhibited by a malware strain or tool.
        """
        df_rel = self.db.get_relations()
        df_tech = self.db.get_techniques()
        query = """
        SELECT r.target_id as technique_id, t.name as technique_name,
               t.tactics, t.is_subtechnique, r.description as evidence
        FROM df_rel r
        JOIN df_tech t ON r.target_id = t.technique_id
        WHERE LOWER(r.source_name) = LOWER(?)
          AND r.relationship = 'uses'
          AND r.target_type = 'attack-pattern'
        """
        conn = self.db.duck_conn
        return conn.execute(query, [malware_name.strip()]).df()

    def get_actors_using_technique(self, technique_id: str) -> pd.DataFrame:
        """
        Lists all threat actors documented to use a given ATT&CK technique.
        """
        df_rel = self.db.get_relations()
        df_groups = self.db.get_groups()

        query = """
        SELECT r.source_name as actor_name, g.group_id, g.aliases, r.description as evidence
        FROM df_rel r
        JOIN df_groups g ON LOWER(r.source_name) = LOWER(g.name)
        WHERE r.target_id = ?
          AND r.relationship = 'uses'
          AND r.source_type = 'intrusion-set'
        ORDER BY actor_name ASC
        """
        conn = self.db.duck_conn
        return conn.execute(query, [technique_id.strip()]).df()

    def get_malware_using_technique(self, technique_id: str) -> pd.DataFrame:
        """
        Lists all software and tools documented to leverage a given ATT&CK technique.
        """
        df_rel = self.db.get_relations()
        df_soft = self.db.get_software()

        query = """
        SELECT r.source_name as software_name, s.type as software_type,
               s.platforms, r.description as evidence
        FROM df_rel r
        JOIN df_soft s ON LOWER(r.source_name) = LOWER(s.name)
        WHERE r.target_id = ?
          AND r.relationship = 'uses'
          AND r.source_type IN ('malware', 'tool')
        ORDER BY software_name ASC
        """
        conn = self.db.duck_conn
        return conn.execute(query, [technique_id.strip()]).df()
