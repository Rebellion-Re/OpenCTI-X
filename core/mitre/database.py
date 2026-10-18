"""
ThreatFusion CTI - MITRE ATT&CK Relational & Graph Database Wrapper
Provides structured query interfaces over parsed MITRE STIX bundles.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from config.settings import RAW_DATA_DIR
from config.logging_config import setup_logger
from core.mitre.downloader import MitreDownloader

logger = setup_logger("MitreDatabase")


class MitreDatabase:
    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self.downloader = MitreDownloader(cache_dir=cache_dir)
        self.data: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        raw_bundle = self.downloader.fetch_stix_bundle()
        self.data = self.downloader.parse_bundle(raw_bundle)

    def get_techniques(self) -> pd.DataFrame:
        techs = self.data.get("techniques", [])
        if not techs:
            return pd.DataFrame()
        return pd.DataFrame(techs)

    def get_groups(self) -> pd.DataFrame:
        groups = self.data.get("groups", [])
        if not groups:
            return pd.DataFrame()
        return pd.DataFrame(groups)

    def get_software(self) -> pd.DataFrame:
        software = self.data.get("software", [])
        if not software:
            return pd.DataFrame()
        return pd.DataFrame(software)

    def get_relationships(self) -> pd.DataFrame:
        rels = self.data.get("relationships", [])
        if not rels:
            return pd.DataFrame()
        return pd.DataFrame(rels)

    def build_graph_elements(self) -> Dict[str, List[Dict[str, Any]]]:
        nodes = []
        edges = []
        id_map = self.data.get("id_map", {})

        for t in self.data.get("techniques", []):
            nodes.append({
                "node_id": t["technique_id"],
                "node_type": "TECHNIQUE",
                "display_label": f"{t['technique_id']}: {t['name']}",
                "attributes_json": json.dumps(t)
            })

        for g in self.data.get("groups", []):
            nodes.append({
                "node_id": g.get("group_id", g["name"]),
                "node_type": "ACTOR",
                "display_label": g["name"],
                "attributes_json": json.dumps(g)
            })

        for s in self.data.get("software", []):
            nodes.append({
                "node_id": s.get("software_id", s["name"]),
                "node_type": s.get("type", "TOOL"),
                "display_label": s["name"],
                "attributes_json": json.dumps(s)
            })

        for r in self.data.get("relationships", []):
            s_obj = id_map.get(r.get("source_ref"), {})
            t_obj = id_map.get(r.get("target_ref"), {})
            s_id = s_obj.get("technique_id") or s_obj.get("group_id") or s_obj.get("software_id")
            t_id = t_obj.get("technique_id") or t_obj.get("group_id") or t_obj.get("software_id")
            if s_id and t_id:
                edges.append({
                    "source_node": s_id,
                    "target_node": t_id,
                    "relation_type": "uses",
                    "confidence": 100.0,
                    "weight": 1.0,
                    "evidence_reports": json.dumps([r.get("description", "")])
                })

        return {"nodes": nodes, "edges": edges}
