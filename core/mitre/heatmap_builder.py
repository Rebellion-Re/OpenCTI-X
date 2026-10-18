"""
ThreatFusion CTI - ATT&CK Matrix Heatmap Scoring Builder
Computes technique frequency, co-occurrence weights, and normalized color intensity.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
from database.parquet_store import ParquetStore
from core.mitre.database import MitreDatabase


class HeatmapBuilder:
    def __init__(self, store: Optional[ParquetStore] = None, mitre_db: Optional[MitreDatabase] = None) -> None:
        self.store = store or ParquetStore()
        self.mitre_db = mitre_db or MitreDatabase()

    def generate_heatmap_layer(
        self,
        actor_filter: Optional[str] = None,
        malware_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates an ATT&CK Matrix heatmap layer with normalized scores (0.0 - 1.0).
        """
        df_techniques = self.mitre_db.get_techniques()
        df_reports = self.store.read_table("reports")

        technique_counts: Dict[str, int] = {
            t: 0 for t in df_techniques["technique_id"].unique()
        }

        # 1. Tally counts from live ingested reports
        if not df_reports.empty and "mitre_hits" in df_reports.columns:
            for _, row in df_reports.iterrows():
                # Apply actor / malware filters if supplied
                if actor_filter and actor_filter.lower() not in [a.lower() for a in row.get("extracted_actors", [])]
                    continue
                if malware_filter and malware_filter.lower() not in [m.lower() for m in row.get("extracted_malware",
                    continue

                hits = row.get("mitre_hits")
                if isinstance(hits, list):
                    for hit in hits:
                        if hit in technique_counts:
                            technique_counts[hit] += 1

        # 2. Add MITRE STIX documented actor relations if actor_filter is applied
        if actor_filter:
            from core.mitre.mapping_engine import MitreMappingEngine
            engine = MitreMappingEngine(self.mitre_db)
            actor_techs = engine.get_techniques_for_actor(actor_filter)
            for tid in actor_techs["technique_id"].tolist():
                technique_counts[tid] = technique_counts.get(tid, 0) + 5

        # 3. Add MITRE STIX documented malware relations if malware_filter is applied
        if malware_filter:
            from core.mitre.mapping_engine import MitreMappingEngine
            engine = MitreMappingEngine(self.mitre_db)
            mal_techs = engine.get_techniques_for_malware(malware_filter)
            for tid in mal_techs["technique_id"].tolist():
                technique_counts[tid] = technique_counts.get(tid, 0) + 5

        max_count = max(technique_counts.values()) if technique_counts else 1
        if max_count == 0:
            max_count = 1

        # Build matrix cell payload
        scores: Dict[str, Dict[str, Any]] = {}
        for tid, count in technique_counts.items():
            norm_score = round(count / max_count, 3)
            # Interpolate hex color from muted navy to vibrant amber/red
            color = self._score_to_color(norm_score) if count > 0 else "#161B22"
            scores[tid] = {
                "count": count,
                "score": norm_score,
                "color": color
            }

        return {
            "max_count": max_count,
            "techniques": scores
        }

    @staticmethod
    def _score_to_color(score: float) -> str:
        """
        Interpolates color between Dark Blue (#1A365D) -> Amber (#D29922) -> Red (#F85149).
        """
        if score <= 0.25:
            return "#1F3A60"  # Low density
        elif score <= 0.60:
            return "#D29922"  # Medium density
        elif score <= 0.85:
            return "#DB6D28"  # High density
        else:
            return "#F85149"  # Critical density
