"""
ThreatFusion CTI - MITRE ATT&CK Heatmap Builder
Aggregates observed technique frequencies across ingested intelligence reports.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
from database.parquet_store import ParquetStore
from core.mitre.database import MitreDatabase
from config.logging_config import setup_logger

logger = setup_logger("HeatmapBuilder")


class HeatmapBuilder:
    def __init__(self, store: ParquetStore, mitre_db: Optional[MitreDatabase] = None) -> None:
        self.store = store
        self.mitre_db = mitre_db or MitreDatabase()

    def generate_heatmap_layer(
        self,
        actor_filter: Optional[str] = None,
        min_score: int = 1
    ) -> Dict[str, Any]:
        """
        Builds frequency and scoring layer mapped by technique_id.
        Returns a dictionary mapping technique IDs to scoring and visual metadata.
        """
        technique_counts: Dict[str, int] = {}

        try:
            reports_df = self.store.read_table("reports")
            if not reports_df.empty:
                for _, row in reports_df.iterrows():
                    # Filter by actor if requested
                    if actor_filter:
                        actors = row.get("extracted_actors", [])
                        if isinstance(actors, str):
                            actors = [actors]
                        elif not isinstance(actors, list):
                            actors = []
                        if actor_filter.lower() not in [a.lower() for a in actors]:
                            continue

                    hits = row.get("mitre_hits", [])
                    if isinstance(hits, str):
                        hits = [hits]
                    elif not isinstance(hits, list):
                        hits = []

                    for tid in hits:
                        if tid:
                            technique_counts[tid] = technique_counts.get(tid, 0) + 1
        except Exception as e:
            logger.error(f"Error computing heatmap metrics: {e}")

        # Compute max count for normalization
        max_count = max(technique_counts.values()) if technique_counts else 1

        layer: Dict[str, Any] = {}
        for tid, count in technique_counts.items():
            if count >= min_score:
                normalized_score = min(100, int((count / max_count) * 100))
                layer[tid] = {
                    "count": count,
                    "score": normalized_score,
                    "color": self._get_color_gradient(normalized_score)
                }

        return layer

    @staticmethod
    def _get_color_gradient(score: int) -> str:
        """Returns hex color gradient based on normalized frequency score (0-100)."""
        if score >= 80:
            return "#FF4444"  # Red / High
        elif score >= 50:
            return "#FF8800"  # Orange / Medium-High
        elif score >= 25:
            return "#FFCC00"  # Yellow / Medium
        return "#33B5E5"      # Blue / Low
