"""
ThreatFusion CTI - ATT&CK Navigator UI Component
Produces an OpenCTI / ATT&CK Navigator-style matrix in Streamlit.
"""

import html
from typing import Dict, Any, List
import pandas as pd
from core.mitre.database import MitreDatabase


class MitreMatrixVisualizer:
    @staticmethod
    def render_matrix_html(
        techniques_df: pd.DataFrame,
        heatmap_data: Dict[str, Any],
        selected_technique: str = ""
    ) -> str:
        """
        Generates full HTML/CSS table layout mirroring the official ATT&CK Navigator.
        """
        scores = heatmap_data.get("techniques", {})

        # Group techniques by primary tactic
        tactic_columns: Dict[str, List[Dict[str, Any]]] = {
            t: [] for t in MitreDatabase.TACTIC_ORDER
        }

        # Index primary parent techniques
        for _, row in techniques_df.iterrows():
            if row.get("is_subtechnique", False):
                continue

            tid = row["technique_id"]
            name = row["name"]
            tactics = row.get("tactics", [])

            t_score_info = scores.get(tid, {"count": 0, "score": 0.0, "color": "#161B22"})

            tech_card = {
                "id": tid,
                "name": name,
                "count": t_score_info["count"],
                "color": t_score_info["color"],
                "selected": (tid == selected_technique)
            }

            for tac in tactics:
                if tac in tactic_columns:
                    tactic_columns[tac].append(tech_card)

        # Build HTML table columns
        cols_html = []
        for tac_slug in MitreDatabase.TACTIC_ORDER:
            tac_title = MitreDatabase.TACTIC_DISPLAY_NAMES.get(tac_slug, tac_slug.title())
            cards = tactic_columns.get(tac_slug, [])

            cards_html = []
            for c in cards:
                border_style = "2px solid #58A6FF" if c["selected"] else "1px solid #30363D"
                count_badge = f"<span style='float:right; font-size:10px; color:#8B949E;'>{c['count']}</span>" if c[

                cards_html.append(f"""
                <div style="background-color: {c['color']}; border: {border_style}; border-radius: 4px; padding: 6px
                    <div style="font-weight: 600; color: #58A6FF;">{c['id']} {count_badge}</div>
                    <div style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{html.escape(c['nam
                </div>
                """)

            col_block = f"""
            <div style="min-width: 140px; max-width: 160px; display: flex; flex-direction: column; background: #0E11
                <div style="font-weight: 700; font-size: 11px; text-transform: uppercase; color: #8B949E; margin-bot
                    {tac_title}
                    <div style="font-size: 9px; color: #484F58;">({len(cards)})</div>
                </div>
                <div style="display: flex; flex-direction: column; max-height: 700px; overflow-y: auto; padding-righ
                    {''.join(cards_html)}
                </div>
            </div>
            """
            cols_html.append(col_block)

        matrix_container = f"""
        <div style="display: flex; gap: 8px; overflow-x: auto; padding: 12px 4px; background-color: #0E1117; border-
            {''.join(cols_html)}
        </div>
        """
        return matrix_container
