"""
ThreatFusion CTI - MITRE Matrix HTML Visualizer Component
"""

from typing import Dict, Any
import pandas as pd


class MitreMatrixVisualizer:
    @staticmethod
    def render_matrix_html(techniques_df: pd.DataFrame, layer: Dict[str, Any]) -> str:
        """Renders an interactive responsive ATT&CK matrix view using HTML/CSS."""
        if techniques_df.empty:
            return "<div style='color: #888;'>No techniques available to render.</div>"

        tactics_order = [
            "initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement",
            "collection", "command-and-control", "exfiltration", "impact"
        ]

        html = """
        <div style="overflow-x: auto; max-height: 480px; border: 1px solid #30363d; border-radius: 6px; padding: 12px; background-color: #0d1117;">
          <div style="display: flex; gap: 8px;">
        """

        for tactic in tactics_order:
            tactic_label = tactic.replace("-", " ").title()
            html += f"""
            <div style="flex: 1; min-width: 130px; background: #161b22; border-radius: 4px; padding: 6px;">
              <div style="font-size: 0.75rem; font-weight: bold; color: #58a6ff; margin-bottom: 6px; text-align: center; text-transform: uppercase;">
                {tactic_label}
              </div>
            """

            # Find matching techniques for this tactic
            for _, row in techniques_df.iterrows():
                row_tactics = row.get("tactics", [])
                if not isinstance(row_tactics, list):
                    row_tactics = [row_tactics]

                if any(tactic in str(t).lower() for t in row_tactics):
                    tid = row.get("technique_id", "")
                    tname = row.get("name", "")
                    heat = layer.get(tid, {})
                    bg_color = heat.get("color", "#21262d")
                    text_color = "#ffffff" if heat else "#8b949e"
                    score_badge = f"<span style='float: right; font-size: 0.65rem; background: #000; border-radius: 3px; padding: 1px 4px;'>{heat.get('count', 0)}</span>" if heat else ""

                    html += f"""
                    <div style="background-color: {bg_color}; color: {text_color}; font-size: 0.68rem; padding: 4px 6px; margin-bottom: 4px; border-radius: 3px; word-break: break-word;">
                      <strong>{tid}</strong>: {tname} {score_badge}
                    </div>
                    """

            html += "</div>"

        html += """
          </div>
        </div>
        """
        return html
