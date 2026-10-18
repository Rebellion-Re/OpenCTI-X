"""
ThreatFusion CTI - MITRE ATT&CK Matrix HTML Visualizer Component
Renders a clean, high-performance tactical matrix heatmap.
"""

from typing import Dict, Any
import pandas as pd


class MitreMatrixVisualizer:
    @staticmethod
    def render_matrix_html(techniques_df: pd.DataFrame, layer: Dict[str, Any], max_items_per_tactic: int = 15) -> str:
        """
        Renders an interactive responsive ATT&CK matrix view using unindented HTML.
        Limits per-column items to prevent DOM bloat while prioritizing heat-scored items.
        """
        if techniques_df.empty:
            return "<div style='color: #8b949e; padding: 12px;'>No MITRE techniques loaded.</div>"

        tactics_order = [
            ("initial-access", "Initial Access"),
            ("execution", "Execution"),
            ("persistence", "Persistence"),
            ("privilege-escalation", "Privilege Escalation"),
            ("defense-evasion", "Defense Evasion"),
            ("credential-access", "Credential Access"),
            ("discovery", "Discovery"),
            ("lateral-movement", "Lateral Movement"),
            ("collection", "Collection"),
            ("command-and-control", "Command & Control"),
            ("exfiltration", "Exfiltration"),
            ("impact", "Impact")
        ]

        columns_html = []

        for tactic_slug, tactic_label in tactics_order:
            # Match techniques for this tactic
            col_items = []
            for _, row in techniques_df.iterrows():
                row_tactics = row.get("tactics", [])
                if not isinstance(row_tactics, list):
                    row_tactics = [row_tactics] if row_tactics else []

                if any(tactic_slug in str(t).lower() for t in row_tactics):
                    tid = str(row.get("technique_id", ""))
                    tname = str(row.get("name", ""))
                    heat = layer.get(tid, {})
                    score = heat.get("score", 0)
                    count = heat.get("count", 0)
                    color = heat.get("color", "#21262d")
                    col_items.append({
                        "tid": tid,
                        "name": tname,
                        "score": score,
                        "count": count,
                        "color": color
                    })

            # Sort: prioritized active/scored techniques first, then alphabetical
            col_items.sort(key=lambda x: (x["score"], x["count"]), reverse=True)
            total_count = len(col_items)
            display_items = col_items[:max_items_per_tactic]

            items_html = []
            for item in display_items:
                badge = f"<span style='float:right;background:#0d1117;padding:1px 4px;border-radius:3px;font-size:0.62rem;color:#58a6ff;'>{item['count']}</span>" if item["count"] > 0 else ""
                text_color = "#ffffff" if item["count"] > 0 else "#8b949e"
                border = "1px solid #58a6ff" if item["count"] > 0 else "1px solid #30363d"

                items_html.append(
                    f"<div style='background-color:{item['color']};color:{text_color};font-size:0.68rem;"
                    f"padding:4px 6px;margin-bottom:4px;border-radius:3px;border:{border};word-break:break-word;'>"
                    f"<strong>{item['tid']}</strong>: {item['name']} {badge}</div>"
                )

            if total_count > max_items_per_tactic:
                remaining = total_count - max_items_per_tactic
                items_html.append(
                    f"<div style='text-align:center;font-size:0.62rem;color:#8b949e;padding:2px;'>"
                    f"+ {remaining} more...</div>"
                )

            column_block = (
                f"<div style='flex:1;min-width:140px;background:#161b22;border:1px solid #30363d;"
                f"border-radius:6px;padding:8px;display:flex;flex-direction:column;'>"
                f"<div style='font-size:0.75rem;font-weight:700;color:#58a6ff;margin-bottom:8px;"
                f"text-align:center;text-transform:uppercase;border-bottom:1px solid #21262d;padding-bottom:4px;'>"
                f"{tactic_label}</div>"
                f"<div style='overflow-y:auto;max-height:380px;'>"
                + "".join(items_html) +
                f"</div></div>"
            )
            columns_html.append(column_block)

        # Assemble outer responsive wrapper
        final_html = (
            "<div style='width:100%;overflow-x:auto;padding-bottom:10px;background-color:#0d1117;"
            "border:1px solid #30363d;border-radius:8px;padding:12px;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;'>"
            "<div style='display:flex;gap:10px;'>"
            + "".join(columns_html) +
            "</div></div>"
        )
        return final_html
