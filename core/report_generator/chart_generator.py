"""
ThreatFusion CTI - Static Report Visualizer
Compiles Plotly figures into base64-encoded PNG/SVG image bytes.
"""

import io
import base64
from typing import List, Dict, Any, Optional
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd


class ReportChartGenerator:
    DARK_LAYOUT = dict(
        template="plotly_dark",
        paper_bgcolor="#161B22",
        plot_bgcolor="#161B22",
        font=dict(color="#C9D1D9", family="Arial, sans-serif", size=11),
        margin=dict(l=30, r=30, t=35, b=30),
    )

    @classmethod
    def generate_attack_trend_chart(cls, dates: List[str], counts: List[int]) -> str:
        """Generates a base64 encoded time-series trend line chart."""
        df = pd.DataFrame({"Date": dates, "Incidents": counts})
        fig = px.area(
            df, x="Date", y="Incidents",
            title="Attack Vector Velocity & Incident Trends",
            color_discrete_sequence=["#58A6FF"]
        )
        fig.update_layout(**cls.DARK_LAYOUT)
        return cls._fig_to_base64(fig)

    @classmethod
    def generate_sector_distribution_chart(cls, sectors: Dict[str, int]) -> str:
        """Generates a base64 encoded horizontal bar chart of targeted industries."""
        df = pd.DataFrame(list(sectors.items()), columns=["Sector", "Volume"]).sort_values("Volume", ascending=True)
        fig = px.bar(
            df, x="Volume", y="Sector", orientation="h",
            title="Target Distribution by Critical Infrastructure Sector",
            color="Volume",
            color_continuous_scale=["#1F3A60", "#58A6FF", "#F85149"]
        )
        fig.update_layout(**cls.DARK_LAYOUT)
        fig.update_layout(coloraxis_showscale=False)
        return cls._fig_to_base64(fig)

    @classmethod
    def generate_mitre_tactic_radar(cls, tactic_counts: Dict[str, int]) -> str:
        """Generates a base64 polar radar chart showing observed MITRE tactic coverage."""
        categories = list(tactic_counts.keys())
        values = list(tactic_counts.values())

        fig = go.Figure()
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories,
            fill="toself",
            name="Tactics",
            line=dict(color="#BC8CFF"),
            fillcolor="rgba(188, 140, 255, 0.3)"
        ))
        fig.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, max(values or [1]) + 1], color="#8B949E"),
                bgcolor="#161B22"
            ),
            **cls.DARK_LAYOUT,
            title="MITRE ATT&CK Tactic Distribution"
        )
        return cls._fig_to_base64(fig)

    @classmethod
    def generate_geo_choropleth(cls, country_counts: Dict[str, int]) -> str:
        """Generates a static world map choropleth."""
        df = pd.DataFrame(list(country_counts.items()), columns=["Country", "Hits"])
        fig = px.choropleth(
            df, locations="Country", locationmode="ISO-3",
            color="Hits",
            color_continuous_scale=["#161B22", "#D29922", "#F85149"],
            title="Geographic Victimology Heatmap"
        )
        fig.update_geos(
            bgcolor="#0E1117",
            showocean=True, oceancolor="#0E1117",
            showland=True, landcolor="#161B22",
            showlakes=False,
            showcountries=True, countrycolor="#30363D"
        )
        fig.update_layout(**cls.DARK_LAYOUT)
        fig.update_layout(coloraxis_showscale=False)
        return cls._fig_to_base64(fig)

    @staticmethod
    def _fig_to_base64(fig: go.Figure) -> str:
        """Converts Plotly chart to base64 PNG data string without disk IO."""
        try:
            img_bytes = fig.to_image(format="png", width=750, height=350, scale=2)
            encoded = base64.b64encode(img_bytes).decode("utf-8")
            return f"data:image/png;base64,{encoded}"
        except Exception:
            # Fallback if kaleido is not installed
            return ""
