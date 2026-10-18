"""
ThreatFusion CTI - Plotly Graph Visualizer Component
Interactive force-directed graph renderer with zoom, hover dossiers, and confidence tooltips.
"""

import math
from typing import Dict, Any, List
import networkx as nx
import plotly.graph_objects as go


class NetworkGraphVisualizer:
    @staticmethod
    def render_plotly_graph(graph: nx.DiGraph, height: int = 680) -> go.Figure:
        """Generates an interactive Plotly figure representing the threat graph."""
        if len(graph.nodes) == 0:
            fig = go.Figure()
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0E1117",
                plot_bgcolor="#0E1117",
                annotations=[{
                    "text": "No entity relationships to display for current selection.",
                    "xref": "paper", "yref": "paper",
                    "showarrow": False,
                    "font": {"size": 14, "color": "#8B949E"}
                }]
            )
            return fig

        # 1. Calculate positions using NetworkX Fruchterman-Reingold Force-Directed Layout
        pos = nx.spring_layout(graph, k=0.55, iterations=60, seed=42)

        # 2. Build Edge Traces
        edge_x = []
        edge_y = []
        edge_hover_text = []

        for u, v, data in graph.edges(data=True):
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            rel = data.get("relation_type", "RELATED_TO")
            conf = data.get("confidence_score", 50.0)


        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.2, color="#30363D"),
            hoverinfo="none",
            mode="lines"
        )

        # 3. Build Node Traces
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_text = []
        hover_tooltips = []

        for node_id, data in graph.nodes(data=True):
            x, y = pos[node_id]
            node_x.append(x)
            node_y.append(y)

            n_type = data.get("node_type", "UNKNOWN")
            n_label = data.get("label", node_id)
            n_color = data.get("color", "#58A6FF")
            centrality = data.get("degree_centrality", 0.0)

            node_colors.append(n_color)
            # Size nodes dynamically by degree centrality
            node_sizes.append(max(14, int(18 + (centrality * 40))))
            node_text.append(n_label)

            tooltip = (
                f"<b>{n_label}</b><br>"
                f"Type: {n_type}<br>"
                f"ID: {node_id}<br>"
                f"Centrality: {centrality}<br>"
                f"First Seen: {data.get('first_seen', 'N/A')[:10]}"
            )
            hover_tooltips.append(tooltip)

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode="markers+text",
            hoverinfo="text",
            text=node_text,
            textposition="top center",
            textfont=dict(size=10, color="#C9D1D9"),
            hovertext=hover_tooltips,
            marker=dict(
                color=node_colors,
                size=node_sizes,
                line=dict(width=1.5, color="#0E1117")
            )
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False,
                hovermode="closest",
                margin=dict(b=10, l=10, r=10, t=10),
                paper_bgcolor="#0E1117",
                plot_bgcolor="#0E1117",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=height
            )
        )
        return fig
