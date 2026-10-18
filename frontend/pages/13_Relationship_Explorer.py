"""
ThreatFusion CTI - Knowledge Graph & Entity Relationship Explorer
Interactive pivoting, link analysis, and graph visualization across threat actors, IOCs, and MITRE TTPs.
"""

import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
import pandas as pd
from config.settings import CSS_DIR, APP_TITLE
from database.parquet_store import ParquetStore
from core.mitre.database import MitreDatabase

st.set_page_config(
    page_title=f"{APP_TITLE} | Relationship Explorer",
    page_icon="🕸️",
    layout="wide"
)

# Custom dark CSS styling
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    try:
        with open(css_file, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except Exception:
        pass

st.title("🕸️ Threat Knowledge Graph & Relationship Explorer")
st.markdown("Perform multi-hop entity link analysis across threat actors, malware strains, infrastructure, and ATT&CK TTPs.")

store = ParquetStore()
try:
    store.initialize_lake()
except Exception:
    pass

# Sidebar Filters
st.sidebar.subheader("Graph Filters")
selected_relation = st.sidebar.selectbox(
    "Filter by Relationship Type:",
    ["All", "uses", "targets", "indicates", "attributed-to", "communicates-with"]
)

col1, col2 = st.columns([1, 1])
with col1:
    search_node = st.text_input(
        "Search Node Identifier / Actor / TTP:",
        placeholder="e.g. APT28, Cobalt Strike, T1059.001"
    )

with col2:
    min_confidence = st.slider(
        "Minimum Confidence Threshold (%):",
        min_value=0.0,
        max_value=100.0,
        value=30.0,
        step=5.0
    )

# Retrieve graph tables from Parquet store
try:
    edges_df = store.read_table("edges")
except Exception:
    edges_df = pd.DataFrame()

try:
    nodes_df = store.read_table("nodes")
except Exception:
    nodes_df = pd.DataFrame()

# If empty in lakehouse, fall back to synthesized MITRE graph elements
if edges_df.empty or nodes_df.empty:
    try:
        mitre_db = MitreDatabase()
        graph_data = mitre_db.build_graph_elements()
        if nodes_df.empty:
            nodes_df = pd.DataFrame(graph_data.get("nodes", []))
        if edges_df.empty:
            edges_df = pd.DataFrame(graph_data.get("edges", []))
    except Exception:
        st.info("Knowledge graph synchronizing...")

# Apply confidence and query filters
filtered_edges = edges_df.copy()
if not filtered_edges.empty:
    if "confidence" in filtered_edges.columns:
        filtered_edges = filtered_edges[filtered_edges["confidence"] >= min_confidence]
    if selected_relation != "All" and "relation_type" in filtered_edges.columns:
        filtered_edges = filtered_edges[filtered_edges["relation_type"].str.lower() == selected_relation.lower()]
    if search_node:
        s = search_node.lower()
        src_match = (
            filtered_edges["source_node"].astype(str).str.lower().str.contains(s)
            if "source_node" in filtered_edges.columns else False
        )
        tgt_match = (
            filtered_edges["target_node"].astype(str).str.lower().str.contains(s)
            if "target_node" in filtered_edges.columns else False
        )
        filtered_edges = filtered_edges[src_match | tgt_match]

tab1, tab2, tab3 = st.tabs(["🔗 Graph Edge Explorer", "🏷️ Knowledge Nodes", "📊 Graph Topology Metrics"])

with tab1:
    st.subheader("Observed Linkages & Behavioral Associations")
    if not filtered_edges.empty:
        display_cols = [c for c in ["source_node", "relation_type", "target_node", "confidence", "weight"] if c in filtered_edges.columns]
        st.dataframe(filtered_edges[display_cols], use_container_width=True, hide_index=True)

        st.download_button(
            label="📥 Export Relationship Subgraph (CSV)",
            data=filtered_edges.to_csv(index=False),
            file_name="threatfusion_relationships.csv",
            mime="text/csv"
        )
    else:
        st.info("No relationship edges found matching current filter parameters.")

with tab2:
    st.subheader("Registered Entity Nodes")
    if not nodes_df.empty:
        filtered_nodes = nodes_df.copy()
        if search_node:
            s = search_node.lower()
            id_match = (
                filtered_nodes["node_id"].astype(str).str.lower().str.contains(s)
                if "node_id" in filtered_nodes.columns else False
            )
            label_match = (
                filtered_nodes["display_label"].astype(str).str.lower().str.contains(s)
                if "display_label" in filtered_nodes.columns else False
            )
            filtered_nodes = filtered_nodes[id_match | label_match]

        display_node_cols = [c for c in ["node_id", "node_type", "display_label"] if c in filtered_nodes.columns]
        st.dataframe(filtered_nodes[display_node_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No entity nodes currently indexed in knowledge lakehouse.")

with tab3:
    st.subheader("Graph Centrality & Structural Telemetry")
    metric_col1, metric_col2, metric_col3 = st.columns(3)
    with metric_col1:
        st.metric("Total Entity Nodes", len(nodes_df))
    with metric_col2:
        st.metric("Total Directed Edges", len(edges_df))
    with metric_col3:
        st.metric("Active Subgraph Connections", len(filtered_edges))
