"""
ThreatFusion CTI - Interactive Knowledge Graph & Relationship Explorer
"""

import streamlit as st
import pandas as pd
from config.settings import CSS_DIR, APP_TITLE
from database.parquet_store import ParquetStore
from core.correlation.graph_engine import KnowledgeGraphEngine
from core.correlation.graph_models import GraphNode
from frontend.components.network_graph import NetworkGraphVisualizer

st.set_page_config(
    page_title=f"{APP_TITLE} | Relationship Explorer",
    page_icon="",
    layout="wide"
)

# Apply Dark Enterprise Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" Threat Knowledge Graph Explorer")
st.markdown("Investigate multi-hop entity relationships, infrastructure linkages, and dynamic confidence scores.")

store = ParquetStore()
graph_engine = KnowledgeGraphEngine(store)

# Top Action Toolbar
col_refresh, col_depth, col_conf = st.columns([1, 1, 2])

with col_refresh:
    if st.button(" Recompile Knowledge Graph", use_container_width=True):
        with st.spinner("Traversing Parquet Lakehouse & Building NetworkX Graph..."):
            graph_engine.build_graph_from_lake()
            st.success("Graph Synchronized!")

# Load graph into memory
G = graph_engine.build_graph_from_lake() if len(graph_engine.graph.nodes) == 0 else graph_engine.graph

with col_depth:
    depth = st.slider("Traversal Depth (Hops):", min_value=1, max_value=3, value=1)

with col_conf:
    min_confidence = st.slider("Minimum Confidence Threshold (%):", min_value=0.0, max_value=100.0, value=30.0, step

# Metrics Strip
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Total Entities (Nodes)</div>
        <div class="soc-metric-value">{G.number_of_nodes()}</div>
    </div>
    """, unsafe_allow_html=True)
with m2:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Total Links (Edges)</div>
        <div class="soc-metric-value">{G.number_of_edges()}</div>
    </div>
    """, unsafe_allow_html=True)
with m3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Graph Density</div>
        <div class="soc-metric-value">{nx.density(G):.4f}</div>
    </div>
    """, unsafe_allow_html=True)
with m4:
    components = nx.number_weakly_connected_components(G) if G.is_directed() else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Threat Clusters</div>
        <div class="soc-metric-value">{components}</div>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# Node Selection & Filtering
all_nodes = sorted(list(G.nodes()))
filter_col1, filter_col2 = st.columns([2, 1])

with filter_col1:
    selected_node = st.selectbox(
        "Focus on Specific Entity Node (Actor, Campaign, Malware, IOC):",
        ["ALL_ENTITIES"] + all_nodes
    )

with filter_col2:
    node_type_filter = st.multiselect(
        "Filter Node Categories:",
        ["ACTOR", "CAMPAIGN", "MALWARE", "IOC", "CVE", "TECHNIQUE", "COUNTRY", "SECTOR"],
        default=["ACTOR", "CAMPAIGN", "MALWARE", "IOC", "CVE", "TECHNIQUE", "COUNTRY", "SECTOR"]
    )

# Subgraph Extraction & Pruning
if selected_node != "ALL_ENTITIES":
    sub_g = graph_engine.extract_subgraph(selected_node, depth=depth)
else:
    sub_g = G.copy()

# Filter sub-graph by selected types
nodes_to_remove = [
    n for n, d in sub_g.nodes(data=True)
    if d.get("node_type") not in node_type_filter
]
sub_g.remove_nodes_from(nodes_to_remove)

# Filter edges by confidence score
edges_to_remove = [
    (u, v) for u, v, d in sub_g.edges(data=True)
    if d.get("confidence_score", 50.0) < min_confidence
]
sub_g.remove_edges_from(edges_to_remove)

# Remove isolated nodes if viewing filtered view
if selected_node == "ALL_ENTITIES":
    isolates = list(nx.isolates(sub_g))
    sub_g.remove_nodes_from(isolates)

# Render Graph Visualizer
st.markdown("###  Interactive Knowledge Graph Visualizer")

# Legend Strip
st.markdown("""
<div style="display: flex; gap: 14px; margin-bottom: 8px; font-size: 11px;">
    <span style="color: #F85149;">● Actor</span>
    <span style="color: #D29922;">● Campaign</span>
    <span style="color: #BC8CFF;">● Malware</span>
    <span style="color: #58A6FF;">● IOC</span>
    <span style="color: #F0883E;">● CVE</span>
    <span style="color: #3FB950;">● Technique</span>
    <span style="color: #39D353;">● Country</span>
    <span style="color: #79C0FF;">● Sector</span>
</div>
""", unsafe_allow_html=True)

fig = NetworkGraphVisualizer.render_plotly_graph(sub_g, height=620)
st.plotly_chart(fig, use_container_width=True)

# Deep-Dive Neighbors & Direct Evidence Table
if selected_node != "ALL_ENTITIES" and G.has_node(selected_node):
    st.markdown(f"###  Neighbor Linkages for `{selected_node}`")

    neighbor_records = []
    # Successors (Outbound relationships)
    for target in G.successors(selected_node):
        edge_data = G[selected_node][target]
        neighbor_records.append({

            "Target Entity": target,
            "Relation Type": edge_data.get("relation_type", "RELATED_TO"),
            "Confidence": f"{edge_data.get('confidence_score', 50.0)}%",
            "Weight / Evidence Count": edge_data.get("weight", 1.0),
            "Last Observed": edge_data.get("last_observed", "N/A")[:10]
        })

    # Predecessors (Inbound relationships)
    for source in G.predecessors(selected_node):
        edge_data = G[source][selected_node]
        neighbor_records.append({

            "Target Entity": source,
            "Relation Type": edge_data.get("relation_type", "RELATED_TO"),
            "Confidence": f"{edge_data.get('confidence_score', 50.0)}%",
            "Weight / Evidence Count": edge_data.get("weight", 1.0),
            "Last Observed": edge_data.get("last_observed", "N/A")[:10]
        })

    if neighbor_records:
        st.dataframe(pd.DataFrame(neighbor_records), use_container_width=True, hide_index=True)
    else:
        st.info("No active relationships identified for this entity matching the filters.")
