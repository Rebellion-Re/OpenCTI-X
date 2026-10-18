"""
ThreatFusion CTI - Primary Executive Console & Dashboard
Open-architecture Cyber Threat Intelligence Lakehouse & Matrix Visualizer.
"""

import sys
from pathlib import Path

# Add repository root directory to sys.path so top-level packages (config, database, utils, core) can be resolved
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
import pandas as pd
from config.settings import CSS_DIR, APP_TITLE, APP_SUBTITLE
from database.parquet_store import ParquetStore
from database.gdrive_sync import GoogleDriveSync

try:
    from core.mitre.database import MitreDatabase
    from core.mitre.heatmap_builder import HeatmapBuilder
    from frontend.components.mitre_matrix import MitreMatrixVisualizer
except ImportError:
    MitreDatabase = None
    HeatmapBuilder = None
    MitreMatrixVisualizer = None

st.set_page_config(
    page_title=f"{APP_TITLE} | Executive Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom dark CSS styling if available
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    try:
        with open(css_file, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except Exception:
        pass

# Initialize lakehouse directory and blank tables to prevent missing view exceptions
@st.cache_resource
def get_store() -> ParquetStore:
    s = ParquetStore()
    try:
        s.initialize_lake()
    except Exception:
        pass
    return s

store = get_store()

# Header & Cloud Storage Connectivity Badge
head_col, status_col = st.columns([3, 1])
with head_col:
    st.markdown(f"# 🛡️ {APP_TITLE}")
    st.markdown(f"*{APP_SUBTITLE}*")

with status_col:
    try:
        gdrive = GoogleDriveSync()
        sync_status = "ONLINE (GDRIVE)" if gdrive.is_connected() else "LOCAL LAKEHOUSE"
    except Exception:
        sync_status = "LOCAL LAKEHOUSE"

    st.markdown(
        f'<div style="text-align: right; padding-top: 15px;">'
        f'<span style="background-color: #238636; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold;">'
        f'STORAGE: {sync_status}</span></div>',
        unsafe_allow_html=True
    )

st.divider()

# Safe KPI queries with zero-fallbacks for cold-start containers
try:
    metrics_df = store.query("""
        SELECT 
            (SELECT COUNT(*) FROM reports) as total_reports,
            (SELECT COUNT(*) FROM iocs WHERE is_active = true) as active_iocs,
            (SELECT COUNT(*) FROM nodes WHERE node_type = 'ACTOR') as total_actors,
            (SELECT COUNT(*) FROM nodes WHERE node_type = 'MALWARE') as total_malware
    """)
    total_reports = int(metrics_df['total_reports'][0]) if not metrics_df.empty else 0
    active_iocs = int(metrics_df['active_iocs'][0]) if not metrics_df.empty else 0
    total_actors = int(metrics_df['total_actors'][0]) if not metrics_df.empty else 0
    total_malware = int(metrics_df['total_malware'][0]) if not metrics_df.empty else 0
except Exception:
    total_reports, active_iocs, total_actors, total_malware = 0, 0, 0, 0

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
with kpi1:
    st.markdown(
        f'<div class="soc-card"><div class="soc-metric-title">Ingested Disclosures</div>'
        f'<div class="soc-metric-value">{total_reports:,}</div></div>',
        unsafe_allow_html=True
    )
with kpi2:
    st.markdown(
        f'<div class="soc-card"><div class="soc-metric-title">Active Indicators (IOCs)</div>'
        f'<div class="soc-metric-value">{active_iocs:,}</div></div>',
        unsafe_allow_html=True
    )
with kpi3:
    st.markdown(
        f'<div class="soc-card"><div class="soc-metric-title">Tracked Threat Actors</div>'
        f'<div class="soc-metric-value">{total_actors:,}</div></div>',
        unsafe_allow_html=True
    )
with kpi4:
    st.markdown(
        f'<div class="soc-card"><div class="soc-metric-title">Identified Malware Strains</div>'
        f'<div class="soc-metric-value">{total_malware:,}</div></div>',
        unsafe_allow_html=True
    )

# Real-time Threat Intelligence Feed & Heatmap panes
left_pane, right_pane = st.columns([3, 2])

with left_pane:
    st.markdown("### 📡 Real-Time Threat Intelligence Feed")
    try:
        feed_df = store.query("""
            SELECT title, source_name, publish_date, url 
            FROM reports 
            ORDER BY publish_date DESC 
            LIMIT 10
        """)
    except Exception:
        feed_df = pd.DataFrame()

    if not feed_df.empty:
        st.dataframe(
            feed_df,
            column_config={"url": st.column_config.LinkColumn("Advisory Link")},
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No threat disclosures available yet. Trigger automated ingestion from GitHub Actions or run the collector script.")

with right_pane:
    st.markdown("### 🎯 Top Active ATT&CK TTP Heatmap")
    if MitreDatabase is not None and HeatmapBuilder is not None and MitreMatrixVisualizer is not None:
        try:
            mitre_db = MitreDatabase()
            heatmap_engine = HeatmapBuilder(store=store, mitre_db=mitre_db)
            layer = heatmap_engine.generate_heatmap_layer()
            tech_df = mitre_db.get_techniques()
            if not tech_df.empty:
                matrix_html = MitreMatrixVisualizer.render_matrix_html(tech_df, layer)
                # Render via component iframe to prevent Markdown code-block escaping and buffer truncations
                st.components.v1.html(matrix_html, height=480, scrolling=True)
            else:
                st.info("MITRE ATT&CK taxonomy synchronizing...")
        except Exception as e:
            st.info(f"MITRE ATT&CK heatmap synchronizing ({e})...")
    else:
        st.info("MITRE ATT&CK visualizer loading...")
