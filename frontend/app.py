"""
ThreatFusion CTI - Enterprise Threat Intelligence Platform
Main Application Router & Strategic Executive Dashboard
"""

import streamlit as st
import pandas as pd
import duckdb
from pathlib import Path

from config.settings import CSS_DIR, APP_TITLE, APP_SUBTITLE
from database.parquet_store import ParquetStore
from database.gdrive_sync import GoogleDriveSync
from core.mitre.database import MitreDatabase
from core.mitre.heatmap_builder import HeatmapBuilder
from frontend.components.mitre_matrix import MitreMatrixVisualizer

st.set_page_config(
    page_title=f"{APP_TITLE} | Executive Console",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Enterprise SOC Dark Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize Core Services
store = ParquetStore()
store.initialize_lake()

# Header Toolbar
head_col, status_col = st.columns([3, 1])
with head_col:
    st.markdown(f"#  {APP_TITLE}")
    st.markdown(f"*{APP_SUBTITLE}*")
with status_col:
    gdrive = GoogleDriveSync()
    sync_status = "ONLINE (GDRIVE)" if gdrive.is_connected() else "LOCAL LAKEHOUSE"
    st.markdown(
        f"""
        <div style="text-align: right; padding-top: 15px;">
            <span style="background-color: #238636; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0
                STORAGE: {sync_status}
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

st.divider()

# KPI Metric Row via Vectorized DuckDB Aggregation
metrics_query = """
SELECT
    (SELECT COUNT(*) FROM reports) as total_reports,
    (SELECT COUNT(*) FROM iocs WHERE is_active = true) as active_iocs,
    (SELECT COUNT(*) FROM nodes WHERE node_type = 'ACTOR') as total_actors,
    (SELECT COUNT(*) FROM nodes WHERE node_type = 'MALWARE') as total_malware
"""
try:
    metrics_df = store.query(metrics_query)
except Exception:
    metrics_df = pd.DataFrame([{
        "total_reports": 0, "active_iocs": 0, "total_actors": 0, "total_malware": 0
    }])

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
with kpi1:
    v = metrics_df['total_reports'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Ingested Disclosures</div>
        <div class="soc-metric-value">{v:,}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi2:
    v = metrics_df['active_iocs'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Active Indicators (IOCs)</div>
        <div class="soc-metric-value">{v:,}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi3:
    v = metrics_df['total_actors'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Tracked Threat Actors</div>
        <div class="soc-metric-value">{v:,}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi4:
    v = metrics_df['total_malware'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Identified Malware Strains</div>
        <div class="soc-metric-value">{v:,}</div>
    </div>
    """, unsafe_allow_html=True)

# Operational Layout: Reports Feed & Tactical ATT&CK Heatmap
left_pane, right_pane = st.columns([3, 2])

with left_pane:
    st.markdown("###  Real-Time Threat Intelligence Feed")
    feed_df = store.query("""
    SELECT title, source_name, publish_date, url
    FROM reports
    ORDER BY publish_date DESC
    LIMIT 10
    """)
    if not feed_df.empty:
        st.dataframe(
            feed_df,
            column_config={
                "url": st.column_config.LinkColumn("Source Advisory"),
                "publish_date": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss")
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No threat disclosures available. Trigger collection from GitHub Actions or local CLI.")

with right_pane:
    st.markdown("###  Top Active ATT&CK TTP Heatmap")
    mitre_db = MitreDatabase()
    heatmap_engine = HeatmapBuilder(store=store, mitre_db=mitre_db)
    layer = heatmap_engine.generate_heatmap_layer()
    tech_df = mitre_db.get_techniques()

    if not tech_df.empty:
        matrix_markup = MitreMatrixVisualizer.render_matrix_html(tech_df, layer)
        st.markdown(matrix_markup, unsafe_allow_html=True)
    else:
        st.info("MITRE ATT&CK taxonomy synchronizing...")
