import streamlit as st
from pathlib import Path
from config.settings import CSS_DIR, APP_TITLE, APP_SUBTITLE
from database.parquet_store import ParquetStore

st.set_page_config(
    page_title=f"{APP_TITLE} | Executive Dashboard",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Dark Enterprise Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize Storage Lake
store = ParquetStore()
store.initialize_lake()

# Header Area
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown(f"#  {APP_TITLE}")
    st.markdown(f"*{APP_SUBTITLE}*")
with col2:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 15px;">
            <span style="background-color: #238636; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0
                OPERATIONAL
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

st.divider()

# In-Memory KPI Computation with DuckDB
metrics_query = """
SELECT
    (SELECT COUNT(*) FROM reports) as total_reports,
    (SELECT COUNT(*) FROM iocs) as total_iocs,
    (SELECT COUNT(*) FROM actors) as total_actors,
    (SELECT COUNT(*) FROM malware) as total_malware
"""
metrics_df = store.query(metrics_query)

m_col1, m_col2, m_col3, m_col4 = st.columns(4)

with m_col1:
    val = metrics_df['total_reports'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Ingested Reports</div>
        <div class="soc-metric-value">{val:,}</div>
    </div>
    """, unsafe_allow_html=True)

with m_col2:
    val = metrics_df['total_iocs'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Observed Indicators</div>
        <div class="soc-metric-value">{val:,}</div>
    </div>
    """, unsafe_allow_html=True)

with m_col3:
    val = metrics_df['total_actors'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Tracked Threat Actors</div>
        <div class="soc-metric-value">{val:,}</div>
    </div>
    """, unsafe_allow_html=True)

with m_col4:
    val = metrics_df['total_malware'][0] if not metrics_df.empty else 0
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Indexed Malware Families</div>
        <div class="soc-metric-value">{val:,}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("###  Recent Threat Reports Feed")
reports_df = store.query("""
SELECT title, source_name, publish_date, url
FROM reports
ORDER BY publish_date DESC
LIMIT 15
""")

if not reports_df.empty:
    st.dataframe(
        reports_df,
        column_config={
            "url": st.column_config.LinkColumn("Source Link"),
            "publish_date": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss")
        },
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No threat intelligence reports ingested yet. Trigger automated ingestion from GitHub Actions or execute
