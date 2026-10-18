"""
ThreatFusion CTI - Threat Hunting Dashboard
Search, pivot, and operationalize hunting queries across SIEM/EDR platforms.
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
from core.hunting.database import HuntDatabase

st.set_page_config(
    page_title=f"{APP_TITLE} | Threat Hunting",
    page_icon="🎯",
    layout="wide"
)

# Custom CSS
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    try:
        with open(css_file, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except Exception:
        pass

st.title("🎯 Proactive Threat Hunting Engine")
st.markdown(
    "Search, pivot, and operationalize high-fidelity hunting queries across KQL, SPL, LogScale, Sigma, YARA, and EDR platforms."
)

hunt_db = HuntDatabase()
df = hunt_db.load_all_queries()

# Search filter
search_query = st.text_input("Search hunting queries (technique, keyword, platform, severity):", "")
if search_query:
    filtered_df = hunt_db.search_rules(search_query)
else:
    filtered_df = df

if not filtered_df.empty:
    st.dataframe(
        filtered_df[["query_id", "name", "platform", "technique_id", "severity"]],
        use_container_width=True,
        hide_index=True
    )

    st.subheader("Query Content Preview")
    selected_id = st.selectbox("Select Query to View Syntax:", filtered_df["query_id"].tolist())
    rule = hunt_db.get_rule_by_id(selected_id)
    if rule:
        st.code(rule.get("query", ""), language="yaml")
else:
    st.info("No detection signatures available matching the filter.")

# Export options
if not df.empty:
    st.download_button(
        label="📥 Export Hunting Repository (JSON)",
        data=df.to_json(orient="records", indent=2),
        file_name="threatfusion_hunting_signatures.json",
        mime="application/json"
    )
