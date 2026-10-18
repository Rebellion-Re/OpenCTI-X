"""
ThreatFusion CTI - Centralized Hunt Query Database View
"""
import sys
from pathlib import Path

# Add repository root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from core.hunting.database import HuntDatabase
from config.settings import APP_TITLE
import streamlit as st
import pandas as pd
from config.settings import CSS_DIR, APP_TITLE
from core.hunting.database import HuntDatabase

st.set_page_config(
    page_title=f"{APP_TITLE} | Hunt Database",
    page_icon="",
    layout="wide"
)

# Apply Dark Enterprise Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" Threat Hunting Signature Knowledge Base")
st.markdown("Raw repository of detection rules, behavioral models, and hunting queries.")

hunt_db = HuntDatabase()
df = hunt_db.load_all_queries()

if not df.empty:
    st.dataframe(
        df[["rule_id", "title", "language", "severity", "status", "mitre_techniques", "associated_actors"]],
        use_container_width=True,
        hide_index=True
    )

    # Export options
    st.download_button(
        label=" Export Full Hunt Repository (JSON)",
        data=df.to_json(orient="records", indent=2),
        file_name="threatfusion_hunting_signatures.json",
        mime="application/json"
    )
else:
    st.info("No signatures currently loaded.")
