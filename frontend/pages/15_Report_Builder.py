"""
ThreatFusion CTI - Threat Report Builder Page
"""

import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from config.settings import CSS_DIR, APP_TITLE
from core.report_generator.report_builder import ReportBuilder

st.set_page_config(
    page_title=f"{APP_TITLE} | Report Builder",
    page_icon="📄",
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

st.title("📄 Executive Threat Advisory Builder")
st.markdown("Compile, customize, and generate multi-format CTI reports.")

builder = ReportBuilder()
sample_data = builder.generate_sample_report_data()

col1, col2 = st.columns([1, 1])
with col1:
    title = st.text_input("Advisory Title", sample_data.get("title", ""))
    tlp = st.selectbox("TLP Marking", ["WHITE", "GREEN", "AMBER", "RED"], index=2)
    summary = st.text_area("Executive Summary", sample_data.get("summary", ""), height=120)

with col2:
    actors = st.text_input("Threat Actors (comma-separated)", ", ".join(sample_data.get("threat_actors", [])))
    malware = st.text_input("Malware Families (comma-separated)", ", ".join(sample_data.get("malware_families", [])))
    sectors = st.text_input("Targeted Sectors (comma-separated)", ", ".join(sample_data.get("targeted_sectors", [])))

custom_data = {
    "title": title,
    "tlp": tlp,
    "summary": summary,
    "report_id": sample_data.get("report_id"),
    "created_at": sample_data.get("created_at"),
    "threat_actors": [a.strip() for a in actors.split(",") if a.strip()],
    "malware_families": [m.strip() for m in malware.split(",") if m.strip()],
    "targeted_sectors": [s.strip() for s in sectors.split(",") if s.strip()],
    "timeline": sample_data.get("timeline", []),
    "mitre_ttps": sample_data.get("mitre_ttps", []),
    "iocs": sample_data.get("iocs", []),
    "recommendations": sample_data.get("recommendations", [])
}

st.divider()
st.subheader("Live Document Preview")
html_preview = builder.render_html_report(custom_data)
st.components.v1.html(html_preview, height=600, scrolling=True)

st.download_button(
    label="📥 Download HTML Report",
    data=html_preview,
    file_name=f"{custom_data['report_id']}.html",
    mime="text/html"
)
