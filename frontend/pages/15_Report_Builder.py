"""
ThreatFusion CTI - Interactive Report Builder Workspace
"""

import streamlit as st
from config.settings import CSS_DIR, APP_TITLE
from core.report_generator.report_builder import ReportBuilder

st.set_page_config(
    page_title=f"{APP_TITLE} | Report Builder",
    page_icon="",
    layout="wide"
)

# Apply Dark Enterprise Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" Threat Intelligence Report Generator")
st.markdown("Compile, customize, and export professional multi-format intelligence dossiers.")

builder = ReportBuilder()

# Configuration Sidebar / Toolbar
col_type, col_entity, col_tlp, col_fmt = st.columns([2, 2, 1, 1])

with col_type:
    report_type = st.selectbox(
        "Report Domain:",
        ["Executive", "Actor", "Campaign", "Malware", "Vulnerability", "IOC", "MITRE", "Threat Hunting"]
    )

with col_entity:
    if report_type == "Actor":
        entity_name = st.text_input("Target Threat Actor:", "APT28")
    elif report_type == "Campaign":
        entity_name = st.text_input("Target Intrusion Campaign:", "Operation StealPast")
    elif report_type == "Malware":
        entity_name = st.text_input("Target Malware Family:", "Cobalt Strike")
    elif report_type == "Vulnerability":
        entity_name = st.text_input("Target CVE Identifier:", "CVE-2023-38831")
    elif report_type == "MITRE":
        entity_name = st.text_input("Target ATT&CK Technique ID:", "T1059.001")
    else:
        entity_name = "Global Telemetry"
        st.text_input("Target Entity:", entity_name, disabled=True)

with col_tlp:
    tlp_choice = st.selectbox("TLP Protocol:", ["AMBER", "RED", "GREEN", "WHITE"])

with col_fmt:
    export_format = st.selectbox("Export Format:", ["PDF", "DOCX", "HTML"])

st.divider()

# Generate Report In-Memory
report_data = builder.build_report(
    report_type=report_type,
    entity_name=entity_name,
    tlp=tlp_choice
)

# Action Bar: Download Trigger
col_action1, col_action2 = st.columns([1, 3])
with col_action1:
    with st.spinner(f"Compiling {export_format} Document..."):
        file_bytes = builder.export(report_data, export_format)

    ext_map = {"PDF": "pdf", "DOCX": "docx", "HTML": "html"}
    mime_map = {
        "PDF": "application/pdf",
        "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "HTML": "text/html"
    }

    file_name = f"ThreatFusion_{report_type}_{tlp_choice}_{entity_name.replace(' ', '_')}.{ext_map[export_format]}"

    st.download_button(
        label=f" Download {export_format} Report",
        data=file_bytes,
        file_name=file_name,
        mime=mime_map[export_format],
        use_container_width=True
    )

with col_action2:
    st.caption(f"Status: Report compiled successfully. Ready for dissemination under TLP:{tlp_choice} guidelines.")

st.markdown("###  Live Report Preview")

# Render Live Preview via tabs
tab_html, tab_summary, tab_mitre = st.tabs([" Document View", " Summary & Metrics", " Mappings & TTPs"])

with tab_html:
    html_preview = builder.export(report_data, "HTML").decode("utf-8")
    st.components.v1.html(html_preview, height=800, scrolling=True)

with tab_summary:
    st.markdown("#### Executive Briefing Summary")
    st.write(report_data.executive_summary)

    if report_data.strategic_impact:
        st.markdown("#### Strategic Threat Impact")
        st.write(report_data.strategic_impact)

    if report_data.recommendations:
        st.markdown("#### Recommended Actions")
        for rec in report_data.recommendations:
            st.info(f"**[{rec.get('priority')}] {rec.get('title')}**: {rec.get('details')}")

with tab_mitre:
    if report_data.mitre_mappings:
        st.markdown("#### Correlated ATT&CK TTPs")
        st.table(report_data.mitre_mappings)
    else:
        st.info("No explicit MITRE technique mappings associated with this report configuration.")
