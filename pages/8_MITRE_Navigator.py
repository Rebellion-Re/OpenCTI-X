"""
ThreatFusion CTI - MITRE ATT&CK Matrix & Navigator Module
"""

import streamlit as st
import pandas as pd
from config.settings import CSS_DIR, APP_TITLE
from core.mitre.database import MitreDatabase
from core.mitre.mapping_engine import MitreMappingEngine
from core.mitre.heatmap_builder import HeatmapBuilder
from frontend.components.mitre_matrix import MitreMatrixVisualizer

st.set_page_config(
    page_title=f"{APP_TITLE} | ATT&CK Navigator",
    page_icon="",
    layout="wide"
)

# Apply Dark Enterprise Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" MITRE ATT&CK Enterprise Navigator")
st.markdown("Explore Enterprise ATT&CK matrices, adversary correlations, and observational heatmaps.")

# Initialize Engines
mitre_db = MitreDatabase()
mapping_engine = MitreMappingEngine(mitre_db)
heatmap_builder = HeatmapBuilder(mitre_db=mitre_db)

# Top Action Toolbar
col_sync, col_filter_actor, col_filter_malware = st.columns([1, 2, 2])

with col_sync:
    if st.button(" Sync Official ATT&CK", use_container_width=True):
        with st.spinner("Downloading Enterprise STIX 2.1 catalog..."):
            mitre_db.sync_from_upstream(force_refresh=True)
            st.success("Synchronized!")

groups_df = mitre_db.get_groups()
software_df = mitre_db.get_software()

with col_filter_actor:
    actor_options = ["None"] + sorted(groups_df["name"].dropna().tolist()) if not groups_df.empty else ["None"]
    selected_actor = st.selectbox("Highlight Adversary Layer:", actor_options)
    active_actor = None if selected_actor == "None" else selected_actor

with col_filter_malware:
    mal_options = ["None"] + sorted(software_df["name"].dropna().tolist()) if not software_df.empty else ["None"]
    selected_malware = st.selectbox("Highlight Malware / Tool Layer:", mal_options)
    active_malware = None if selected_malware == "None" else selected_malware

# Generate Heatmap Layer
heatmap_payload = heatmap_builder.generate_heatmap_layer(
    actor_filter=active_actor,
    malware_filter=active_malware
)

# Tabs
tab_matrix, tab_explorer, tab_mappings = st.tabs([
    " ATT&CK Matrix Heatmap",
    " Technique Explorer",
    " Adversary & Tool Mappings"
])

# -------------------------------------------------------------
# TAB 1: ATT&CK MATRIX HEATMAP
# -------------------------------------------------------------
with tab_matrix:
    st.markdown("#### Enterprise Matrix Heatmap")

    # Heatmap legend
    st.markdown(
        """
        <div style="display: flex; gap: 16px; align-items: center; margin-bottom: 12px; font-size: 12px;">
            <span style="color: #8B949E;">Density Intensity:</span>
            <span style="background: #161B22; padding: 2px 8px; border: 1px solid #30363D; border-radius: 3px;">Unob
            <span style="background: #1F3A60; padding: 2px 8px; border-radius: 3px;">Low</span>
            <span style="background: #D29922; color: black; padding: 2px 8px; border-radius: 3px; font-weight: bold;
            <span style="background: #DB6D28; padding: 2px 8px; border-radius: 3px; font-weight: bold;">High</span>
            <span style="background: #F85149; padding: 2px 8px; border-radius: 3px; font-weight: bold;">Critical</sp
        </div>
        """,
        unsafe_allow_html=True
    )

    techniques_df = mitre_db.get_techniques()
    if not techniques_df.empty:
        matrix_html = MitreMatrixVisualizer.render_matrix_html(techniques_df, heatmap_payload)
        st.markdown(matrix_html, unsafe_allow_html=True)
    else:
        st.info("No ATT&CK techniques available. Click 'Sync Official ATT&CK'.")

# -------------------------------------------------------------
# TAB 2: TECHNIQUE EXPLORER
# -------------------------------------------------------------
with tab_explorer:
    st.markdown("#### Technique Details & Mitigations")

    if not techniques_df.empty:
        # Search & Select
        search_kw = st.text_input("Filter techniques by ID or keyword (e.g., T1059 or PowerShell):")
        filtered_techs = techniques_df
        if search_kw:
            filtered_techs = techniques_df[
                techniques_df["technique_id"].str.contains(search_kw, case=False, na=False) |
                techniques_df["name"].str.contains(search_kw, case=False, na=False)
            ]

        tech_choice = st.selectbox(
            "Select Technique to Inspect:",
            filtered_techs["technique_id"] + " - " + filtered_techs["name"]
        )

        if tech_choice:
            chosen_id = tech_choice.split(" - ")[0]
            t_record = techniques_df[techniques_df["technique_id"] == chosen_id].iloc[0]

            col_t1, col_t2 = st.columns([2, 1])
            with col_t1:
                st.subheader(f"{t_record['technique_id']}: {t_record['name']}")
                st.markdown(f"**Associated Tactics:** `{', '.join(t_record.get('tactics', []))}`")
                st.markdown(f"**Platforms:** `{', '.join(t_record.get('platforms', []))}`")
                st.markdown(f"**Reference Link:** [{t_record['url']}]({t_record['url']})")
                st.markdown("##### Description")
                st.write(t_record.get("description", "No description provided."))

                if t_record.get("detection"):
                    st.markdown("##### Detection Strategies")
                    st.info(t_record["detection"])

            with col_t2:
                st.markdown("##### Observed Adversaries")
                actors_using = mapping_engine.get_actors_using_technique(chosen_id)
                if not actors_using.empty:
                    st.dataframe(actors_using[["actor_name", "group_id"]], hide_index=True, use_container_width=True
                else:
                    st.caption("No direct threat actor mapping documented.")

                st.markdown("##### Observed Tools & Malware")
                soft_using = mapping_engine.get_malware_using_technique(chosen_id)
                if not soft_using.empty:
                    st.dataframe(soft_using[["software_name", "software_type"]], hide_index=True, use_container_widt
                else:
                    st.caption("No direct software mapping documented.")

# -------------------------------------------------------------
# TAB 3: ADVERSARY & TOOL MAPPINGS
# -------------------------------------------------------------
with tab_mappings:
    st.markdown("#### Entity TTP Mappings")
    mapping_type = st.radio("Choose Entity Category:", ["Threat Groups", "Software & Tools"], horizontal=True)

    if mapping_type == "Threat Groups":
        if not groups_df.empty:
            chosen_g = st.selectbox("Select Threat Group:", groups_df["name"].sort_values())
            mapped_tts = mapping_engine.get_techniques_for_actor(chosen_g)
            st.markdown(f"**Identified Techniques for {chosen_g}:** ({len(mapped_tts)} techniques)")
            if not mapped_tts.empty:
                st.dataframe(
                    mapped_tts[["technique_id", "technique_name", "tactics", "evidence"]],
                    hide_index=True,
                    use_container_width=True
                )
            else:
                st.info("No technique associations mapped for this entity.")
    else:
        if not software_df.empty:
            chosen_s = st.selectbox("Select Software / Malware:", software_df["name"].sort_values())
            mapped_tts = mapping_engine.get_techniques_for_malware(chosen_s)
            st.markdown(f"**Identified Techniques for {chosen_s}:** ({len(mapped_tts)} techniques)")
            if not mapped_tts.empty:
                st.dataframe(
                    mapped_tts[["technique_id", "technique_name", "tactics", "evidence"]],
                    hide_index=True,
                    use_container_width=True
                )
            else:
                st.info("No technique associations mapped for this entity.")
