"""
ThreatFusion CTI - Threat Hunting & Detection Engineering Workbench
"""

import streamlit as st
import pandas as pd
from config.settings import CSS_DIR, APP_TITLE
from core.hunting.database import HuntDatabase
from core.hunting.mapping_engine import HuntMappingEngine
from core.hunting.schema import HuntQueryRecord

st.set_page_config(
    page_title=f"{APP_TITLE} | Threat Hunting",
    page_icon="",
    layout="wide"
)

# Apply Dark Enterprise Theme
css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" Threat Hunting & Detection Intelligence")
st.markdown("Search, pivot, and operationalize high-fidelity hunting queries across KQL, SPL, LogScale, Sigma, YARA,

# Initialize Repositories
hunt_db = HuntDatabase()
hunt_db.seed_default_knowledge_base()
mapping_engine = HuntMappingEngine(hunt_db)

coverage = mapping_engine.compute_coverage_matrix()

# Top Metrics Banner
col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
with col_m1:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Total Hunt Rules</div>
        <div class="soc-metric-value">{coverage['total_queries']}</div>
    </div>
    """, unsafe_allow_html=True)
with col_m2:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Covered ATT&CK TTPs</div>
        <div class="soc-metric-value">{coverage['technique_coverage_count']}</div>
    </div>
    """, unsafe_allow_html=True)
with col_m3:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Attributed Actors</div>
        <div class="soc-metric-value">{coverage['actor_coverage_count']}</div>
    </div>
    """, unsafe_allow_html=True)
with col_m4:
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">Indexed Malware</div>
        <div class="soc-metric-value">{coverage['malware_coverage_count']}</div>
    </div>
    """, unsafe_allow_html=True)
with col_m5:
    kql_cnt = coverage['language_distribution'].get('KQL', 0)
    spl_cnt = coverage['language_distribution'].get('SPL', 0)
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-metric-title">SIEM Dialects</div>
        <div class="soc-metric-value" style="font-size:1.1rem; padding-top:6px;">KQL:{kql_cnt} | SPL:{spl_cnt}</div>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# Navigation Tabs
tab_explore, tab_correlate, tab_create = st.tabs([
    " Query Repository & Inspector",
    " Entity Correlation Pivot",
    " Register Hunt Signature"
])

# -------------------------------------------------------------
# TAB 1: QUERY REPOSITORY & INSPECTOR
# -------------------------------------------------------------
with tab_explore:
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        search_query = st.text_input("Search rules by title, keyword, or MITRE ID:", "")
    with f_col2:
        lang_filter = st.selectbox("Language Dialect:", ["ALL"] + HuntDatabase.SUPPORTED_LANGUAGES)
    with f_col3:
        severity_filter = st.selectbox("Severity:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])

    df_queries = hunt_db.load_all_queries()

    if not df_queries.empty:
        # Apply filters
        if search_query:
            q_lower = search_query.lower()
            df_queries = df_queries[
                df_queries["title"].str.contains(q_lower, case=False, na=False) |
                df_queries["description"].str.contains(q_lower, case=False, na=False) |
                df_queries["query_content"].str.contains(q_lower, case=False, na=False) |
                df_queries["mitre_techniques"].astype(str).str.contains(q_lower, case=False, na=False)
            ]
        if lang_filter != "ALL":
            df_queries = df_queries[df_queries["language"] == lang_filter]
        if severity_filter != "ALL":
            df_queries = df_queries[df_queries["severity"] == severity_filter]

        st.markdown(f"**Showing {len(df_queries)} Matching Hunt Queries**")

        for _, row in df_queries.iterrows():
            with st.expander(f"[{row['language']}] [{row['severity']}] {row['title']} ({row['rule_id']})"):
                c_desc, c_meta = st.columns([3, 1])
                with c_desc:
                    st.markdown(f"**Description:** {row['description']}")

                    # Language formatting
                    lang_type = row['language'].lower()
                    if lang_type in ["kql", "spl", "fql"]:
                        st.code(row["query_content"], language="sql")
                    elif lang_type == "sigma":
                        st.code(row["query_content"], language="yaml")
                    elif lang_type == "yara":
                        st.code(row["query_content"], language="c")
                    else:
                        st.code(row["query_content"], language="text")

                with c_meta:
                    st.markdown(f"**Status:** `{row['status']}`")
                    st.markdown(f"**Author:** `{row['author']}`")
                    if row.get("mitre_techniques"):
                        st.markdown(f"**MITRE TTPs:** `{', '.join(row['mitre_techniques'])}`")
                    if row.get("associated_actors"):
                        st.markdown(f"**Actors:** `{', '.join(row['associated_actors'])}`")
                    if row.get("associated_malware"):
                        st.markdown(f"**Malware:** `{', '.join(row['associated_malware'])}`")
                    if row.get("data_sources"):
                        st.markdown(f"**Data Sources:** `{', '.join(row['data_sources'])}`")
    else:
        st.info("No hunt queries found.")

# -------------------------------------------------------------
# TAB 2: ENTITY CORRELATION PIVOT
# -------------------------------------------------------------
with tab_correlate:
    st.subheader("Cross-Entity Threat Hunting Correlation")
    pivot_target = st.radio(
        "Pivot Hunt Queries By:",
        ["MITRE ATT&CK Technique", "Threat Actor", "Malware Strain", "Intrusion Campaign"],
        horizontal=True
    )

    if pivot_target == "MITRE ATT&CK Technique":
        tech_opts = coverage["unique_techniques"]
        chosen_tech = st.selectbox("Select ATT&CK Technique:", tech_opts if tech_opts else ["None"])
        if chosen_tech and chosen_tech != "None":
            correlated = mapping_engine.get_queries_by_mitre_technique(chosen_tech)
            st.markdown(f"### Detections Mapped to `{chosen_tech}` ({len(correlated)} rules)")
            if not correlated.empty:
                st.dataframe(correlated[["rule_id", "title", "language", "severity", "status"]], use_container_width

    elif pivot_target == "Threat Actor":
        actor_opts = coverage["unique_actors"]
        chosen_actor = st.selectbox("Select Threat Actor:", actor_opts if actor_opts else ["None"])
        if chosen_actor and chosen_actor != "None":
            correlated = mapping_engine.get_queries_by_actor(chosen_actor)
            st.markdown(f"### Detections Attributed to `{chosen_actor}` ({len(correlated)} rules)")
            if not correlated.empty:
                st.dataframe(correlated[["rule_id", "title", "language", "severity", "query_content"]], use_containe

    elif pivot_target == "Malware Strain":
        mal_opts = coverage["unique_malware"]
        chosen_mal = st.selectbox("Select Malware Strain:", mal_opts if mal_opts else ["None"])
        if chosen_mal and chosen_mal != "None":
            correlated = mapping_engine.get_queries_by_malware(chosen_mal)
            st.markdown(f"### Detections Targeting `{chosen_mal}` ({len(correlated)} rules)")
            if not correlated.empty:
                st.dataframe(correlated[["rule_id", "title", "language", "severity", "query_content"]], use_containe

    elif pivot_target == "Intrusion Campaign":
        camp_input = st.text_input("Enter Campaign Name (e.g., Operation StealPast):", "Operation StealPast")
        if camp_input:
            correlated = mapping_engine.get_queries_by_campaign(camp_input)
            st.markdown(f"### Detections Associated with `{camp_input}` ({len(correlated)} rules)")
            if not correlated.empty:
                st.dataframe(correlated[["rule_id", "title", "language", "severity", "query_content"]], use_containe

# -------------------------------------------------------------
# TAB 3: REGISTER HUNT SIGNATURE
# -------------------------------------------------------------
with tab_create:
    st.subheader("Register New Detection Rule / Hunt Signature")

    with st.form("new_hunt_query_form"):
        c1, c2 = st.columns([2, 1])
        with c1:
            q_title = st.text_input("Rule Title*", placeholder="e.g., Encrypted C2 Handshake Pattern")
            q_desc = st.text_area("Description*", placeholder="Operational explanation of what this hunt query catch
        with c2:
            q_lang = st.selectbox("Language / Syntax*", HuntDatabase.SUPPORTED_LANGUAGES)
            q_sev = st.selectbox("Severity*", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], index=1)
            q_stat = st.selectbox("Status*", ["PRODUCTION", "TESTED", "EXPERIMENTAL"])

        q_content = st.text_area("Query / Detection Logic*", height=180, placeholder="Write raw KQL, SPL, FQL, Sigma

        c3, c4 = st.columns(2)
        with c3:
            q_mitre = st.text_input("MITRE ATT&CK Techniques (comma-separated):", "T1071.001, T1573")
            q_actors = st.text_input("Associated Threat Actors (comma-separated):", "APT28, Sandworm")
        with c4:
            q_malware = st.text_input("Associated Malware / Tools (comma-separated):", "Cobalt Strike")
            q_camps = st.text_input("Associated Campaigns (comma-separated):", "Operation StealPast")

        q_submit = st.form_submit_button(" Save to Hunt Repository", use_container_width=True)

        if q_submit:
            if not q_title or not q_content or not q_desc:
                st.error("Please fill in all required fields (Title, Description, and Query Content).")
            else:
                rule_id = HuntQueryRecord.generate_id(q_lang, q_title)
                new_record = HuntQueryRecord(
                    rule_id=rule_id,
                    title=q_title,
                    description=q_desc,
                    language=q_lang,
                    query_content=q_content,
                    severity=q_sev,
                    status=q_stat,
                    mitre_techniques=[t.strip().upper() for t in q_mitre.split(",") if t.strip()],
                    associated_actors=[a.strip() for a in q_actors.split(",") if a.strip()],
                    associated_malware=[m.strip() for m in q_malware.split(",") if m.strip()],
                    associated_campaigns=[c.strip() for c in q_camps.split(",") if c.strip()],
                    author="SOC Detection Engineer"
                )
                hunt_db.save_query(new_record)
                st.success(f"Successfully registered rule `{rule_id}` into {q_lang} signature vault!")
