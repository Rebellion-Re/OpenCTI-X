import streamlit as st
from config.settings import CSS_DIR, APP_TITLE
from database.parquet_store import ParquetStore

st.set_page_config(page_title=f"{APP_TITLE} | IOC Intelligence", page_icon="", layout="wide")

css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" Indicators of Compromise (IOCs)")
st.markdown("Search, filter, and export deduplicated indicators with confidence decay scoring.")

store = ParquetStore()
iocs_df = store.query("""
SELECT ioc_type, ioc_value, decay_score, is_active, first_seen, last_seen
FROM iocs
ORDER BY last_seen DESC
""")

if not iocs_df.empty:
    search = st.text_input("Filter indicators by value or type (e.g., IPV4, DOMAIN, SHA256):")
    if search:
        iocs_df = iocs_df[iocs_df['ioc_value'].str.contains(search, case=False, na=False) | iocs_df['ioc_type'].str.
    st.dataframe(iocs_df, use_container_width=True, hide_index=True)
else:
    st.info("No indicators observed yet. Harvest data through the ingestion pipeline.")
