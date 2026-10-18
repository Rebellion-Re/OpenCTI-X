import streamlit as st
from config.settings import CSS_DIR, APP_TITLE
from database.parquet_store import ParquetStore

st.set_page_config(page_title=f"{APP_TITLE} | Threat Actors", page_icon="", layout="wide")

css_file = CSS_DIR / "dark_theme.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title(" Threat Actor Intelligence")
st.markdown("Track nation-state advanced persistent threats (APTs) and financially-motivated threat groups.")

store = ParquetStore()
actors_df = store.read_table("actors")

if not actors_df.empty:
    st.dataframe(actors_df, use_container_width=True, hide_index=True)
else:
    st.info("No Threat Actor profiles loaded in database. Connect MITRE ATT&CK or ingestion pipeline.")
