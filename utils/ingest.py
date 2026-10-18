import hashlib
from datetime import datetime
import feedparser
import yaml
import pandas as pd
from config.settings import CONFIG_DIR
from config.logging_config import setup_logger
from database.parquet_store import ParquetStore
from utils.ioc_extractor import IOCExtractor
from utils.mitre_tagger import MitreTagger
from utils.entity_resolver import EntityResolver

logger = setup_logger("IngestPipeline")

def run_pipeline() -> None:
    store = ParquetStore()
    store.initialize_lake()
    resolver = EntityResolver()

    sources_path = CONFIG_DIR / "sources.yaml"
    if not sources_path.exists():
        logger.error(f"Missing configuration: {sources_path}")
        return

    with open(sources_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    existing_reports_df = store.read_table("reports")
    seen_urls = set(existing_reports_df["url"].dropna().tolist()) if not existing_reports_df.empty else set()

    new_reports = []
    new_iocs = []

    for src in config.get("sources", []):
        if not src.get("enabled", False) or src.get("type") != "rss":
            continue

        feed_url = src.get("url")
        feed_name = src.get("name")
        logger.info(f"Harvesting feed: {feed_name} -> {feed_url}")

        try:
            parsed = feedparser.parse(feed_url)
            for entry in parsed.entries[:10]:
                link = entry.get("link", "")
                if link in seen_urls:
                    continue

                title = entry.get("title", "")
                summary = entry.get("summary", "")
                full_text = f"{title} {summary}"
                # Deterministic Parsing
                report_id = hashlib.sha256(link.encode()).hexdigest()
                extracted_iocs = IOCExtractor.extract_all(full_text)
                mitre_tags = MitreTagger.tag_text(full_text)

                # Actor / Malware identification
                detected_actors = []
                for candidate in resolver.actor_lookup.keys():
                    if candidate in full_text.lower():
                        detected_actors.append(resolver.resolve_actor(candidate))
                detected_actors = list(set(filter(None, detected_actors)))

                detected_malware = []
                for candidate in resolver.malware_lookup.keys():
                    if candidate in full_text.lower():
                        detected_malware.append(resolver.resolve_malware(candidate))
                detected_malware = list(set(filter(None, detected_malware)))

                # Add report record
                new_reports.append({
                    "report_id": report_id,
                    "source_name": feed_name,
                    "title": title,
                    "url": link,
                    "publish_date": pd.to_datetime(datetime.utcnow()),
                    "raw_text_path": "",
                    "extracted_actors": detected_actors,
                    "extracted_malware": detected_malware,
                    "extracted_cves": [],
                    "extracted_iocs": [i["ioc_id"] for i in extracted_iocs],
                    "mitre_hits": [m["technique_id"] for m in mitre_tags]
                })

                # Flatten extracted IOCs
                for ioc in extracted_iocs:
                    new_iocs.append({
                        "ioc_id": ioc["ioc_id"],
                        "ioc_type": ioc["ioc_type"],
                        "ioc_value": ioc["ioc_value"],
                        "c2_flag": False,
                        "asn": None,
                        "asn_org": None,
                        "country_code": "XX",
                        "threat_actors": detected_actors,
                        "campaigns": [],
                        "malware_families": detected_malware,
                        "first_seen": pd.to_datetime(datetime.utcnow()),
                        "last_seen": pd.to_datetime(datetime.utcnow()),
                        "decay_score": 100.0,
                        "is_active": True
                    })

                seen_urls.add(link)
        except Exception as e:
            logger.error(f"Error parsing feed {feed_name}: {str(e)}")

    # Vectorized persist
    if new_reports:
        df_new_reports = pd.DataFrame(new_reports)
        combined_reports = pd.concat([existing_reports_df, df_new_reports], ignore_index=True).drop_duplicates(subse
        store.write_table("reports", combined_reports)
        logger.info(f"Persisted {len(new_reports)} new threat reports.")

    if new_iocs:
        existing_iocs_df = store.read_table("iocs")
        df_new_iocs = pd.DataFrame(new_iocs)
        combined_iocs = pd.concat([existing_iocs_df, df_new_iocs], ignore_index=True).drop_duplicates(subset=["ioc_i
        store.write_table("iocs", combined_iocs)
        logger.info(f"Persisted {len(new_iocs)} new IOC records.")
