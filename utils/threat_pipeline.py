"""
ThreatFusion CTI - Master Ingestion & Parsing Pipeline Coordinator
"""

import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd

from utils.threat_parsers import ThreatParsers
from utils.normalization_pipeline import NormalizationPipeline
from utils.categorization_engine import CategorizationEngine
from database.schemas import ReportRecord, IOCRecord
from config.logging_config import setup_logger

logger = setup_logger("ThreatPipeline")


class ThreatPipeline:
    def __init__(self) -> None:
        self.parsers = ThreatParsers()
        self.normalizer = NormalizationPipeline()
        self.categorizer = CategorizationEngine()

    def process_raw_document(
        self,
        raw_text: str,
        source_title: str,
        source_url: str,
        source_name: str,
        publish_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end extraction, normalization, and categorization pipeline.
        Returns a structured dictionary ready for Apache Parquet persistence.
        """
        if publish_date is None:
            publish_date = datetime.utcnow()

        # 1. Deterministic IOC Parsing
        extracted_ips = self.parsers.extract_ips(raw_text)
        extracted_urls = self.parsers.extract_urls(raw_text)

        # Exclude URL netlocs from domain matching to prevent duplication
        excluded_hosts = {u["hostname"] for u in extracted_urls if "hostname" in u}
        extracted_domains = self.parsers.extract_domains(raw_text, excluded_hosts=excluded_hosts)

        extracted_emails = self.parsers.extract_emails(raw_text)
        extracted_hashes = self.parsers.extract_hashes(raw_text)
        extracted_cves = self.parsers.extract_cves(raw_text)
        explicit_mitre_techs, explicit_mitre_tactics = self.parsers.extract_mitre_ids(raw_text)
        # 2. Entity Normalization & Resolution
        threat_actors = self.normalizer.resolve_threat_actors(raw_text)
        malware = self.normalizer.resolve_malware(raw_text)
        tools = self.normalizer.resolve_tools(raw_text)
        campaigns = self.normalizer.resolve_campaigns(raw_text)
        sectors = self.normalizer.resolve_sectors(raw_text)
        target_countries, target_regions = self.normalizer.resolve_geopolitics(raw_text)

        # 3. Categorization & Behavioral TTP Analysis
        behavior_analysis = self.categorizer.analyze_behaviors_and_ttps(raw_text)
        mitre_tech_records = behavior_analysis["mitre_techniques"]

        # Add explicit MITRE IDs detected in raw text
        existing_tids = {t["technique_id"] for t in mitre_tech_records}
        for tid in explicit_mitre_techs:
            if tid not in existing_tids:
                mitre_tech_records.append({
                    "technique_id": tid,
                    "technique_name": "Referenced ATT&CK Technique",
                    "tactic": "Unassigned",
                    "tactic_id": "TA0000",
                    "confidence": 70.0
                })

        category = self.categorizer.determine_threat_category(
            actors=threat_actors,
            malware=malware,
            cves=extracted_cves,
            techniques=mitre_tech_records,
            text=raw_text
        )

        # 4. Generate Standardized Lakehouse Records
        report_id = hashlib.sha256(source_url.encode("utf-8")).hexdigest()

        # Build IOC structured records
        all_iocs = []
        for item in extracted_ips + extracted_urls + extracted_domains + extracted_emails + extracted_hashes:
            ioc_val = item["normalized"]
            ioc_type = item["type"]
            ioc_id = hashlib.sha256(f"{ioc_type}:{ioc_val}".encode("utf-8")).hexdigest()

            # Dynamic IOC confidence
            c2_flag = (ioc_type in ("IPV4", "DOMAIN", "URL")) and (
                any(t["technique_id"] in ("T1071.001", "T1573") for t in mitre_tech_records) or
                "c2" in raw_text.lower() or "command and control" in raw_text.lower()
            )

            all_iocs.append({
                "ioc_id": ioc_id,
                "ioc_type": ioc_type,
                "ioc_value": item.get("defanged", ioc_val),
                "c2_flag": c2_flag,
                "asn": None,
                "asn_org": None,
                "country_code": target_countries[0] if target_countries else "XX",
                "threat_actors": threat_actors,
                "campaigns": campaigns,
                "malware_families": malware,
                "first_seen": publish_date,
                "last_seen": publish_date,
                "decay_score": 100.0,
                "is_active": True
            })

        structured_report = {
            "report_id": report_id,
            "source_name": source_name,
            "title": source_title,
            "url": source_url,
            "publish_date": publish_date,
            "threat_category": category,
            "extracted_actors": threat_actors,
            "extracted_malware": malware,
            "extracted_tools": tools,
            "extracted_campaigns": campaigns,
            "extracted_cves": extracted_cves,
            "extracted_sectors": sectors,
            "target_countries": target_countries,
            "target_regions": target_regions,
            "ttps": behavior_analysis["ttps"],
            "mitre_techniques": [t["technique_id"] for t in mitre_tech_records],
            "mitre_tactics": behavior_analysis["mitre_tactics"],
            "ioc_count": len(all_iocs)
        }

        return {
            "report": structured_report,
            "iocs": all_iocs
        }
