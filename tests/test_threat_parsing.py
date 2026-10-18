"""
ThreatFusion CTI - Automated Tests for Parsing, Normalization & Categorization
"""

import pytest
from utils.threat_parsers import ThreatParsers
from utils.normalization_pipeline import NormalizationPipeline
from utils.categorization_engine import CategorizationEngine
from utils.threat_pipeline import ThreatPipeline


SAMPLE_INTEL_TEXT = """
In late 2024, Fancy Bear (also known as APT28) launched Operation StealPast targeting 
the Financial Services sector and Defense Industrial Base across Ukraine and the United States.
The threat group exploited CVE-2023-38831 in WinRAR and used PowerShell to execute encoded payloads.
Attackers deployed Mimikatz to dump credentials from lsass.exe and established persistence 
via scheduled tasks. Cobalt Strike Beacon was observed connecting to command and control 
infrastructure at 198.51.100.25:8080 and hxxps://malicious-telemetry[.]com/api/v1.
The sample SHA256 was 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae.
"""


def test_parsers_extraction():
    parsers = ThreatParsers()
    
    # Test IP Extraction (excludes private/bogons)
    ips = parsers.extract_ips(SAMPLE_INTEL_TEXT)
    assert any(ip["normalized"] == "198.51.100.25" for ip in ips)

    # Test URL Defanging / Extraction
    urls = parsers.extract_urls(SAMPLE_INTEL_TEXT)
    assert any("malicious-telemetry.com" in u["normalized"] for u in urls)

    # Test Hash Extraction
    hashes = parsers.extract_hashes(SAMPLE_INTEL_TEXT)
    assert any(h["normalized"] == "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" for h in hashes)

    # Test CVE Extraction
    cves = parsers.extract_cves(SAMPLE_INTEL_TEXT)
    assert "CVE-2023-38831" in cves


def test_normalization_and_aliases():
    normalizer = NormalizationPipeline()
    
    actors = normalizer.resolve_threat_actors(SAMPLE_INTEL_TEXT)
    assert "APT28" in actors

    malware = normalizer.resolve_malware(SAMPLE_INTEL_TEXT)
    assert "Cobalt Strike" in malware

    tools = normalizer.resolve_tools(SAMPLE_INTEL_TEXT)
    assert "Mimikatz" in tools

    campaigns = normalizer.resolve_campaigns(SAMPLE_INTEL_TEXT)
    assert "Operation StealPast" in campaigns

    sectors = normalizer.resolve_sectors(SAMPLE_INTEL_TEXT)
    assert "Financial Services" in sectors
    assert "Defense Industrial Base" in sectors

    countries, regions = normalizer.resolve_geopolitics(SAMPLE_INTEL_TEXT)
    assert "UA" in countries
    assert "US" in countries
    assert "Europe" in regions


def test_categorization_and_ttps():
    categorizer = CategorizationEngine()
    analysis = categorizer.analyze_behaviors_and_ttps(SAMPLE_INTEL_TEXT)

    tech_ids = {t["technique_id"] for t in analysis["mitre_techniques"]}
    assert "T1059.001" in tech_ids
    assert "T1003.001" in tech_ids
    assert "T1053.005" in tech_ids

    category = categorizer.determine_threat_category(
        actors=["APT28"],
        malware=["Cobalt Strike"],
        cves=["CVE-2023-38831"],
        techniques=analysis["mitre_techniques"],
        text=SAMPLE_INTEL_TEXT
    )
    assert category == "APT_ESPIONAGE"


def test_end_to_end_threat_pipeline():
    pipeline = ThreatPipeline()
    result = pipeline.process_raw_document(
        raw_text=SAMPLE_INTEL_TEXT,
        source_title="Advisory: APT28 Campaign Analysis",
        source_url="https://threatfusion.local/reports/apt28-stealpast",
        source_name="Talos Research"
    )

    report = result["report"]
    iocs = result["iocs"]

    assert report["threat_category"] == "APT_ESPIONAGE"
    assert "APT28" in report["extracted_actors"]
    assert len(iocs) >= 1
