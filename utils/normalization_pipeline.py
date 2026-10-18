"""
ThreatFusion CTI - Normalization & Entity Resolution Pipeline
Maps heterogeneous intelligence feeds and text strings to canonical entities.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import yaml

from config.settings import CONFIG_DIR
from config.logging_config import setup_logger

logger = setup_logger("NormalizationPipeline")


class NormalizationPipeline:
    def __init__(self) -> None:
        self.alias_path = CONFIG_DIR / "alias_dictionary.json"
        self.sectors_path = CONFIG_DIR / "sectors.yaml"
        self.geo_path = CONFIG_DIR / "country_regions.json"

        # Lookup caches
        self.actor_alias_map: Dict[str, str] = {}
        self.malware_alias_map: Dict[str, str] = {}
        self.tool_alias_map: Dict[str, str] = {}
        self.sector_definitions: List[Dict[str, Any]] = []
        self.geo_definitions: Dict[str, Dict[str, Any]] = {}
        self.country_name_to_code: Dict[str, str] = {}

        self.load_reference_catalogs()

    def load_reference_catalogs(self) -> None:
        """Loads and compiles alias tables and geographic catalogs into memory."""
        # Load Actor, Malware, and Tool Aliases
        if self.alias_path.exists():
            try:
                with open(self.alias_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Threat Actors / Threat Groups
                for canonical, aliases in data.get("actors", {}).items():
                    self.actor_alias_map[canonical.lower()] = canonical
                    for a in aliases:
                        self.actor_alias_map[a.lower()] = canonical

                # Malware Families
                for canonical, aliases in data.get("malware", {}).items():
                    self.malware_alias_map[canonical.lower()] = canonical
                    for a in aliases:
                        self.malware_alias_map[a.lower()] = canonical

                # Tools (Commodity / Penetration Testing Utilities)
                for canonical, aliases in data.get("tools", {
                    "Mimikatz": ["mimi", "sekurlsa"],
                    "Cobalt Strike": ["beacon", "cs beacon"],
                    "Chisel": ["chisel-tunnel"],
                    "BloodHound": ["SharpHound"],
                    "Impacket": ["wmiexec", "psexec.py", "secretsdump"],
                    "Sqlmap": ["sqlmap-dev"],
                    "PsExec": ["psexec.exe", "sysinternals psexec"]
                }).items():
                    self.tool_alias_map[canonical.lower()] = canonical
                    for a in aliases:
                        self.tool_alias_map[a.lower()] = canonical

            except Exception as e:
                logger.error(f"Failed to load alias dictionary: {e}")

        # Load Sector Taxonomies
        if self.sectors_path.exists():
            try:
                with open(self.sectors_path, "r", encoding="utf-8") as f:
                    sec_data = yaml.safe_load(f)
                    self.sector_definitions = sec_data.get("sectors", [])
            except Exception as e:
                logger.error(f"Failed to load sectors: {e}")

        # Load Geographic Taxonomies
        if self.geo_path.exists():
            try:
                with open(self.geo_path, "r", encoding="utf-8") as f:
                    self.geo_definitions = json.load(f)
                    for code, info in self.geo_definitions.items():
                        self.country_name_to_code[info["name"].lower()] = code
                        # Add subregion/region aliases
                        self.country_name_to_code[code.lower()] = code
            except Exception as e:
                logger.error(f"Failed to load geo database: {e}")

    def resolve_threat_actors(self, text: str) -> List[str]:
        """Identifies threat actors/groups from text and returns canonical names."""
        text_lower = text.lower()
        matched = set()

        # Check sorted by length descending to prioritize longer phrases
        sorted_keys = sorted(self.actor_alias_map.keys(), key=len, reverse=True)
        for key in sorted_keys:
            # Word boundary search
            pattern = r'\b' + re.escape(key) + r'\b'
            if re.search(pattern, text_lower):
                canonical = self.actor_alias_map[key]
                matched.add(canonical)

        return sorted(list(matched))

    def resolve_malware(self, text: str) -> List[str]:
        """Identifies malware strains from text and returns canonical names."""
        text_lower = text.lower()
        matched = set()

        sorted_keys = sorted(self.malware_alias_map.keys(), key=len, reverse=True)
        for key in sorted_keys:
            pattern = r'\b' + re.escape(key) + r'\b'
            if re.search(pattern, text_lower):
                canonical = self.malware_alias_map[key]
                matched.add(canonical)

        return sorted(list(matched))

    def resolve_tools(self, text: str) -> List[str]:
        """Identifies dual-use/offensive tools from text."""
        text_lower = text.lower()
        matched = set()

        for key, canonical in self.tool_alias_map.items():
            pattern = r'\b' + re.escape(key) + r'\b'
            if re.search(pattern, text_lower):
                matched.add(canonical)

        return sorted(list(matched))

    def resolve_campaigns(self, text: str) -> List[str]:
        """Extracts designated campaign monikers (Operation X, Campaign Y)."""
        campaign_patterns = [
            re.compile(r'\bOperation\s+[A-Z][a-zA-Z0-9_\-\s]{2,20}\b'),
            re.compile(r'\bCampaign\s+[A-Z][a-zA-Z0-9_\-\s]{2,20}\b'),
            re.compile(r'\b[A-Z][a-zA-Z0-9_]+\s+Campaign\b')
        ]
        found = set()
        for pat in campaign_patterns:
            for match in pat.finditer(text):
                c = match.group(0).strip()
                # Exclude generic false positives
                if len(c) > 10 and not any(neg in c.lower() for neg in ["operation system", "operation code", "opera
                    found.add(c)
        return sorted(list(found))

    def resolve_sectors(self, text: str) -> List[str]:
        """Maps content to CISA/NAICS critical infrastructure sectors."""
        text_lower = text.lower()
        matched_sectors = set()

        for sector in self.sector_definitions:
            s_name = sector["name"]
            # Check sector name directly
            if re.search(r'\b' + re.escape(s_name.lower()) + r'\b', text_lower):
                matched_sectors.add(s_name)
                continue
            # Check sector keywords
            for kw in sector.get("keywords", []):
                if re.search(r'\b' + re.escape(kw.lower()) + r'\b', text_lower):
                    matched_sectors.add(s_name)
                    break

        return sorted(list(matched_sectors))

    def resolve_geopolitics(self, text: str) -> Tuple[List[str], List[str]]:
        """
        Extracts impacted countries (ISO codes) and geographic regions.
        Returns: (country_codes, regions)
        """
        text_lower = text.lower()
        matched_countries = set()
        matched_regions = set()
        for code, info in self.geo_definitions.items():
            name = info["name"].lower()
            region = info.get("region")
            subregion = info.get("subregion")

            # Match on country name with word boundary
            if re.search(r'\b' + re.escape(name) + r'\b', text_lower):
                matched_countries.add(code)
                if region:
                    matched_regions.add(region)
                if subregion:
                    matched_regions.add(subregion)

        # Explicit region matching
        for reg in ["Americas", "Europe", "Asia", "Middle East", "Africa", "Oceania", "Latin America", "Indo-Pacific
            if re.search(r'\b' + re.escape(reg.lower()) + r'\b', text_lower):
                matched_regions.add(reg)

        return sorted(list(matched_countries)), sorted(list(matched_regions))
