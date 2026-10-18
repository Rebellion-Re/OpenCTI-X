"""
ThreatFusion CTI - Normalization & Entity Resolution Pipeline
Maps heterogeneous intelligence feeds and text strings to canonical entities.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
import yaml

from config.settings import CONFIG_DIR


class NormalizationPipeline:
    def __init__(self) -> None:
        self.alias_path = CONFIG_DIR / "alias_dictionary.json"
        self.sectors_path = CONFIG_DIR / "sectors.yaml"
        self.geo_path = CONFIG_DIR / "country_regions.json"

        self.actor_map: Dict[str, str] = {}
        self.malware_map: Dict[str, str] = {}
        self.tool_map: Dict[str, str] = {}
        self.sectors: List[Dict[str, Any]] = []
        self.geo_data: Dict[str, Dict[str, Any]] = {}
        self._load_catalogs()

    def _load_catalogs(self) -> None:
        if self.alias_path.exists():
            with open(self.alias_path, "r", encoding="utf-8") as f:
                d = json.load(f)

            for can, aliases in d.get("actors", {}).items():
                self.actor_map[can.lower()] = can
                for a in aliases:
                    self.actor_map[a.lower()] = can

            for can, aliases in d.get("malware", {}).items():
                self.malware_map[can.lower()] = can
                for a in aliases:
                    self.malware_map[a.lower()] = can

            for can, aliases in d.get("tools", {}).items():
                self.tool_map[can.lower()] = can
                for a in aliases:
                    self.tool_map[a.lower()] = can

        if self.sectors_path.exists():
            with open(self.sectors_path, "r", encoding="utf-8") as f:
                self.sectors = yaml.safe_load(f).get("sectors", [])

        if self.geo_path.exists():
            with open(self.geo_path, "r", encoding="utf-8") as f:
                self.geo_data = json.load(f)

    def resolve_threat_actors(self, text: str) -> List[str]:
        t_low = text.lower()
        matched = set()
        for k in sorted(self.actor_map.keys(), key=len, reverse=True):
            if re.search(r"\b" + re.escape(k) + r"\b", t_low):
                matched.add(self.actor_map[k])
        return sorted(list(matched))

    def resolve_malware(self, text: str) -> List[str]:
        t_low = text.lower()
        matched = set()
        for k in sorted(self.malware_map.keys(), key=len, reverse=True):
            if re.search(r"\b" + re.escape(k) + r"\b", t_low):
                matched.add(self.malware_map[k])
        return sorted(list(matched))

    def resolve_tools(self, text: str) -> List[str]:
        t_low = text.lower()
        matched = set()
        for k in sorted(self.tool_map.keys(), key=len, reverse=True):
            if re.search(r"\b" + re.escape(k) + r"\b", t_low):
                matched.add(self.tool_map[k])
        return sorted(list(matched))

    def resolve_campaigns(self, text: str) -> List[str]:
        campaign_patterns = [
            re.compile(r"\bOperation\s+[A-Z][a-zA-Z0-9_\-\s]{2,20}\b"),
            re.compile(r"\bCampaign\s+[A-Z][a-zA-Z0-9_\-\s]{2,20}\b"),
            re.compile(r"\b[A-Z][a-zA-Z0-9_]+\s+Campaign\b"),
        ]
        found = set()
        for pat in campaign_patterns:
            for match in pat.finditer(text):
                c = match.group(0).strip()
                if len(c) > 10 and not any(
                    neg in c.lower()
                    for neg in ["operation system", "operation code", "operation type"]
                ):
                    found.add(c)
        return sorted(list(found))

    def resolve_sectors(self, text: str) -> List[str]:
        t_low = text.lower()
        matched = set()
        for s in self.sectors:
            if re.search(r"\b" + re.escape(s["name"].lower()) + r"\b", t_low):
                matched.add(s["name"])
            for kw in s.get("keywords", []):
                if re.search(r"\b" + re.escape(kw.lower()) + r"\b", t_low):
                    matched.add(s["name"])
        return sorted(list(matched))

    def resolve_geopolitics(self, text: str) -> Tuple[List[str], List[str]]:
        t_low = text.lower()
        countries, regions = set(), set()

        for code, info in self.geo_data.items():
            if re.search(r"\b" + re.escape(info["name"].lower()) + r"\b", t_low):
                countries.add(code)
                if "region" in info:
                    regions.add(info["region"])

        for reg in [
            "Americas",
            "Europe",
            "Asia",
            "Middle East",
            "Africa",
            "Oceania",
            "Latin America",
            "Indo-Pacific",
        ]:
            if re.search(r"\b" + re.escape(reg.lower()) + r"\b", t_low):
                regions.add(reg)

        return sorted(list(countries)), sorted(list(regions))
