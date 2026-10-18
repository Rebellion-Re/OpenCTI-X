"""
ThreatFusion CTI - MITRE ATT&CK Downloader
Pulls the canonical MITRE Enterprise ATT&CK STIX 2.1 catalog and parses
Tactics, Techniques, Sub-Techniques, Groups, Software, and Relationships.
"""

import json
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from config.settings import DATA_DIR, RAW_DATA_DIR
from config.logging_config import setup_logger

logger = setup_logger("MitreDownloader")

MITRE_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


class MitreDownloader:
    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self.cache_dir = cache_dir or (RAW_DATA_DIR / "mitre")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.stix_path = self.cache_dir / "enterprise-attack.json"

    def fetch_stix_bundle(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Downloads official Enterprise ATT&CK bundle or loads from disk cache.
        """
        if self.stix_path.exists() and not force_refresh:
            logger.info(f"Loading cached MITRE ATT&CK STIX bundle: {self.stix_path}")
            with open(self.stix_path, "r", encoding="utf-8") as f:
                return json.load(f)

        logger.info(f"Fetching MITRE Enterprise ATT&CK from {MITRE_ENTERPRISE_ATTACK_URL}...")
        req = urllib.request.Request(
            MITRE_ENTERPRISE_ATTACK_URL,
            headers={"User-Agent": "ThreatFusion-CTI/1.0 (+https://github.com/threatfusion)"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        with open(self.stix_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info(f"Persisted MITRE STIX catalog to {self.stix_path}")
        return data

    def parse_bundle(self, raw_stix: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Normalizes STIX 2.1 objects into discrete, typed relational entities.
        """
        objects = raw_stix.get("objects", [])

        tactics: List[Dict[str, Any]] = []
        techniques: List[Dict[str, Any]] = []
        groups: List[Dict[str, Any]] = []
        software: List[Dict[str, Any]] = []
        campaigns: List[Dict[str, Any]] = []
        relationships: List[Dict[str, Any]] = []

        # Maps stix-id to canonical technique ID for relationship linking
        id_to_object_map: Dict[str, Dict[str, Any]] = {}

        for obj in objects:
            obj_type = obj.get("type")
            is_revoked = obj.get("revoked", False)
            is_deprecated = obj.get("x_mitre_deprecated", False)
            if is_revoked or is_deprecated:
                continue

            stix_id = obj.get("id")

            # 1. TACTICS (x-mitre-tactic)
            if obj_type == "x-mitre-tactic":
                short_name = obj.get("x_mitre_shortname", "")
                ext_refs = obj.get("external_references", [])
                tactic_id = ext_refs[0].get("external_id", "") if ext_refs else ""
                tactic_data = {
                    "tactic_id": tactic_id,
                    "short_name": short_name,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "stix_id": stix_id,
                }
                tactics.append(tactic_data)
                id_to_object_map[stix_id] = tactic_data

            # 2. TECHNIQUES & SUB-TECHNIQUES (attack-pattern)
            elif obj_type == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                tech_id = ""
                url = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id", "")
                        url = ref.get("url", "")
                        break

                if not tech_id:
                    continue

                kill_chain = obj.get("kill_chain_phases", [])
                associated_tactics = [
                    phase.get("phase_name")
                    for phase in kill_chain
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]

                is_sub = obj.get("x_mitre_is_subtechnique", False)
                data_sources = obj.get("x_mitre_data_sources", [])
                platforms = obj.get("x_mitre_platforms", [])

                tech_data = {
                    "technique_id": tech_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactics": associated_tactics,
                    "is_subtechnique": is_sub,
                    "platforms": platforms,
                    "data_sources": data_sources,
                    "url": url,
                    "stix_id": stix_id,
                    "detection": obj.get("x_mitre_detection", ""),
                }
                techniques.append(tech_data)
                id_to_object_map[stix_id] = tech_data

            # 3. THREAT GROUPS (intrusion-set)
            elif obj_type == "intrusion-set":
                ext_refs = obj.get("external_references", [])
                group_id = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        group_id = ref.get("external_id", "")
                        break

                group_data = {
                    "group_id": group_id,
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", ""),
                    "stix_id": stix_id,
                }
                groups.append(group_data)
                id_to_object_map[stix_id] = group_data
            # 4. SOFTWARE / MALWARE / TOOLS (malware, tool)
            elif obj_type in ("malware", "tool"):
                ext_refs = obj.get("external_references", [])
                software_id = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        software_id = ref.get("external_id", "")
                        break

                sw_data = {
                    "software_id": software_id,
                    "name": obj.get("name", ""),
                    "type": obj_type.upper(),
                    "aliases": obj.get("x_mitre_aliases", []),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "description": obj.get("description", ""),
                    "stix_id": stix_id,
                }
                software.append(sw_data)
                id_to_object_map[stix_id] = sw_data

            # 5. CAMPAIGNS (campaign)
            elif obj_type == "campaign":
                ext_refs = obj.get("external_references", [])
                camp_id = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        camp_id = ref.get("external_id", "")
                        break

                camp_data = {
                    "campaign_id": camp_id,
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                    "first_seen": obj.get("first_seen"),
                    "last_seen": obj.get("last_seen"),
                    "description": obj.get("description", ""),
                    "stix_id": stix_id,
                }
                campaigns.append(camp_data)
                id_to_object_map[stix_id] = camp_data

            # 6. RELATIONSHIPS (relationship)
            elif obj_type == "relationship":
                rel_type = obj.get("relationship_type")
                source = obj.get("source_ref")
                target = obj.get("target_ref")

                if rel_type in ("uses", "attributed-to", "subtechnique-of", "targets"):
                    relationships.append({
                        "relationship_type": rel_type,
                        "source_ref": source,
                        "target_ref": target,
                        "description": obj.get("description", ""),
                    })

        return {
            "tactics": tactics,
            "techniques": techniques,
            "groups": groups,
            "software": software,
            "campaigns": campaigns,
            "relationships": relationships,
            "id_map": id_to_object_map,
        }
