import json
from pathlib import Path
from typing import Dict, Optional, Tuple
from config.settings import CONFIG_DIR

class EntityResolver:
    def __init__(self) -> None:
        self.alias_path: Path = CONFIG_DIR / "alias_dictionary.json"
        self.actor_lookup: Dict[str, str] = {}
        self.malware_lookup: Dict[str, str] = {}
        self._load_dictionaries()

    def _load_dictionaries(self) -> None:
        if self.alias_path.exists():
            with open(self.alias_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Map canonical names and aliases to canonical representation
            for canonical, aliases in data.get("actors", {}).items():
                self.actor_lookup[canonical.lower()] = canonical
                for alias in aliases:
                    self.actor_lookup[alias.lower()] = canonical

            for canonical, aliases in data.get("malware", {}).items():
                self.malware_lookup[canonical.lower()] = canonical
                for alias in aliases:
                    self.malware_lookup[alias.lower()] = canonical

    def resolve_actor(self, candidate_name: str) -> Optional[str]:
        return self.actor_lookup.get(candidate_name.strip().lower())

    def resolve_malware(self, candidate_name: str) -> Optional[str]:
        return self.malware_lookup.get(candidate_name.strip().lower())
