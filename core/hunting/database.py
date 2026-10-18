"""
ThreatFusion CTI - Threat Hunting Database Engine
Manages Sigma, KQL, Splunk SPL, and YARA detection signatures.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from config.settings import SIGNATURES_DIR
from config.logging_config import setup_logger

logger = setup_logger("HuntDatabase")


class HuntDatabase:
    """Repository and search engine for detection rules and hunting logic."""

    def __init__(self, signatures_dir: Optional[Path] = None) -> None:
        self.signatures_dir = signatures_dir or SIGNATURES_DIR
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        self.signatures: List[Dict[str, Any]] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Loads and indexes rule signatures from disk."""
        self.signatures = []
        for file_path in self.signatures_dir.glob("**/*.*"):
            if file_path.suffix.lower() in [".json", ".yaml", ".yml", ".kql", ".spl", ".yar", ".yara"]:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        raw_content = f.read()

                    self.signatures.append({
                        "rule_id": file_path.stem,
                        "rule_name": file_path.stem.replace("_", " ").title(),
                        "rule_type": file_path.suffix.lower().lstrip("."),
                        "file_path": str(file_path),
                        "content": raw_content,
                    })
                except Exception as e:
                    logger.warning(f"Failed to read signature {file_path.name}: {e}")

    def get_all_rules(self) -> pd.DataFrame:
        """Returns all loaded detection rules as a DataFrame."""
        if not self.signatures:
            return pd.DataFrame(columns=["rule_id", "rule_name", "rule_type", "file_path", "content"])
        return pd.DataFrame(self.signatures)

    def search_rules(self, query: str) -> pd.DataFrame:
        """Searches rules by query string across name, type, and content."""
        if not query:
            return self.get_all_rules()

        q = query.lower()
        matched = [
            r for r in self.signatures
            if q in r["rule_name"].lower() or q in r["rule_type"].lower() or q in r["content"].lower()
        ]
        if not matched:
            return pd.DataFrame(columns=["rule_id", "rule_name", "rule_type", "file_path", "content"])
        return pd.DataFrame(matched)

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single rule definition by its identifier."""
        for rule in self.signatures:
            if rule["rule_id"] == rule_id:
                return rule
        return None
