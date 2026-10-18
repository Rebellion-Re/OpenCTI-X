"""
ThreatFusion CTI - Threat Hunting Query Data Schemas
Defines structured hunt objects across KQL, SPL, FQL, Sigma, YARA, and Regex.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
import hashlib


@dataclass
class HuntQueryRecord:
    rule_id: str
    title: str
    description: str
    language: str  # KQL, SPL, FQL, SIGMA, YARA, REGEX
    query_content: str
    severity: str  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    status: str    # EXPERIMENTAL, TESTED, PRODUCTION
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    associated_actors: List[str] = field(default_factory=list)
    associated_malware: List[str] = field(default_factory=list)
    associated_campaigns: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    author: str = "ThreatFusion Research"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @staticmethod
    def generate_id(language: str, title: str) -> str:
        """Generates a deterministic unique ID based on language and rule title."""
        token = f"{language.upper()}:{title.strip().lower()}"
        return f"HUNT-{hashlib.sha256(token.encode('utf-8')).hexdigest()[:12].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "language": self.language.upper(),
            "query_content": self.query_content,
            "severity": self.severity.upper(),
            "status": self.status.upper(),
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "associated_actors": self.associated_actors,
            "associated_malware": self.associated_malware,
            "associated_campaigns": self.associated_campaigns,
            "data_sources": self.data_sources,
            "false_positives": self.false_positives,
            "author": self.author,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
