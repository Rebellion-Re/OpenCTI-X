"""
ThreatFusion CTI - Knowledge Graph Data Models & Confidence Algorithms
Defines entity nodes, directed typed edges, and mathematical scoring models.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
import math
import hashlib


class RelationTypes:
    # Actor relationships
    ACTOR_USES_MALWARE = "USES_MALWARE"
    ACTOR_USES_TOOL = "USES_TOOL"
    ACTOR_CONDUCTS_CAMPAIGN = "CONDUCTS_CAMPAIGN"
    ACTOR_EXPLOITS_VULNERABILITY = "EXPLOITS_VULNERABILITY"
    ACTOR_EXHIBITS_TECHNIQUE = "EXHIBITS_TECHNIQUE"
    ACTOR_TARGETS_SECTOR = "TARGETS_SECTOR"
    ACTOR_TARGETS_COUNTRY = "TARGETS_COUNTRY"

    # Campaign relationships
    CAMPAIGN_DEPLOYS_MALWARE = "DEPLOYS_MALWARE"
    CAMPAIGN_UTILIZES_IOC = "UTILIZES_IOC"
    CAMPAIGN_EXPLOITS_CVE = "EXPLOITS_CVE"
    CAMPAIGN_TARGETS_SECTOR = "TARGETS_SECTOR"
    CAMPAIGN_TARGETS_COUNTRY = "TARGETS_COUNTRY"
    CAMPAIGN_EXHIBITS_TECHNIQUE = "EXHIBITS_TECHNIQUE"

    # Malware relationships
    MALWARE_COMMUNICATES_WITH_IOC = "COMMUNICATES_WITH"
    MALWARE_EXPLOITS_CVE = "EXPLOITS_CVE"
    MALWARE_EXHIBITS_TECHNIQUE = "EXHIBITS_TECHNIQUE"

    # IOC relationships
    IOC_RESOLVES_TO_IP = "RESOLVES_TO"
    IOC_HOSTED_BY_ASN = "HOSTED_BY"


@dataclass
class GraphNode:
    node_id: str
    node_type: str  # ACTOR, CAMPAIGN, MALWARE, IOC, CVE, TECHNIQUE, COUNTRY, SECTOR
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @staticmethod
    def format_id(node_type: str, raw_identifier: str) -> str:
        clean_id = raw_identifier.strip().replace(" ", "_").upper()
        return f"{node_type.upper()}:{clean_id}"


@dataclass
class GraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    relation_type: str
    confidence_score: float = 50.0
    weight: float = 1.0
    evidence_reports: List[str] = field(default_factory=list)
    first_observed: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_observed: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @staticmethod
    def generate_id(source_id: str, relation_type: str, target_id: str) -> str:
        token = f"{source_id}->{relation_type}->{target_id}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
class ConfidenceScorer:
    """
    Computes dynamic confidence scores using:
    - Base source reliability (High Trust = 1.25, Medium = 1.0, Low = 0.75)
    - Independent corroboration factor
    - Temporal exponential decay: Confidence = Initial * e^(-lambda * delta_days)
    """
    SOURCE_WEIGHTS = {
        "HIGH_TRUST": 1.25,
        "MEDIUM_TRUST": 1.0,
        "LOW_TRUST": 0.75
    }

    @classmethod
    def calculate_edge_confidence(
        cls,
        corroboration_count: int,
        trust_level: str = "HIGH_TRUST",
        days_since_last_seen: float = 0.0,
        half_life_days: float = 45.0
    ) -> float:
        trust_mult = cls.SOURCE_WEIGHTS.get(trust_level, 1.0)

        # Corroboration curve: base 50.0 + up to 40.0 additional points
        # Saturated logarithmically
        raw_confidence = (40.0 * trust_mult) + (math.log(corroboration_count + 1, 2) * 18.0)
        raw_confidence = min(100.0, max(10.0, raw_confidence))

        # Exponential decay calculation
        decay_lambda = math.log(2) / half_life_days
        decay_factor = math.exp(-decay_lambda * max(0.0, days_since_last_seen))

        return round(float(raw_confidence * decay_factor), 2)
