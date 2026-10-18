from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

class ActorRecord(BaseModel):
    actor_id: str
    canonical_name: str
    aliases: List[str] = Field(default_factory=list)
    origin_country: str = "UNKNOWN"
    motivation: List[str] = Field(default_factory=list)
    sophistication: str = "INTERMEDIATE"
    first_observed: datetime
    last_observed: datetime
    targeted_countries: List[str] = Field(default_factory=list)
    targeted_sectors: List[str] = Field(default_factory=list)
    active_status: bool = True
    confidence_score: float = 50.0
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class MalwareRecord(BaseModel):
    malware_id: str
    canonical_name: str
    aliases: List[str] = Field(default_factory=list)
    malware_type: List[str] = Field(default_factory=list)
    target_os: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    is_open_source: bool = False
    first_seen: datetime
    last_seen: datetime
    confidence_score: float = 50.0

class CampaignRecord(BaseModel):
    campaign_id: str
    campaign_name: str
    threat_actors: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    target_sectors: List[str] = Field(default_factory=list)
    target_countries: List[str] = Field(default_factory=list)
    start_date: datetime
    end_date: Optional[datetime] = None
    confidence_score: float = 50.0
    object_summary: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)

class IOCRecord(BaseModel):
    ioc_id: str
    ioc_type: str
    ioc_value: str
    c2_flag: bool = False
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    country_code: str = "XX"
    threat_actors: List[str] = Field(default_factory=list)
    campaigns: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    decay_score: float = 100.0
    is_active: bool = True
class VulnerabilityRecord(BaseModel):
    cve_id: str
    cvss_v3_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: List[str] = Field(default_factory=list)
    is_known_exploited: bool = False
    ransomware_use: bool = False
    affected_vendors: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)
    first_published: datetime

class ReportRecord(BaseModel):
    report_id: str
    source_name: str
    title: str
    url: str
    publish_date: datetime
    raw_text_path: str = ""
    extracted_actors: List[str] = Field(default_factory=list)
    extracted_malware: List[str] = Field(default_factory=list)
    extracted_cves: List[str] = Field(default_factory=list)
    extracted_iocs: List[str] = Field(default_factory=list)
    mitre_hits: List[str] = Field(default_factory=list)

class NodeRecord(BaseModel):
    node_id: str
    node_type: str
    display_label: str
    degree_centrality: float = 0.0
    attributes_json: str = "{}"

class EdgeRecord(BaseModel):
    edge_id: str
    source_node: str
    target_node: str
    relation_type: str
    confidence: float = 50.0
    weight: float = 1.0
    first_observed: datetime
    last_observed: datetime
    evidence_reports: List[str] = Field(default_factory=list)
