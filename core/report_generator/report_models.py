"""
ThreatFusion CTI - Report Models & Data Contracts
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class ReportData:
    report_type: str  # EXECUTIVE, ACTOR, CAMPAIGN, MALWARE, VULNERABILITY, IOC, MITRE, HUNTING
    title: str
    tlp: str = "AMBER"  # WHITE, GREEN, AMBER, RED
    classification: str = "CONFIDENTIAL // TLP:AMBER // THREAT INTEL"
    author: str = "ThreatFusion CTI Operations"
    date_generated: str = field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    executive_summary: str = ""
    strategic_impact: str = ""
    recommendations: List[Dict[str, str]] = field(default_factory=list)

    # Visual & Structural Artifacts
    timeline: List[Dict[str, str]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    mitre_mappings: List[Dict[str, Any]] = field(default_factory=list)
    geo_targets: List[Dict[str, Any]] = field(default_factory=list)
    sector_targets: List[str] = field(default_factory=list)

    # Specific Domain Payloads
    actors: List[Dict[str, Any]] = field(default_factory=list)
    campaigns: List[Dict[str, Any]] = field(default_factory=list)
    malware: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    hunt_queries: List[Dict[str, Any]] = field(default_factory=list)

    # Base64 Rendered Chart Embeds (PNG / SVG)
    chart_images: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_type": self.report_type.upper(),
            "title": self.title,
            "tlp": self.tlp.upper(),
            "classification": self.classification,
            "author": self.author,
            "date_generated": self.date_generated,
            "executive_summary": self.executive_summary,
            "strategic_impact": self.strategic_impact,
            "recommendations": self.recommendations,
            "timeline": self.timeline,
            "metrics": self.metrics,
            "mitre_mappings": self.mitre_mappings,
            "geo_targets": self.geo_targets,
            "sector_targets": self.sector_targets,
            "actors": self.actors,
            "campaigns": self.campaigns,
            "malware": self.malware,
            "vulnerabilities": self.vulnerabilities,
            "iocs": self.iocs,
            "hunt_queries": self.hunt_queries,
            "chart_images": self.chart_images,
        }
