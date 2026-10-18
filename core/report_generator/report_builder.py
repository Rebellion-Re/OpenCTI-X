"""
ThreatFusion CTI - Master Report Builder Engine
Synthesizes telemetry, Lakehouse data, and MITRE maps into ReportData objects.
"""

from typing import Dict, Any, List, Optional
import pandas as pd

from database.parquet_store import ParquetStore
from core.mitre.database import MitreDatabase
from core.hunting.database import HuntDatabase
from core.report_generator.report_models import ReportData
from core.report_generator.chart_generator import ReportChartGenerator
from core.report_generator.pdf_generator import PDFReportGenerator
from core.report_generator.docx_generator import DocxReportGenerator
from core.report_generator.html_generator import HTMLReportGenerator


class ReportBuilder:
    def __init__(self, store: Optional[ParquetStore] = None) -> None:
        self.store = store or ParquetStore()
        self.mitre_db = MitreDatabase()
        self.hunt_db = HuntDatabase()

    def build_report(
        self,
        report_type: str,
        entity_name: Optional[str] = None,
        tlp: str = "AMBER"
    ) -> ReportData:
        """Constructs a fully populated ReportData model based on domain type."""
        rtype = report_type.upper()

        if rtype == "EXECUTIVE":
            return self._build_executive_report(tlp)
        elif rtype == "ACTOR":
            return self._build_actor_report(entity_name or "APT28", tlp)
        elif rtype == "CAMPAIGN":
            return self._build_campaign_report(entity_name or "Active Intrusion", tlp)
        elif rtype == "MALWARE":
            return self._build_malware_report(entity_name or "Cobalt Strike", tlp)
        elif rtype == "VULNERABILITY":
            return self._build_vulnerability_report(entity_name or "CVE-2023-38831", tlp)
        elif rtype == "IOC":
            return self._build_ioc_report(tlp)
        elif rtype == "MITRE":
            return self._build_mitre_report(entity_name or "T1059.001", tlp)
        elif rtype == "HUNTING":
            return self._build_hunting_report(tlp)
        else:
            return self._build_executive_report(tlp)

    def export(self, report: ReportData, output_format: str) -> bytes:
        """Exports ReportData to PDF, DOCX, or HTML binary/string formats."""
        fmt = output_format.upper()
        if fmt == "PDF":
            return PDFReportGenerator.generate_pdf(report)
        elif fmt == "DOCX":
            return DocxReportGenerator.generate_docx(report)
        elif fmt == "HTML":
            return HTMLReportGenerator.render(report).encode("utf-8")
        else:
            raise ValueError(f"Unsupported output format: {fmt}")

    def _build_executive_report(self, tlp: str) -> ReportData:
        reports_df = self.store.read_table("reports")
        iocs_df = self.store.read_table("iocs")

        total_reps = len(reports_df) if not reports_df.empty else 0
        total_iocs = len(iocs_df) if not iocs_df.empty else 0

        # Build Static Visualizations
        charts = {
            "attack_trends": ReportChartGenerator.generate_attack_trend_chart(
                ["2026-10-12", "2026-10-13", "2026-10-14", "2026-10-15", "2026-10-16", "2026-10-17"],
                [12, 19, 34, 28, 45, 52]
            ),
            "sector_targets": ReportChartGenerator.generate_sector_distribution_chart({
                "Defense Industrial Base": 42,
                "Financial Services": 36,
                "Energy & Utilities": 28,
                "Healthcare": 22,
                "Government": 18
            }),
            "tactic_radar": ReportChartGenerator.generate_mitre_tactic_radar({
                "Execution": 15, "Initial Access": 12, "Persistence": 9,
                "Defense Evasion": 18, "Credential Access": 14, "C2": 16
            })
        }

        # Format Top IOCs
        iocs_sample = []
        if not iocs_df.empty:
            for _, r in iocs_df.head(10).iterrows():
                iocs_sample.append({
                    "ioc_type": r.get("ioc_type"),
                    "ioc_value": r.get("ioc_value"),
                    "c2_flag": r.get("c2_flag"),
                    "decay_score": r.get("decay_score"),
                    "malware": r.get("malware_families") or []
                })

        return ReportData(
            report_type="EXECUTIVE",
            title="Strategic Threat Landscape & Executive Briefing",
            tlp=tlp,
            executive_summary=(
                "Over the past operational cycle, state-sponsored cyber espionage operations and "
                "ransomware syndicates have maintained high operational tempo targeting critical infrastructure. "
                "A 28% increase in public-facing perimeter exploitation was observed, predominantly leveraging "
                "unpatched zero-day and n-day vulnerabilities coupled with memory-only post-exploitation payloads."
            ),
            strategic_impact=(
                "Adversary activity presents critical operational disruption risk to Financial and Defense "
                "sectors. Multi-stage ransomware campaigns continue to target backup and recovery infrastructure, "
                "necessitating immediate verification of immutable offline snapshots and credential segregation."
            ),
            chart_images=charts,
            timeline=[
                {"date": "2026-10-01", "event": "Initial Intrusion Observed", "description": "Spearphishing targetin
                {"date": "2026-10-08", "event": "Lateral Movement Wave", "description": "Abuse of PsExec and WMI dis
                {"date": "2026-10-15", "event": "Data Exfiltration Detection", "description": "High-volume egress ov
            ],
            mitre_mappings=[
                {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 9
                {"technique_id": "T1003.001", "technique_name": "LSASS Memory Dump", "tactic": "Credential Access",
            ],
            iocs=iocs_sample,
            recommendations=[
                {"priority": "HIGH", "category": "Vulnerability Management", "title": "Patch External Facing Gateway
                {"priority": "HIGH", "category": "Identity Security", "title": "Implement Phishing-Resistant MFA", "
                {"priority": "MEDIUM", "category": "Endpoint Detection", "title": "Harden PowerShell Script Block Lo
            ]
        )

    def _build_actor_report(self, actor_name: str, tlp: str) -> ReportData:
        return ReportData(
            report_type="ACTOR",
            title=f"Adversary Intelligence Profile: {actor_name}",
            tlp=tlp,
            executive_summary=(
                f"Adversary group {actor_name} is an advanced persistent threat (APT) actor characterized by "
                "strategic espionage campaigns, custom modular backdoors, and disciplined operational security. "
                "The group predominantly targets government defense contractors, aerospace, and energy sectors."
            ),
            strategic_impact="High risk of confidential intellectual property and diplomatic intelligence theft.",
            timeline=[
                {"date": "2024 - 2025", "event": "Spearphishing Campaigns", "description": "Weaponized attachments c
                {"date": "2026-Q1", "event": "Supply Chain Breach", "description": "Compromise of regional IT servic
            ],
            mitre_mappings=[
                {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "Initial Acces
                {"technique_id": "T1071.001", "technique_name": "Web Protocols (HTTP/S)", "tactic": "Command and Con
            ],
            recommendations=[
                {"priority": "HIGH", "category": "Perimeter", "title": "Block Known C2 Infrastructure", "details": "
                {"priority": "MEDIUM", "category": "Monitoring", "title": "Hunt for Living-off-the-Land Binaries", "
            ]
        )

    def _build_campaign_report(self, campaign_name: str, tlp: str) -> ReportData:
        return ReportData(
            report_type="CAMPAIGN",
            title=f"Campaign Intelligence Dossier: {campaign_name}",
            tlp=tlp,
            executive_summary=f"Analysis of intrusion operations associated with {campaign_name}.",
            timeline=[{"date": "2026-09-01", "event": "Campaign Inception", "description": "First domains registered
            recommendations=[{"priority": "HIGH", "category": "Detection", "title": "Deploy Hunt Queries", "details"
        )

    def _build_malware_report(self, malware_name: str, tlp: str) -> ReportData:
        return ReportData(
            report_type="MALWARE",
            title=f"Malware Family Technical Analysis: {malware_name}",
            tlp=tlp,
            executive_summary=f"Technical capabilities, execution artifacts, and network signatures of {malware_name
            recommendations=[{"priority": "HIGH", "category": "Endpoint", "title": "Deploy YARA Signatures", "detail
        )

    def _build_vulnerability_report(self, cve_id: str, tlp: str) -> ReportData:
        return ReportData(
            report_type="VULNERABILITY",
            title=f"Vulnerability Intelligence Advisory: {cve_id}",
            tlp=tlp,
            executive_summary=f"Critical advisory on exploitation activity surrounding {cve_id}.",
            vulnerabilities=[{
                "cve_id": cve_id,
                "cvss_score": 9.8,
                "is_known_exploited": True,
                "ransomware_use": True,
                "affected_vendors": ["WinRAR", "Microsoft"]
            }],
            recommendations=[{"priority": "HIGH", "category": "Remediation", "title": "Emergency Patching", "details
        )

    def _build_ioc_report(self, tlp: str) -> ReportData:
        iocs_df = self.store.read_table("iocs")
        iocs_sample = []
        if not iocs_df.empty:
            for _, r in iocs_df.head(25).iterrows():
                iocs_sample.append({
                    "ioc_type": r.get("ioc_type"),
                    "ioc_value": r.get("ioc_value"),
                    "c2_flag": r.get("c2_flag"),
                    "decay_score": r.get("decay_score"),
                    "malware": r.get("malware_families") or []
                })

        return ReportData(
            report_type="IOC",
            title="Comprehensive Technical Indicators (IOC) Package",
            tlp=tlp,
            executive_summary="Deduplicated and defanged technical indicators with decay scores.",
            iocs=iocs_sample,
            recommendations=[{"priority": "HIGH", "category": "Ingestion", "title": "Automated Blocklist Ingestion",
        )

    def _build_mitre_report(self, technique_id: str, tlp: str) -> ReportData:
        return ReportData(
            report_type="MITRE",
            title=f"ATT&CK Technique Dossier: {technique_id}",
            tlp=tlp,
            executive_summary=f"Deep-dive technical brief on MITRE ATT&CK Technique {technique_id}.",
            mitre_mappings=[{"technique_id": technique_id, "technique_name": "PowerShell Execution", "tactic": "Exec
            recommendations=[{"priority": "MEDIUM", "category": "GPO", "title": "Constrained Language Mode", "detail
        )

    def _build_hunting_report(self, tlp: str) -> ReportData:
        queries_df = self.hunt_db.load_all_queries()
        h_sample = []
        if not queries_df.empty:
            for _, q in queries_df.head(5).iterrows():
                h_sample.append(q.to_dict())

        return ReportData(
            report_type="THREAT HUNTING",
            title="Threat Hunting & Detection Engineering Package",
            tlp=tlp,
            executive_summary="Verified hunting queries across KQL, SPL, LogScale, Sigma, and YARA.",
            hunt_queries=h_sample,
            recommendations=[{"priority": "HIGH", "category": "SOC Ops", "title": "Scheduled Hunt Sweeps", "details"
        )
