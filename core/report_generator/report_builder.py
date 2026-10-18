"""
ThreatFusion CTI - Executive & Technical Threat Intelligence Report Generator
Builds multi-format reports (HTML, PDF, Markdown) with dynamic styling.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from config.settings import REPORTS_DIR
from config.logging_config import setup_logger

logger = setup_logger("ReportBuilder")

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False


class ReportBuilder:
    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = output_dir or REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_sample_report_data(self) -> Dict[str, Any]:
        """Provides default structured data for report generation and testing."""
        return {
            "title": "Threat Advisory: Advanced Cyber Threat Activity",
            "report_id": f"TF-ADV-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "tlp": "AMBER",
            "confidence": "High",
            "threat_actors": ["APT28", "Fancy Bear"],
            "malware_families": ["Cobalt Strike", "Mimikatz"],
            "targeted_sectors": ["Financial Services", "Defense Industrial Base", "Critical Infrastructure"],
            "targeted_countries": ["US", "UA", "GB", "DE"],
            "summary": (
                "Recent threat telemetry indicates elevated operational tempo by state-sponsored actors "
                "utilizing multi-stage PowerShell execution chains, credential dumping via LSASS injection, "
                "and persistent scheduled tasks across targeted enterprise environments."
            ),
            "timeline": [
                {"date": "2026-10-01", "event": "Initial Intrusion Observed via spearphishing attachment."},
                {"date": "2026-10-03", "event": "Execution of obfuscated PowerShell scripts and credential access."},
                {"date": "2026-10-05", "event": "Lateral movement detected via SMB and scheduled tasks creation."},
                {"date": "2026-10-10", "event": "Command and control communication established to external infrastructure."}
            ],
            "mitre_ttps": [
                {"technique_id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
                {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
                {"technique_id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
                {"technique_id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
                {"technique_id": "T1071.001", "name": "Web Protocols (HTTP/S)", "tactic": "Command and Control"}
            ],
            "iocs": [
                {"type": "IPV4", "value": "185.220.101.5", "asn": "AS9009", "status": "Active C2"},
                {"type": "DOMAIN", "value": "malicious-telemetry.com", "asn": "AS13335", "status": "Active C2"},
                {"type": "SHA256", "value": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "asn": "N/A", "status": "Dropper Payload"}
            ],
            "recommendations": [
                "Implement strict endpoint isolation rules for unauthorized PowerShell script executions.",
                "Enforce Credential Guard and LSA Protection to thwart memory dumping tools.",
                "Block identified C2 IP addresses and domain infrastructure at network perimeters."
            ]
        }

    def render_html_report(self, data: Optional[Dict[str, Any]] = None) -> str:
        """Renders executive-grade dark-themed HTML report."""
        rep = data or self.generate_sample_report_data()

        tlp = rep.get("tlp", "AMBER").upper()
        tlp_color = "#FF8800" if tlp == "AMBER" else ("#FF4444" if tlp == "RED" else "#00FF66")

        timeline_rows = "".join([
            f"<tr><td style='padding: 8px; border-bottom: 1px solid #30363d; font-family: monospace;'>{item['date']}</td>"
            f"<td style='padding: 8px; border-bottom: 1px solid #30363d;'>{item['event']}</td></tr>"
            for item in rep.get("timeline", [])
        ])

        ttp_rows = "".join([
            f"<tr><td style='padding: 8px; border-bottom: 1px solid #30363d; font-family: monospace; color: #58a6ff;'>{item['technique_id']}</td>"
            f"<td style='padding: 8px; border-bottom: 1px solid #30363d;'>{item['name']}</td>"
            f"<td style='padding: 8px; border-bottom: 1px solid #30363d; color: #8b949e;'>{item['tactic']}</td></tr>"
            for item in rep.get("mitre_ttps", [])
        ])

        ioc_rows = "".join([
            f"<tr><td style='padding: 8px; border-bottom: 1px solid #30363d; font-weight: bold;'>{item['type']}</td>"
            f"<td style='padding: 8px; border-bottom: 1px solid #30363d; font-family: monospace;'>{item['value']}</td>"
            f"<td style='padding: 8px; border-bottom: 1px solid #30363d; color: #3fb950;'>{item['status']}</td></tr>"
            for item in rep.get("iocs", [])
        ])

        recs = "".join([f"<li style='margin-bottom: 6px;'>{r}</li>" for r in rep.get("recommendations", [])])

        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{rep.get('title')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 24px;
            font-size: 14px;
            line-height: 1.5;
        }}
        .header {{
            border-bottom: 2px solid #30363d;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            color: #ffffff;
            background-color: {tlp_color};
        }}
        h1 {{ color: #ffffff; margin-top: 10px; font-size: 24px; }}
        h2 {{ color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 6px; margin-top: 24px; font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th {{ text-align: left; background-color: #161b22; padding: 10px 8px; color: #8b949e; border-bottom: 1px solid #30363d; }}
        .card {{ background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <span class="badge">TLP:{tlp}</span>
        <span style="float: right; color: #8b949e;">{rep.get('created_at')} | {rep.get('report_id')}</span>
        <h1>{rep.get('title')}</h1>
    </div>

    <div class="card">
        <h2 style="margin-top: 0;">Executive Summary</h2>
        <p>{rep.get('summary')}</p>
        <p><strong>Threat Actors:</strong> {", ".join(rep.get('threat_actors', []))}</p>
        <p><strong>Identified Malware:</strong> {", ".join(rep.get('malware_families', []))}</p>
        <p><strong>Targeted Sectors:</strong> {", ".join(rep.get('targeted_sectors', []))}</p>
    </div>

    <h2>Incident & Activity Timeline</h2>
    <table>
        <thead><tr><th>Date</th><th>Observed Event Activity</th></tr></thead>
        <tbody>{timeline_rows}</tbody>
    </table>

    <h2>MITRE ATT&CK Mapping</h2>
    <table>
        <thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th></tr></thead>
        <tbody>{ttp_rows}</tbody>
    </table>

    <h2>Indicators of Compromise (IOCs)</h2>
    <table>
        <thead><tr><th>Type</th><th>Indicator Value</th><th>Context</th></tr></thead>
        <tbody>{ioc_rows}</tbody>
    </table>

    <h2>Mitigation & Defense Recommendations</h2>
    <ul>{recs}</ul>
</body>
</html>"""
        return html_template

    def generate_pdf_report(self, data: Optional[Dict[str, Any]] = None, output_filename: Optional[str] = None) -> Optional[Path]:
        """Generates a PDF report using WeasyPrint if available."""
        if not WEASYPRINT_AVAILABLE:
            logger.warning("WeasyPrint is not installed or available on this system.")
            return None

        rep_data = data or self.generate_sample_report_data()
        html_content = self.render_html_report(rep_data)
        out_name = output_filename or f"{rep_data.get('report_id', 'report')}.pdf"
        out_path = self.output_dir / out_name

        try:
            HTML(string=html_content).write_pdf(str(out_path))
            logger.info(f"Generated PDF report: {out_path}")
            return out_path
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return None
