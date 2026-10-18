"""
ThreatFusion CTI - Standalone HTML Report Generator
"""

import html
from typing import Dict, Any
from jinja2 import Template
from core.report_generator.report_models import ReportData

HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{{ report.title }} - ThreatFusion CTI</title>
<style>
    @page { size: A4; margin: 15mm 15mm 15mm 15mm; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #0E1117;
        color: #C9D1D9;
        margin: 0;
        padding: 30px;
        line-height: 1.5;
    }
    .header-banner {
        border-bottom: 2px solid #30363D;
        padding-bottom: 15px;
        margin-bottom: 25px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
    }
    .tlp-badge {
        display: inline-block;
        padding: 4px 10px;
        font-weight: 700;
        font-size: 11px;
        border-radius: 4px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .tlp-AMBER { background-color: #D29922; color: #000; }
    .tlp-RED { background-color: #F85149; color: #fff; }
    .tlp-GREEN { background-color: #3FB950; color: #000; }
    .tlp-WHITE { background-color: #F0F6FC; color: #000; }

    h1 { color: #58A6FF; margin: 5px 0 0 0; font-size: 24px; }
    h2 { color: #58A6FF; font-size: 16px; border-bottom: 1px solid #30363D; padding-bottom: 6px; margin-top: 30px; }
    h3 { color: #E6EDF3; font-size: 14px; margin-top: 15px; }

    .meta-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 10px;
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 25px;
        font-size: 12px;
    }
    .meta-item strong { display: block; color: #8B949E; margin-bottom: 3px; }

    .summary-box {
        background-color: #161B22;
        border-left: 4px solid #58A6FF;
        padding: 15px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 20px;
        font-size: 13px;
    }
    .table-container { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
    .table-container th {
        background-color: #21262D;
        color: #8B949E;
        text-align: left;
        padding: 8px 10px;
        border: 1px solid #30363D;
        font-weight: 600;
    }
    .table-container td {
        padding: 8px 10px;
        border: 1px solid #30363D;
        background-color: #161B22;
    }
    .code-block {
        font-family: "JetBrains Mono", Consolas, monospace;
        background-color: #0D1117;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 10px;
        color: #79C0FF;
        font-size: 11px;
        white-space: pre-wrap;
        word-break: break-all;
    }
    .chart-container { text-align: center; margin: 20px 0; }
    .chart-container img { max-width: 100%; border-radius: 6px; border: 1px solid #30363D; }

    /* Timeline component */
    .timeline { position: relative; margin: 20px 0; padding-left: 20px; border-left: 2px solid #30363D; }
    .timeline-item { margin-bottom: 15px; position: relative; }
    .timeline-item::before {
        content: "";
        position: absolute;
        left: -25px;
        top: 4px;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #58A6FF;
    }
    .timeline-date { font-size: 11px; color: #8B949E; font-weight: 600; }
    .timeline-content { font-size: 12px; margin-top: 2px; }

    .rec-item {
        background: #161B22;
        border: 1px solid #30363D;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 10px;
    }
    .rec-priority-HIGH { border-left: 4px solid #F85149; }
    .rec-priority-MEDIUM { border-left: 4px solid #D29922; }
    .rec-priority-LOW { border-left: 4px solid #3FB950; }
</style>
</head>
<body>

<div class="header-banner">
    <div>
        <div style="font-size: 11px; color: #8B949E; text-transform: uppercase; letter-spacing: 0.05em;">
            ThreatFusion Cyber Threat Intelligence Platform
        </div>
        <h1>{{ report.title }}</h1>
    </div>
    <div>
        <span class="tlp-badge tlp-{{ report.tlp }}">TLP:{{ report.tlp }}</span>
    </div>
</div>

<div class="meta-grid">
    <div class="meta-item">
        <strong>REPORT TYPE</strong>
        {{ report.report_type }}
    </div>
    <div class="meta-item">
        <strong>GENERATED ON</strong>
        {{ report.date_generated }}
    </div>
    <div class="meta-item">
        <strong>AUTHOR</strong>
        {{ report.author }}
    </div>
    <div class="meta-item">
        <strong>CLASSIFICATION</strong>
        {{ report.classification }}
    </div>
</div>

<h2>1. Executive Summary</h2>
<div class="summary-box">
    {{ report.executive_summary }}
</div>

{% if report.strategic_impact %}
<h2>2. Strategic Threat Impact</h2>
<p style="font-size: 13px;">{{ report.strategic_impact }}</p>
{% endif %}

{% if report.chart_images %}
<h2>3. Visual Intelligence Telemetry</h2>
{% for chart_name, img_data in report.chart_images.items() %}
    {% if img_data %}
    <div class="chart-container">
        <img src="{{ img_data }}" alt="{{ chart_name }}">
    </div>
    {% endif %}
{% endfor %}
{% endif %}

{% if report.timeline %}
<h2>4. Chronological Threat Timeline</h2>
<div class="timeline">
    {% for item in report.timeline %}
    <div class="timeline-item">
        <div class="timeline-date">{{ item.date }}</div>
        <div class="timeline-content"><strong>{{ item.event }}</strong>: {{ item.description }}</div>
    </div>
    {% endfor %}
</div>
{% endif %}

{% if report.mitre_mappings %}
<h2>5. MITRE ATT&CK Matrix Alignment</h2>
<table class="table-container">
    <thead>
        <tr>
            <th>Technique ID</th>
            <th>Technique Name</th>
            <th>Tactic</th>
            <th>Confidence</th>
            <th>Operational Evidence</th>
        </tr>
    </thead>
    <tbody>
        {% for m in report.mitre_mappings %}
        <tr>
            <td style="color: #58A6FF; font-weight: bold;">{{ m.technique_id }}</td>
            <td>{{ m.technique_name }}</td>
            <td>{{ m.tactic }}</td>
            <td>{{ m.confidence }}%</td>
            <td>{{ m.evidence }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endif %}

{% if report.iocs %}
<h2>6. Indicators of Compromise (IOCs)</h2>
<table class="table-container">
    <thead>
        <tr>
            <th>Type</th>
            <th>Indicator (Defanged)</th>
            <th>C2 Flag</th>
            <th>Decay Score</th>
            <th>Malware Association</th>
        </tr>
    </thead>
    <tbody>
        {% for ioc in report.iocs %}
        <tr>
            <td><code>{{ ioc.ioc_type }}</code></td>
            <td style="font-family: monospace;">{{ ioc.ioc_value }}</td>
            <td>{{ "YES" if ioc.c2_flag else "NO" }}</td>
            <td>{{ ioc.decay_score }}</td>
            <td>{{ ioc.malware | join(", ") if ioc.malware is iterable and ioc.malware is not string else ioc.malwar
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endif %}

{% if report.vulnerabilities %}
<h2>7. Exploited Vulnerabilities (CVE / KEV)</h2>
<table class="table-container">
    <thead>
        <tr>
            <th>CVE ID</th>
            <th>CVSS v3</th>
            <th>Known Exploited (CISA)</th>
            <th>Ransomware Use</th>
            <th>Affected Vendors</th>
        </tr>
    </thead>
    <tbody>
        {% for v in report.vulnerabilities %}
        <tr>
            <td style="color: #F85149; font-weight: bold;">{{ v.cve_id }}</td>
            <td>{{ v.cvss_score or 'N/A' }}</td>
            <td>{{ "YES" if v.is_known_exploited else "NO" }}</td>
            <td>{{ "YES" if v.ransomware_use else "NO" }}</td>
            <td>{{ v.affected_vendors | join(", ") if v.affected_vendors is iterable and v.affected_vendors is not s
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endif %}

{% if report.hunt_queries %}
<h2>8. Operational Threat Hunting Signatures</h2>
{% for h in report.hunt_queries %}
<div style="margin-bottom: 20px;">
    <div style="font-weight: 600; font-size: 13px; color: #58A6FF;">[{{ h.language }}] {{ h.title }}</div>
    <div style="font-size: 11px; color: #8B949E; margin-bottom: 5px;">{{ h.description }}</div>
    <div class="code-block">{{ h.query_content }}</div>
</div>
{% endfor %}
{% endif %}

{% if report.recommendations %}
<h2>9. Strategic Mitigations & Recommendations</h2>
{% for rec in report.recommendations %}
<div class="rec-item rec-priority-{{ rec.priority }}">
    <div style="font-size: 11px; font-weight: 700; color: #8B949E; text-transform: uppercase;">
        Priority: {{ rec.priority }} | Category: {{ rec.category }}
    </div>
    <div style="font-size: 13px; font-weight: 600; margin-top: 2px;">{{ rec.title }}</div>
    <div style="font-size: 12px; margin-top: 4px;">{{ rec.details }}</div>
</div>
{% endfor %}
{% endif %}

<div style="margin-top: 40px; border-top: 1px solid #30363D; padding-top: 15px; font-size: 11px; color: #8B949E; tex
    End of Report // Compiled Automatically via ThreatFusion CTI Reporting Engine
</div>

</body>
</html>
"""


class HTMLReportGenerator:
    @staticmethod
    def render(report: ReportData) -> str:
        """Renders self-contained HTML document string."""
        template = Template(HTML_REPORT_TEMPLATE)
        return template.render(report=report.to_dict())
