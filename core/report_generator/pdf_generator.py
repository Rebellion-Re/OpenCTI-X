"""
ThreatFusion CTI - Headless PDF Report Engine
Utilizes WeasyPrint to transform formatted HTML into A4 intelligence PDFs.
"""

import io
from typing import Optional
from core.report_generator.report_models import ReportData
from core.report_generator.html_generator import HTMLReportGenerator
from config.logging_config import setup_logger

logger = setup_logger("PdfReportGenerator")

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False


class PDFReportGenerator:
    @classmethod
    def generate_pdf(cls, report: ReportData) -> bytes:
        """Compiles ReportData into binary PDF stream."""
        html_content = HTMLReportGenerator.render(report)

        if not WEASYPRINT_AVAILABLE:
            logger.warning("WeasyPrint / Pango libraries not found. Falling back to plain text PDF stub.")
            return cls._generate_fallback_pdf(report, html_content)

        pdf_css = CSS(string="""
            @page {
                size: A4;
                margin: 20mm 15mm 20mm 15mm;
                @top-left {
                    content: "THREATFUSION INTELLIGENCE DIRECTIVE";
                    font-size: 8pt;
                    color: #8B949E;
                    font-family: sans-serif;
                }
                @top-right {
                    content: "TLP:""" + report.tlp + """";
                    font-size: 8pt;
                    font-weight: bold;
                    color: #D29922;
                    font-family: sans-serif;
                }
                @bottom-right {
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 8pt;
                    color: #8B949E;
                    font-family: sans-serif;
                }
                @bottom-left {
                    content: "CONFIDENTIAL // LAW ENFORCEMENT & SOC USE ONLY";
                    font-size: 8pt;
                    color: #8B949E;
                    font-family: sans-serif;
                }
            }
        """)

        html_doc = HTML(string=html_content)
        buffer = io.BytesIO()
        html_doc.write_pdf(buffer, stylesheets=[pdf_css])
        return buffer.getvalue()

    @staticmethod
    def _generate_fallback_pdf(report: ReportData, html_src: str) -> bytes:
        """Lightweight emergency PDF generator if system cairo/pango libraries are absent."""
        # Simple PDF minimal payload encapsulation
        pdf_payload = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >>
4 0 obj << /Length 200 >> stream
BT
/F1 14 Tf
50 720 Td
({report.title} - TLP:{report.tlp}) Tj
/F1 10 Tf
0 -30 Td
(Report Type: {report.report_type}) Tj
0 -20 Td
(Date: {report.date_generated}) Tj
0 -20 Td
(Summary: {report.executive_summary[:80]}...) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000242 00000 n
0000000494 00000 n
trailer << /Size 6 /Root 1 0 R >>
startxref
565
%%EOF
"""
        return pdf_payload.encode("latin1")
