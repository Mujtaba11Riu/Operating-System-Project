# ============================================================
# pdf_exporter.py — PDF Report Exporter
# ReportLab use karke professional PDF banata hai
# ============================================================

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)


class PdfExporter:
    """
    Report data le kar professional PDF file banata hai.
    ReportLab library use karta hai.
    """

    # Colors
    COLOR_CRITICAL = colors.HexColor("#FF0000")
    COLOR_HIGH     = colors.HexColor("#FF6600")
    COLOR_MEDIUM   = colors.HexColor("#FFB300")
    COLOR_LOW      = colors.HexColor("#00AA00")
    COLOR_BLACK    = colors.black
    COLOR_DARK     = colors.HexColor("#1a1a2e")
    COLOR_HEADER   = colors.HexColor("#16213e")

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Custom styles define karta hai"""

        self.title_style = ParagraphStyle(
            "CustomTitle",
            parent=self.styles["Title"],
            fontSize=20,
            textColor=self.COLOR_DARK,
            spaceAfter=10,
            fontName="Helvetica-Bold"
        )

        self.heading_style = ParagraphStyle(
            "CustomHeading",
            parent=self.styles["Heading1"],
            fontSize=13,
            textColor=self.COLOR_HEADER,
            spaceBefore=15,
            spaceAfter=8,
            fontName="Helvetica-Bold"
        )

        self.normal_style = ParagraphStyle(
            "CustomNormal",
            parent=self.styles["Normal"],
            fontSize=10,
            textColor=self.COLOR_BLACK,
            spaceAfter=5,
            fontName="Helvetica"
        )

        self.threat_style = ParagraphStyle(
            "ThreatStyle",
            parent=self.styles["Normal"],
            fontSize=10,
            textColor=self.COLOR_BLACK,
            leftIndent=20,
            spaceAfter=4,
            fontName="Helvetica"
        )

    def export(self, report_data: dict, output_path: str = None) -> str:
        """
        PDF file banata hai aur path return karta hai.

        Parameters:
            report_data : ReportGenerator ka output
            output_path : Kahan save karni hai (optional)

        Returns:
            PDF file ka path
        """

        # Output path set karo
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"outputs/reports/report_{timestamp}.pdf"

        # Outputs folder exist nahi toh banao
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # PDF document create karo
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        # Content build karo
        content = []
        content += self._build_header(report_data["meta"])
        content += self._build_system_info(report_data["system_info"])
        content += self._build_overall_risk(report_data["overall_risk"])
        content += self._build_stride_section(report_data["stride_results"])
        content += self._build_dread_section(report_data["dread_results"])
        content += self._build_cve_section(report_data["cve_results"])
        content += self._build_footer()

        # PDF build karo
        doc.build(content)

        return output_path

    def _build_header(self, meta: dict) -> list:
        """Report ka header banata hai"""
        items = []

        items.append(Paragraph(meta["title"], self.title_style))
        items.append(HRFlowable(width="100%", thickness=2, color=self.COLOR_DARK))
        items.append(Spacer(1, 0.3*cm))

        info = [
            ["Author:",     meta["author"]],
            ["SAP ID:",     meta["sap_id"]],
            ["University:", meta["university"]],
            ["Date:",       meta["date"]],
        ]

        table = Table(info, colWidths=[4*cm, 13*cm])
        table.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",  (0, 0), (-1, -1), 10),
            ("FONTNAME",  (0, 0), (0, -1),  "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (-1, -1), self.COLOR_BLACK),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        items.append(table)
        items.append(Spacer(1, 0.5*cm))
        return items

    def _build_system_info(self, system_info: dict) -> list:
        """System information section"""
        items = []

        items.append(Paragraph("System Information", self.heading_style))
        items.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        items.append(Spacer(1, 0.2*cm))

        data = [
            ["Services Analyzed:", ", ".join(system_info["services"])],
            ["Authentication:",    system_info["authentication"]],
            ["Encryption:",        system_info["encryption"]],
        ]

        table = Table(data, colWidths=[4*cm, 13*cm])
        table.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",  (0, 0), (-1, -1), 10),
            ("FONTNAME",  (0, 0), (0, -1),  "Helvetica-Bold"),
            ("BACKGROUND",(0, 0), (-1, -1), colors.HexColor("#f5f5f5")),
            ("GRID",      (0, 0), (-1, -1), 0.5, colors.grey),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ]))

        items.append(table)
        items.append(Spacer(1, 0.3*cm))
        return items

    def _build_overall_risk(self, overall_risk: dict) -> list:
        """Overall risk section"""
        items = []

        items.append(Paragraph("Overall Risk Assessment", self.heading_style))
        items.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        items.append(Spacer(1, 0.2*cm))

        level = overall_risk.get("level", "LOW")
        avg   = overall_risk.get("average", 0)

        risk_color = {
            "CRITICAL": self.COLOR_CRITICAL,
            "HIGH":     self.COLOR_HIGH,
            "MEDIUM":   self.COLOR_MEDIUM,
            "LOW":      self.COLOR_LOW,
        }.get(level, self.COLOR_LOW)

        data = [["Overall Risk Level", "Score", "Status"]]
        data.append([level, f"{avg}/10", "System requires immediate attention" if level in ["CRITICAL", "HIGH"] else "Monitor regularly"])

        table = Table(data, colWidths=[5*cm, 3*cm, 9*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  self.COLOR_HEADER),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("BACKGROUND",    (0, 1), (-1, -1), risk_color),
            ("TEXTCOLOR",     (0, 1), (-1, -1), colors.white),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica-Bold"),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.white),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ]))

        items.append(table)
        items.append(Spacer(1, 0.3*cm))
        return items

    def _build_stride_section(self, stride_results: dict) -> list:
        """STRIDE results section"""
        items = []

        items.append(Paragraph("STRIDE Threat Analysis", self.heading_style))
        items.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        items.append(Spacer(1, 0.2*cm))

        if not stride_results:
            items.append(Paragraph("No threats identified.", self.normal_style))
            return items

        for threat_type, threat_list in stride_results.items():
            items.append(Paragraph(f"• {threat_type}", ParagraphStyle(
                "ThreatHeader",
                parent=self.styles["Normal"],
                fontSize=11,
                fontName="Helvetica-Bold",
                textColor=self.COLOR_DARK,
                spaceBefore=8,
                spaceAfter=4,
            )))
            for threat in threat_list:
                items.append(Paragraph(
                    f"  [{threat['source']}] {threat['description']}",
                    self.threat_style
                ))

        items.append(Spacer(1, 0.3*cm))
        return items

    def _build_dread_section(self, dread_results: dict) -> list:
        """DREAD scores section"""
        items = []

        items.append(Paragraph("DREAD Risk Scoring", self.heading_style))
        items.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        items.append(Spacer(1, 0.2*cm))

        if not dread_results:
            items.append(Paragraph("No scores available.", self.normal_style))
            return items

        # Table header
        data = [["Threat Type", "D", "R", "E", "A", "D", "Avg", "Level"]]

        for threat_type, info in dread_results.items():
            s = info["scores"]
            data.append([
                threat_type,
                str(s.get("Damage", 0)),
                str(s.get("Reproducibility", 0)),
                str(s.get("Exploitability", 0)),
                str(s.get("Affected_Users", 0)),
                str(s.get("Discoverability", 0)),
                str(info["average"]),
                info["level"],
            ])

        col_widths = [5*cm, 1.2*cm, 1.2*cm, 1.2*cm, 1.2*cm, 1.2*cm, 1.5*cm, 2.5*cm]
        table = Table(data, colWidths=col_widths)

        style = [
            ("BACKGROUND",    (0, 0), (-1, 0),  self.COLOR_HEADER),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.grey),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]

        # Har row ka color risk level ke hisaab se
        for i, (threat_type, info) in enumerate(dread_results.items(), start=1):
            risk_color = {
                "CRITICAL": self.COLOR_CRITICAL,
                "HIGH":     self.COLOR_HIGH,
                "MEDIUM":   self.COLOR_MEDIUM,
                "LOW":      self.COLOR_LOW,
            }.get(info["level"], self.COLOR_LOW)

            style.append(("BACKGROUND", (7, i), (7, i), risk_color))
            style.append(("TEXTCOLOR",  (7, i), (7, i), colors.white))
            style.append(("FONTNAME",   (7, i), (7, i), "Helvetica-Bold"))

        table.setStyle(TableStyle(style))
        items.append(table)
        items.append(Spacer(1, 0.3*cm))
        return items

    def _build_cve_section(self, cve_results: dict) -> list:
        """CVE results section"""
        items = []

        items.append(Paragraph("CVE Vulnerability Lookup", self.heading_style))
        items.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        items.append(Spacer(1, 0.2*cm))

        if not cve_results:
            items.append(Paragraph("No CVE data available.", self.normal_style))
            return items

        for service, cves in cve_results.items():
            items.append(Paragraph(f"• {service}", ParagraphStyle(
                "CVEHeader",
                parent=self.styles["Normal"],
                fontSize=11,
                fontName="Helvetica-Bold",
                textColor=self.COLOR_DARK,
                spaceBefore=8,
                spaceAfter=4,
            )))
            for cve in cves:
                items.append(Paragraph(
                    f"  [{cve['id']}] Severity: {cve['severity']} | Score: {cve['score']}",
                    self.threat_style
                ))
                items.append(Paragraph(
                    f"  {cve['description']}",
                    self.threat_style
                ))

        items.append(Spacer(1, 0.3*cm))
        return items

    def _build_footer(self) -> list:
        """Report ka footer"""
        items = []
        items.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        items.append(Spacer(1, 0.2*cm))
        items.append(Paragraph(
            "Generated by Security Threat Analyzer | Riphah International University Islamabad",
            ParagraphStyle(
                "Footer",
                parent=self.styles["Normal"],
                fontSize=8,
                textColor=colors.grey,
                alignment=1
            )
        ))
        return items