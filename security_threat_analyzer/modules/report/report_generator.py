# ============================================================
# report_generator.py — Report Data Collector
# Saare modules ka data ek jagah collect karta hai
# ============================================================

from datetime import datetime


class ReportGenerator:
    """
    STRIDE, DREAD aur CVE modules ka data
    ek jagah collect karke report ready karta hai.
    """

    def __init__(self):
        self.report_data = {}

    def generate(
        self,
        services: list,
        has_auth: bool,
        has_encryption: bool,
        stride_results: dict,
        dread_results: dict,
        cve_results: dict,
        overall_risk: dict
    ) -> dict:
        """
        Saara data ek dictionary mein collect karta hai.

        Returns:
            Complete report data dictionary
        """

        self.report_data = {
            # Report ki basic info
            "meta": {
                "title":      "Security Threat Analysis Report",
                "author":     "Syed Mujtaba Zaidi",
                "sap_id":     "62081",
                "university": "Riphah International University Islamabad",
                "date":       datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            },

            # User ne jo input diya
            "system_info": {
                "services":       services,
                "authentication": "Yes" if has_auth else "No",
                "encryption":     "Yes" if has_encryption else "No",
            },

            # Overall risk
            "overall_risk": overall_risk,

            # STRIDE results
            "stride_results": stride_results,

            # DREAD results
            "dread_results": dread_results,

            # CVE results
            "cve_results": cve_results,
        }

        return self.report_data

    def get_summary(self) -> dict:
        """Report ki summary return karta hai"""
        if not self.report_data:
            return {}

        total_threats = sum(
            len(v["threats"])
            for v in self.report_data["dread_results"].values()
        )

        critical_count = sum(
            1 for v in self.report_data["dread_results"].values()
            if v["level"] == "CRITICAL"
        )

        high_count = sum(
            1 for v in self.report_data["dread_results"].values()
            if v["level"] == "HIGH"
        )

        return {
            "total_threats":  total_threats,
            "critical_count": critical_count,
            "high_count":     high_count,
            "overall_level":  self.report_data["overall_risk"]["level"],
            "overall_avg":    self.report_data["overall_risk"]["average"],
        }
    