# ============================================================
# cve_parser.py — CVE API Response Parser
# API ka raw JSON response clean aur readable banata hai
# ============================================================


class CveParser:
    """
    NIST NVD API ka raw response le kar
    clean aur simple format mein convert karta hai.
    """

    def parse(self, raw_data: dict) -> list:
        """
        API response ko parse karta hai.

        Parameters:
            raw_data: API se aya hua raw JSON

        Returns:
            Clean CVE entries ki list
        """
        results = []

        # API response mein vulnerabilities key hoti hai
        vulnerabilities = raw_data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve_data = item.get("cve", {})

            # CVE ID
            cve_id = cve_data.get("id", "Unknown")

            # Description (English wali lo)
            description = self._get_description(cve_data)

            # Severity aur Score
            severity, score = self._get_severity(cve_data)

            results.append({
                "id":          cve_id,
                "description": description,
                "severity":    severity,
                "score":       score
            })

        return results

    def _get_description(self, cve_data: dict) -> str:
        """CVE ki English description extract karta hai"""
        try:
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    # Description ko 150 characters tak limit karo
                    text = desc.get("value", "No description available")
                    return text[:150] + "..." if len(text) > 150 else text
        except Exception:
            pass
        return "No description available"

    def _get_severity(self, cve_data: dict) -> tuple:
        """CVE ka severity level aur score extract karta hai"""
        try:
            metrics = cve_data.get("metrics", {})

            # CVSS v3.1 try karo pehle
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                data = cvss_v31[0].get("cvssData", {})
                return (
                    data.get("baseSeverity", "UNKNOWN"),
                    data.get("baseScore", 0.0)
                )

            # CVSS v3.0 try karo
            cvss_v30 = metrics.get("cvssMetricV30", [])
            if cvss_v30:
                data = cvss_v30[0].get("cvssData", {})
                return (
                    data.get("baseSeverity", "UNKNOWN"),
                    data.get("baseScore", 0.0)
                )

            # CVSS v2 try karo
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                data = cvss_v2[0].get("cvssData", {})
                return (
                    cvss_v2[0].get("baseSeverity", "UNKNOWN"),
                    data.get("baseScore", 0.0)
                )

        except Exception:
            pass

        return ("UNKNOWN", 0.0)