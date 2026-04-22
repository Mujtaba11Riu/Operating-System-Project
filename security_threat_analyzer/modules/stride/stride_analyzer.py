# ============================================================
# stride_analyzer.py — STRIDE Threat Analyzer
# User input le kar threats identify karta hai
# ============================================================

from modules.stride.threat_rules import (
    THREAT_RULES,
    NO_AUTH_THREATS,
    NO_ENCRYPTION_THREATS
)


class StrideAnalyzer:
    """
    STRIDE model implement karta hai.
    User ki input le kar relevant threats identify karta hai.
    """

    def __init__(self):
        # Yahan identified threats store honge
        self.identified_threats = {}

    def analyze(self, services: list, has_auth: bool, has_encryption: bool) -> dict:
        """
        Main analysis function.

        Parameters:
            services      : User ne jo services select ki hain (e.g. ['FTP', 'HTTP'])
            has_auth      : Authentication hai ya nahi (True/False)
            has_encryption: Encryption hai ya nahi (True/False)

        Returns:
            Dictionary of identified threats
        """
        self.identified_threats = {}

        # Step 1: Har service ke liye rules check karo
        for service in services:
            if service in THREAT_RULES:
                for threat_type, description in THREAT_RULES[service].items():
                    self._add_threat(threat_type, service, description)

        # Step 2: Agar authentication nahi hai
        if not has_auth:
            for threat_type, description in NO_AUTH_THREATS.items():
                self._add_threat(threat_type, "No Authentication", description)

        # Step 3: Agar encryption nahi hai
        if not has_encryption:
            for threat_type, description in NO_ENCRYPTION_THREATS.items():
                self._add_threat(threat_type, "No Encryption", description)

        return self.identified_threats

    def _add_threat(self, threat_type: str, source: str, description: str):
        """
        Threat ko dictionary mein add karta hai.
        Agar threat type pehle se hai toh us mein add karta hai.
        """
        if threat_type not in self.identified_threats:
            self.identified_threats[threat_type] = []

        self.identified_threats[threat_type].append({
            "source":      source,
            "description": description
        })

    def get_threat_count(self) -> int:
        """Total kitne threats mile hain"""
        return sum(len(v) for v in self.identified_threats.values())

    def get_threat_types(self) -> list:
        """Sirf threat types ki list return karta hai"""
        return list(self.identified_threats.keys())