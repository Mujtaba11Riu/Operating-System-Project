# ============================================================
# risk_calculator.py — Risk Level Calculator
# DREAD score ke basis pe Low/Medium/High/Critical decide karta hai
# ============================================================


class RiskCalculator:
    """
    DREAD score le kar risk level calculate karta hai.
    Score 1-10 hota hai har factor ka.
    """

    # Risk levels aur unke score ranges
    RISK_LEVELS = {
        "CRITICAL": (8.0, 10.0),
        "HIGH":     (6.0, 7.9),
        "MEDIUM":   (4.0, 5.9),
        "LOW":      (0.0, 3.9),
    }

    # Har risk level ka color (GUI mein use hoga)
    RISK_COLORS = {
        "CRITICAL": "#FF0000",  # Red
        "HIGH":     "#FF6600",  # Orange
        "MEDIUM":   "#FFB300",  # Yellow
        "LOW":      "#00AA00",  # Green
    }

    def calculate(self, scores: dict) -> dict:
        """
        5 DREAD factors ka average nikaal ke risk level decide karta hai.

        Parameters:
            scores: {
                "Damage":          8,
                "Reproducibility": 7,
                "Exploitability":  9,
                "Affected_Users":  6,
                "Discoverability": 7
            }

        Returns:
            {
                "average": 7.4,
                "level":   "HIGH",
                "color":   "#FF6600"
            }
        """
        if not scores:
            return {"average": 0, "level": "LOW", "color": self.RISK_COLORS["LOW"]}

        # Average nikalo
        total = sum(scores.values())
        average = round(total / len(scores), 1)

        # Risk level decide karo
        level = self._get_risk_level(average)

        return {
            "average": average,
            "level":   level,
            "color":   self.RISK_COLORS[level]
        }

    def _get_risk_level(self, average: float) -> str:
        """Average score dekh ke risk level return karta hai"""
        for level, (min_score, max_score) in self.RISK_LEVELS.items():
            if min_score <= average <= max_score:
                return level
        return "LOW"