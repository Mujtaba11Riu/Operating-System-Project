# ============================================================
# dread_scorer.py — DREAD Threat Scorer
# Har identified threat ko 5 factors pe score karta hai
# ============================================================

from modules.dread.risk_calculator import RiskCalculator


class DreadScorer:
    """
    STRIDE se aye hue threats ko DREAD model se score karta hai.
    Har threat ko 5 factors pe 1-10 score milta hai.
    """

    # Har STRIDE threat type ke liye predefined DREAD scores
    DREAD_SCORES = {
        "Spoofing": {
            "Damage":          8,
            "Reproducibility": 7,
            "Exploitability":  8,
            "Affected_Users":  7,
            "Discoverability": 6,
        },
        "Tampering": {
            "Damage":          9,
            "Reproducibility": 6,
            "Exploitability":  7,
            "Affected_Users":  8,
            "Discoverability": 5,
        },
        "Repudiation": {
            "Damage":          6,
            "Reproducibility": 8,
            "Exploitability":  6,
            "Affected_Users":  5,
            "Discoverability": 7,
        },
        "Information Disclosure": {
            "Damage":          9,
            "Reproducibility": 9,
            "Exploitability":  8,
            "Affected_Users":  9,
            "Discoverability": 8,
        },
        "Denial of Service": {
            "Damage":          8,
            "Reproducibility": 9,
            "Exploitability":  7,
            "Affected_Users":  10,
            "Discoverability": 6,
        },
        "Elevation of Privilege": {
            "Damage":          10,
            "Reproducibility": 6,
            "Exploitability":  7,
            "Affected_Users":  8,
            "Discoverability": 5,
        },
    }

    def __init__(self):
        self.calculator = RiskCalculator()
        self.scored_threats = {}

    def score_threats(self, identified_threats: dict) -> dict:
        """
        STRIDE se aye hue threats ko score karta hai.

        Parameters:
            identified_threats: STRIDE analyzer ka output

        Returns:
            Har threat ka score aur risk level
        """
        self.scored_threats = {}

        for threat_type, threat_list in identified_threats.items():

            # Is threat type ka DREAD score lo
            scores = self.DREAD_SCORES.get(threat_type, {
                "Damage":          5,
                "Reproducibility": 5,
                "Exploitability":  5,
                "Affected_Users":  5,
                "Discoverability": 5,
            })

            # Risk calculate karo
            risk = self.calculator.calculate(scores)

            # Result store karo
            self.scored_threats[threat_type] = {
                "threats":  threat_list,
                "scores":   scores,
                "average":  risk["average"],
                "level":    risk["level"],
                "color":    risk["color"],
            }

        return self.scored_threats

    def get_highest_risk(self) -> dict:
        """Sabse zyada dangerous threat return karta hai"""
        if not self.scored_threats:
            return {}

        return max(
            self.scored_threats.items(),
            key=lambda x: x[1]["average"]
        )

    def get_overall_risk(self) -> dict:
        """Poore system ka overall risk level calculate karta hai"""
        if not self.scored_threats:
            return {"average": 0, "level": "LOW"}

        all_averages = [v["average"] for v in self.scored_threats.values()]
        overall_avg = round(sum(all_averages) / len(all_averages), 1)

        calculator = RiskCalculator()
        level = calculator._get_risk_level(overall_avg)

        return {
            "average": overall_avg,
            "level":   level,
            "color":   RiskCalculator.RISK_COLORS[level]
        }