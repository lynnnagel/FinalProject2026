"""
Heuristic phishing detector – 5 rule-based checks.

Performs:
  1. Suspicious-keyword count (Hebrew + English)
  2. Suspicious sender-address patterns (homoglyph / typosquatting chars)
  3. Excessive URL count in body
  4. Artificial-urgency language
  5. Non-standard sender domain

Returns a risk score 0-100 and human-readable indicators.
"""
import re
from datetime import datetime

from config import (
    PHISHING_THRESHOLD,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD,
    MAX_KEYWORD_SCORE,
    KEYWORD_SCORE_PER_WORD,
    SUSPICIOUS_DOMAIN_SCORE,
    MULTIPLE_URLS_SCORE,
    URGENCY_SCORE,
    INVALID_DOMAIN_SCORE,
    URL_COUNT_THRESHOLD,
)


class PhishingDetector:
    """
    Rule-based phishing classifier.

    Phase 2 plan: integrate BERT predictions as an additional feature
    via an Ensemble (0.7 * BERT_score + 0.3 * heuristic_score).
    """

    # 18 bilingual suspicious keywords (Hebrew + English)
    SUSPICIOUS_KEYWORDS = [
        # Hebrew
        "דחוף", "אימות", "חשבון", "זכית", "פרס", "לחץ כאן",
        "סיסמה", "בנק", "כרטיס אשראי",
        # English
        "verify", "urgent", "account", "suspended", "prize", "click here",
        "password", "bank", "credit card",
    ]

    # Words that signal artificial urgency
    URGENCY_WORDS = [
        "דחוף", "urgent", "מיידי", "immediate", "תוקף", "expire",
    ]

    # Sender-domain extensions considered legitimate
    VALID_DOMAIN_SUFFIXES = [
        ".com", ".co.il", ".org", ".net", ".gov", ".edu", ".io", ".co",
    ]

    # Character sequences that appear in typosquatting / homoglyph attacks
    SUSPICIOUS_SENDER_PATTERNS = ["l0", "o0", "rn", "vv"]

    _URL_RE = re.compile(
        r"https?://(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%])+"
    )

    # ------------------------------------------------------------------ #
    def analyze_email(self, sender: str, subject: str, content: str) -> dict:
        """
        Run all five heuristic checks and return a scored result dict.

        Returns
        -------
        dict with keys: risk_score, is_phishing, risk_level,
                        indicators, recommendation, response_time
        """
        start = datetime.now()
        full_text = f"{sender} {subject} {content}".lower()
        risk_score = 0.0
        indicators: list[str] = []

        # -- Check 1: Suspicious keywords -----------------------------------
        keyword_hits = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw.lower() in full_text]
        if keyword_hits:
            score = min(len(keyword_hits) * KEYWORD_SCORE_PER_WORD, MAX_KEYWORD_SCORE)
            risk_score += score
            indicators.append(f"נמצאו {len(keyword_hits)} מילות מפתח חשודות")

        # -- Check 2: Suspicious sender patterns ----------------------------
        sender_lower = sender.lower()
        if any(pat in sender_lower for pat in self.SUSPICIOUS_SENDER_PATTERNS):
            risk_score += SUSPICIOUS_DOMAIN_SCORE
            indicators.append('כתובת דוא"ל חשודה')

        # -- Check 3: Excessive URL count in body ---------------------------
        urls = self._URL_RE.findall(content)
        if len(urls) > URL_COUNT_THRESHOLD:
            risk_score += MULTIPLE_URLS_SCORE
            indicators.append(f"נמצאו {len(urls)} קישורים")

        # -- Check 4: Artificial urgency ------------------------------------
        if any(word in full_text for word in self.URGENCY_WORDS):
            risk_score += URGENCY_SCORE
            indicators.append("דחיפות מלאכותית")

        # -- Check 5: Non-standard sender domain ----------------------------
        if "@" in sender and not any(
            sfx in sender.lower() for sfx in self.VALID_DOMAIN_SUFFIXES
        ):
            risk_score += INVALID_DOMAIN_SCORE
            indicators.append("דומיין לא תקני")

        # -- Finalise -------------------------------------------------------
        risk_score = min(risk_score, 100.0)
        is_phishing = risk_score >= PHISHING_THRESHOLD

        if risk_score >= HIGH_RISK_THRESHOLD:
            risk_level = "סכנה גבוהה"
            recommendation = "אל תלחץ על שום קישור. מחק את המייל מיד."
        elif risk_score >= MEDIUM_RISK_THRESHOLD:
            risk_level = "חשוד"
            recommendation = "היזהר. בדוק את המקור לפני כל פעולה."
        elif risk_score >= LOW_RISK_THRESHOLD:
            risk_level = "זהירות"
            recommendation = "המייל מכיל אלמנטים חשודים. היה ערני."
        else:
            risk_level = "בטוח"
            recommendation = "המייל נראה תקין."

        response_time = (datetime.now() - start).total_seconds()

        return {
            "risk_score": round(risk_score, 2),
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "indicators": indicators if indicators else ["לא נמצאו אינדיקטורים חשודים"],
            "recommendation": recommendation,
            "response_time": round(response_time, 4),
        }


# Singleton – imported by API layer
detector = PhishingDetector()
