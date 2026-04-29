"""
Heuristic phishing detector – 8 rule-based checks.
Enhanced from 5 checks to 8 with 50+ bilingual keywords.
"""
import re
from datetime import datetime

from config import (
    PHISHING_THRESHOLD, HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD, MAX_KEYWORD_SCORE, KEYWORD_SCORE_PER_WORD,
    SUSPICIOUS_DOMAIN_SCORE, MULTIPLE_URLS_SCORE, URGENCY_SCORE,
    INVALID_DOMAIN_SCORE, URL_COUNT_THRESHOLD,
)


class PhishingDetector:

    SUSPICIOUS_KEYWORDS = [
        # עברית – פיננסי
        "דחוף", "אימות", "חשבון", "זכית", "פרס", "לחץ כאן", "סיסמה",
        "בנק", "כרטיס אשראי", "אשראי", "העברה", "מזומן", "הגרלה",
        "זכייה", "מתנה", "חינם", "בחינם", "מבצע", "אישור", "אימות זהות",
        "פרטים אישיים", "תעודת זהות", "חסימה", "ביטול", "השעיה",
        "נחסם", "מוקפא", "רשות המסים", "ביטוח לאומי", "דואר ישראל",
        "בנק הפועלים", "בנק לאומי", "היום בלבד", "הצעה מוגבלת",
        "פג תוקף", "מסתיים", "עדכן פרטים", "אמת את חשבונך",
        # אנגלית
        "verify", "urgent", "account", "suspended", "prize", "click here",
        "password", "bank", "credit card", "confirm", "update your",
        "limited time", "act now", "immediately", "validate",
        "your account has been", "unusual activity", "security alert",
        "winner", "congratulations", "free", "gift", "claim",
        "social security", "irs", "tax refund", "invoice",
        "payment required", "login", "sign in", "reset password",
        "verify your identity", "account locked", "suspicious activity",
    ]

    URGENCY_WORDS = [
        "דחוף", "urgent", "מיידי", "immediate", "תוקף", "expire",
        "עכשיו", "now", "today", "היום", "שעות", "hours",
        "מסתיים", "expires", "deadline", "אחרון", "last chance",
        "limited", "מוגבל", "hurry", "מהר",
    ]

    VALID_DOMAIN_SUFFIXES = [
        ".com", ".co.il", ".org", ".net", ".gov", ".edu",
        ".io", ".co", ".gov.il", ".org.il", ".net.il", ".ac.il",
        ".info", ".biz",
    ]

    SUSPICIOUS_SENDER_PATTERNS = [
        "l0", "o0", "rn", "vv", "paypa1", "arnazon",
        "g00gle", "app1e", "faceb00k", "micros0ft", "netf1ix",
    ]

    FREE_EMAIL_PROVIDERS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "walla.co.il", "bezeqint.net", "mail.com", "protonmail.com",
    ]

    OFFICIAL_KEYWORDS = [
        "bank", "בנק", "paypal", "amazon", "irs", "gov", "tax",
        "מסים", "police", "משטרה", "ביטוח לאומי", "government",
        "ממשלה", "ministry", "משרד", "רשות",
    ]

    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "short.link",
        "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
    ]

    _URL_RE = re.compile(
        r"https?://(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%])+"
    )
    _IP_IN_URL = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    def analyze_email(self, sender: str, subject: str, content: str) -> dict:
        start = datetime.now()
        full_text = f"{sender} {subject} {content}".lower()
        risk_score = 0.0
        indicators: list[str] = []

        # בדיקה 1: מילות מפתח חשודות
        keyword_hits = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw.lower() in full_text]
        if keyword_hits:
            score = min(len(keyword_hits) * KEYWORD_SCORE_PER_WORD, MAX_KEYWORD_SCORE)
            risk_score += score
            indicators.append(f"נמצאו {len(keyword_hits)} מילות מפתח חשודות")

        # בדיקה 2: תבניות חשודות בשולח
        sender_lower = sender.lower()
        if any(pat in sender_lower for pat in self.SUSPICIOUS_SENDER_PATTERNS):
            risk_score += SUSPICIOUS_DOMAIN_SCORE
            indicators.append('כתובת דוא"ל חשודה – תווים מבלבלים')

        # בדיקה 3: ריבוי קישורים
        urls = self._URL_RE.findall(content)
        if len(urls) > URL_COUNT_THRESHOLD:
            risk_score += MULTIPLE_URLS_SCORE
            indicators.append(f"נמצאו {len(urls)} קישורים חשודים")

        # בדיקה 4: שפת דחיפות
        urgency_hits = [w for w in self.URGENCY_WORDS if w in full_text]
        if urgency_hits:
            risk_score += URGENCY_SCORE
            indicators.append("דחיפות מלאכותית – לחץ על המשתמש")

        # בדיקה 5: דומיין לא תקני
        if "@" in sender and not any(
            sfx in sender.lower() for sfx in self.VALID_DOMAIN_SUFFIXES
        ):
            risk_score += INVALID_DOMAIN_SCORE
            indicators.append("דומיין לא תקני")

        # בדיקה 6: כתובת IP ישירה בקישור
        if self._IP_IN_URL.search(content):
            risk_score += 25
            indicators.append("קישור עם כתובת IP ישירה – חשוד מאוד")

        # בדיקה 7: קיצור URL (מסתיר את היעד)
        if any(s in content.lower() for s in self.URL_SHORTENERS):
            risk_score += 15
            indicators.append("שימוש בקיצור URL – מסתיר יעד")

        # בדיקה 8: ארגון רשמי + מייל חינמי
        subject_lower = subject.lower()
        content_lower = content.lower()
        claims_official = any(
            kw in subject_lower or kw in content_lower
            for kw in self.OFFICIAL_KEYWORDS
        )
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
        uses_free = any(f in sender_domain for f in self.FREE_EMAIL_PROVIDERS)
        if claims_official and uses_free:
            risk_score += 30
            indicators.append("ארגון רשמי משתמש בכתובת מייל חינמית")

        # סיכום
        risk_score = min(risk_score, 100.0)
        is_phishing = risk_score >= PHISHING_THRESHOLD

        if risk_score >= HIGH_RISK_THRESHOLD:
            risk_level = "סכנה גבוהה"
            recommendation = "⛔ אל תלחץ על שום קישור! מחק את המייל מיד."
        elif risk_score >= MEDIUM_RISK_THRESHOLD:
            risk_level = "חשוד"
            recommendation = "⚠️ היזהר מאוד. בדוק את המקור לפני כל פעולה."
        elif risk_score >= LOW_RISK_THRESHOLD:
            risk_level = "זהירות"
            recommendation = "🔍 המייל מכיל אלמנטים חשודים. היה ערני."
        else:
            risk_level = "בטוח"
            recommendation = "✅ המייל נראה תקין."

        response_time = (datetime.now() - start).total_seconds()

        return {
            "risk_score": round(risk_score, 2),
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "indicators": indicators if indicators else ["לא נמצאו אינדיקטורים חשודים"],
            "recommendation": recommendation,
            "response_time": round(response_time, 4),
        }


detector = PhishingDetector()