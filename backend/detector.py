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
    INVALID_DOMAIN_SCORE, URL_COUNT_THRESHOLD, BRAND_IMPERSONATION_SCORE,
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

    # -----------------------------------------------------------------------
    # מותגים והדומיינים הרשמיים שלהם.
    #
    # זו הבדיקה החזקה ביותר בזיהוי פישינג: אם המייל מציג את עצמו כבנק
    # הפועלים אך נשלח מ-bankhapoalim-secure.net, זו התחזות ודאית.
    #
    # הבדיקה הקודמת על דומיינים (VALID_DOMAIN_SUFFIXES) בחנה רק את הסיומת,
    # ולכן bezeq-pay.net ו-netflix-il.info עברו בה בשלום — .net ו-.info הן
    # סיומות חוקיות לחלוטין. מדידה על 250 מיילי פישינג בעברית הראתה שהיא
    # לא נדלקה אף פעם.
    #
    # המפתח הוא צורת ההופעה של המותג בטקסט; הערך הוא הדומיינים שמהם
    # הארגון באמת שולח. יש לרשום כל וריאציה שסביר שתופיע במייל.
    # -----------------------------------------------------------------------
    BRAND_DOMAINS = {
        # בנקים וכרטיסי אשראי — ישראל
        "בנק הפועלים":      ["bankhapoalim.co.il", "poalim.co.il"],
        "הפועלים":          ["bankhapoalim.co.il", "poalim.co.il"],
        "בנק לאומי":        ["leumi.co.il", "bankleumi.co.il"],
        "לאומי":            ["leumi.co.il", "bankleumi.co.il"],
        "בנק דיסקונט":      ["discountbank.co.il"],
        "דיסקונט":          ["discountbank.co.il"],
        "מזרחי טפחות":      ["mizrahi-tefahot.co.il"],
        "בנק מזרחי":        ["mizrahi-tefahot.co.il"],
        "ישראכרט":          ["isracard.co.il"],
        "isracard":         ["isracard.co.il"],
        "כאל":              ["cal-online.co.il"],
        "cal":              ["cal-online.co.il"],
        # תקשורת
        "פרטנר":            ["partner.co.il"],
        "partner":          ["partner.co.il"],
        "סלקום":            ["cellcom.co.il"],
        "cellcom":          ["cellcom.co.il"],
        "בזק":              ["bezeq.co.il", "bezeqint.net"],
        "bezeq":            ["bezeq.co.il", "bezeqint.net"],
        "hot":              ["hot.net.il"],
        "גולן טלקום":       ["golantelecom.co.il"],
        # משלוחים
        "דואר ישראל":       ["israelpost.co.il"],
        "israel post":      ["israelpost.co.il"],
        "dhl":              ["dhl.com", "dhl.co.il"],
        "fedex":            ["fedex.com"],
        "ups":              ["ups.com"],
        # מסחר
        "ksp":              ["ksp.co.il"],
        "terminal x":       ["terminalx.com"],
        "איקאה":            ["ikea.co.il", "ikea.com"],
        "ikea":             ["ikea.co.il", "ikea.com"],
        "רמי לוי":          ["rami-levy.co.il"],
        "שופרסל":           ["shufersal.co.il"],
        "zap":              ["zap.co.il"],
        # ממשלה
        "רשות המסים":       ["gov.il", "taxes.gov.il"],
        "ביטוח לאומי":      ["btl.gov.il", "gov.il"],
        "משרד התחבורה":     ["gov.il"],
        "חברת החשמל":       ["iec.co.il"],
        # בינלאומי
        "paypal":           ["paypal.com"],
        "netflix":          ["netflix.com"],
        "spotify":          ["spotify.com"],
        "microsoft":        ["microsoft.com", "outlook.com", "live.com"],
        "google":           ["google.com", "accounts.google.com", "gmail.com"],
        "apple":            ["apple.com", "icloud.com"],
        "amazon":           ["amazon.com", "amazon.co.uk"],
        "facebook":         ["facebook.com", "facebookmail.com"],
        "instagram":        ["instagram.com", "mail.instagram.com"],
        "whatsapp":         ["whatsapp.com"],
        "linkedin":         ["linkedin.com"],
        "ebay":             ["ebay.com"],
        "dropbox":          ["dropbox.com"],
    }

    _URL_RE = re.compile(
        r"https?://(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%])+"
    )
    _IP_IN_URL = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    _SENDER_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-]+)")

    # -----------------------------------------------------------------------
    def _sender_domain(self, sender: str) -> str:
        """הדומיין מתוך כתובת השולח, באותיות קטנות. מחרוזת ריקה אם אין."""
        match = self._SENDER_DOMAIN_RE.search(sender or "")
        return match.group(1).lower().rstrip(".") if match else ""

    def _domain_matches(self, domain: str, official: str) -> bool:
        """
        האם הדומיין הוא הדומיין הרשמי או תת-דומיין שלו.

        mail.netflix.com  מול  netflix.com   → כן
        netflix-il.info   מול  netflix.com   → לא
        """
        return domain == official or domain.endswith("." + official)

    def _check_brand_impersonation(self, sender: str, subject: str,
                                   content: str) -> tuple[str, str] | None:
        """
        מחזיר (מותג, דומיין השולח) אם המייל מתחזה למותג מוכר, אחרת None.

        המותג מזוהה בנושא ובגוף — שם התוקף שותל אותו כדי לבנות אמון.
        אם השולח הוא בכל זאת הדומיין הרשמי, אין התחזות.
        """
        domain = self._sender_domain(sender)
        if not domain:
            return None

        haystack = f"{subject} {content}".lower()
        for brand, official_domains in self.BRAND_DOMAINS.items():
            if brand not in haystack:
                continue
            if any(self._domain_matches(domain, off) for off in official_domains):
                return None          # נשלח מהדומיין הרשמי — תקין
            return brand, domain
        return None

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

        # בדיקה 9: התחזות למותג מוכר
        # המייל מציג את עצמו כארגון מוכר אך נשלח מדומיין שאינו שלו.
        # זהו הסיגנל החזק ביותר, ולכן הניקוד הגבוה ביותר.
        impersonation = self._check_brand_impersonation(sender, subject, content)
        if impersonation:
            brand, domain = impersonation
            risk_score += BRAND_IMPERSONATION_SCORE
            indicators.append(
                f'המייל מתיימר להיות מ"{brand}" אך נשלח מהדומיין {domain}'
            )

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