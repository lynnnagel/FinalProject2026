"""
URL-specific phishing detector.
"""
import re
from urllib.parse import urlparse
from datetime import datetime


class URLPhishingDetector:

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".click", ".loan", ".gq", ".ml",
        ".cf", ".ga", ".tk", ".work", ".party", ".racing", ".pw"
    ]

    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "short.link", "rb.gy", "cutt.ly"
    ]

    HOMOGLYPHS = [
        "paypa1", "arnazon", "g00gle", "micros0ft", "app1e",
        "faceb00k", "inst4gram", "tw1tter", "paypai", "googie",
        "amaz0n", "netfl1x"
    ]

    BRANDS = [
        "paypal", "amazon", "google", "microsoft", "apple",
        "facebook", "instagram", "netflix", "spotify",
        "bank", "leumi", "hapoalim", "discount", "mizrahi"
    ]

    SUSPICIOUS_PATH_WORDS = [
        "login", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "signin", "wallet",
        "credential", "authenticate", "validation"
    ]

    _IP_RE = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')

    def analyze_url(self, url: str) -> dict:
        start = datetime.now()
        score = 0.0
        indicators = []

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower().replace("www.", "")
            path = parsed.path.lower()
        except Exception:
            return {
                "risk_score": 50.0,
                "risk_level": "לא ניתן לנתח",
                "indicators": ["כתובת URL לא תקינה"],
                "recommendation": "בדוק את הכתובת שהזנת",
                "is_dangerous": False,
                "url": url,
                "response_time": 0.0,
            }

        # 1. HTTP (not HTTPS)
        if url.startswith("http://"):
            score += 15
            indicators.append("חיבור לא מאובטח (HTTP במקום HTTPS)")

        # 2. IP address instead of domain
        if self._IP_RE.match(url):
            score += 35
            indicators.append("כתובת IP ישירה במקום שם דומיין")

        # 3. URL shortener
        if any(netloc == s or netloc.endswith("." + s) for s in self.URL_SHORTENERS):
            score += 20
            indicators.append("שירות קיצור קישורים — היעד האמיתי מוסתר")

        # 4. Suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                score += 25
                indicators.append(f"סיומת דומיין חשודה (.{netloc.split('.')[-1]})")
                break

        # 5. Very long URL
        if len(url) > 100:
            score += 10
            indicators.append(f"כתובת URL ארוכה חשודה ({len(url)} תווים)")

        # 6. Many subdomains
        if netloc.count(".") >= 3:
            score += 15
            indicators.append("תת-דומיינים רבים — טקטיקת הסוואה נפוצה")

        # 7. Homoglyph attack
        if any(h in netloc for h in self.HOMOGLYPHS):
            score += 40
            indicators.append("שם דומיין מזויף (דמיון ויזואלי למותג אמיתי)")

        # 8. Brand impersonation
        for brand in self.BRANDS:
            if brand in netloc:
                parts = netloc.split(".")
                is_legit = len(parts) == 2 and parts[0] == brand
                if not is_legit:
                    score += 30
                    indicators.append(
                        f'זיוף מותג: "{brand}" מופיע בכתובת אך אינו הדומיין הרשמי'
                    )
                    break

        # 9. Suspicious keywords in path
        hits = [w for w in self.SUSPICIOUS_PATH_WORDS if w in path]
        if hits:
            score += min(len(hits) * 10, 25)
            indicators.append(f"מילים חשודות בנתיב: {', '.join(hits)}")

        score = min(score, 100.0)

        if score >= 70:
            risk_level = "מסוכן"
            recommendation = "אל תלחץ על הקישור. סביר שמדובר בניסיון פישינג."
        elif score >= 40:
            risk_level = "חשוד"
            recommendation = "היזהר. בדוק את הכתובת בקפידה לפני כניסה."
        elif score >= 20:
            risk_level = "זהירות"
            recommendation = "הכתובת מכילה כמה מאפיינים חשודים קלים."
        else:
            risk_level = "בטוח"
            recommendation = "הכתובת נראית תקינה."

        return {
            "risk_score": round(score, 1),
            "risk_level": risk_level,
            "indicators": indicators if indicators else ["לא נמצאו אינדיקטורים חשודים"],
            "recommendation": recommendation,
            "is_dangerous": score >= 70,
            "url": url,
            "response_time": round((datetime.now() - start).total_seconds(), 4),
        }


url_detector = URLPhishingDetector()