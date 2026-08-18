"""
LURA – מנוע החוקים.

תשע בדיקות משוקללות על השולח, הנושא והגוף, מסוכמות לציון 0–100.
המנוע שקוף במלואו: כל נקודה בציון מגיעה מבדיקה שאפשר להצביע עליה,
ולכן הוא גם מסביר למשתמש למה המייל סומן וגם אינו תלוי בקורפוס
האימון — מה שהופך אותו לחלק שמכליל למיילים שלא נראו מעולם.
"""
import re
from datetime import datetime

import risk_levels
from config import (
    MAX_KEYWORD_SCORE, KEYWORD_SCORE_PER_WORD,
    SUSPICIOUS_DOMAIN_SCORE, MULTIPLE_URLS_SCORE, URGENCY_SCORE,
    INVALID_DOMAIN_SCORE, URL_COUNT_THRESHOLD, BRAND_IMPERSONATION_SCORE,
    BODY_IMPERSONATION_SCORE, WEAK_KEYWORD_SCORE, MAX_WEAK_KEYWORD_SCORE,
)


class PhishingDetector:

    # מילים שמופיעות כמעט אך ורק בפישינג. כל אחת מהן היא סימן חזק.
    STRONG_KEYWORDS = [
        # עברית — ניסוחים שארגון אמיתי לא ישלח
        "אמת את חשבונך", "אימות זהות", "החשבון יינעל", "חשבונך ייחסם",
        "החשבון הושעה", "פעילות חריגה", "לחץ כאן", "עדכן פרטים",
        "הזן סיסמה", "הזן פרטי אשראי", "תעודת זהות", "זכית",
        "זכייה", "הגרלה", "פרס", "היום בלבד", "הצעה מוגבלת",
        "לחץ לאימות", "אישור מיידי", "חשבונך מוקפא",
        # אנגלית
        "verify your account", "verify your identity", "account locked",
        "account suspended", "unusual activity", "security alert",
        "click here", "update your payment", "confirm your password",
        "reset password", "act now", "limited time", "congratulations",
        "you have won", "claim your prize", "suspicious activity",
        "your account has been", "payment required", "social security",
        "tax refund", "immediately",
    ]

    # מילים שמופיעות גם במיילים לגיטימיים לחלוטין. מייל אמיתי של בנק
    # או חברת אשראי מכיל "חשבון", "אשראי" ו"כרטיס אשראי" בהכרח, ולכן
    # הן שוות פחות ומוגבלות בתקרה נמוכה. מייל אמיתי של כאל סומן בעבר
    # כפישינג רק בגללן.
    WEAK_KEYWORDS = [
        "חשבון", "בנק", "אשראי", "כרטיס אשראי", "העברה", "מזומן",
        "סיסמה", "אימות", "אישור", "ביטול", "חסימה", "פרטים אישיים",
        "מבצע", "מתנה", "חינם", "בחינם", "פג תוקף", "מסתיים",
        "רשות המסים", "ביטוח לאומי", "דואר ישראל", "בנק הפועלים",
        "בנק לאומי", "השעיה", "נחסם", "מוקפא",
        "account", "bank", "credit card", "password", "verify",
        "confirm", "invoice", "login", "sign in", "free", "gift",
        "prize", "winner", "claim", "urgent", "validate", "update your",
    ]

    # לתאימות לאחור — קוד או בדיקות שמצפים לרשימה אחת
    SUSPICIOUS_KEYWORDS = STRONG_KEYWORDS + WEAK_KEYWORDS

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
        "בנק לאומי":        ["leumi.co.il", "bankleumi.co.il", "leumi-card.co.il"],
        "לאומי":            ["leumi.co.il", "bankleumi.co.il"],
        "בנק דיסקונט":      ["discountbank.co.il"],
        "דיסקונט":          ["discountbank.co.il"],
        "מזרחי טפחות":      ["mizrahi-tefahot.co.il"],
        "בנק מזרחי":        ["mizrahi-tefahot.co.il"],
        "ישראכרט":          ["isracard.co.il", "premium.co.il"],
        "isracard":         ["isracard.co.il", "premium.co.il"],
        "כאל":              ["cal-online.co.il", "icc.co.il"],          # icc = Israel Credit Cards
        "cal-online":       ["cal-online.co.il", "icc.co.il"],
        "hot mobile":       ["hot.net.il", "hot.co.il"],
        "זאפ":              ["zap.co.il"],
        # תקשורת
        "פרטנר":            ["partner.co.il", "orange.co.il"],          # פרטנר היה אורנג'
        "partner":          ["partner.co.il", "orange.co.il"],
        "סלקום":            ["cellcom.co.il"],
        "cellcom":          ["cellcom.co.il"],
        "בזק":              ["bezeq.co.il", "bezeqint.net"],
        "bezeq":            ["bezeq.co.il", "bezeqint.net"],
        "גולן טלקום":       ["golantelecom.co.il"],
        # משלוחים
        "דואר ישראל":       ["israelpost.co.il"],
        "israel post":      ["israelpost.co.il"],
        "dhl":              ["dhl.com", "dhl.co.il"],
        "fedex":            ["fedex.com"],
        # מסחר
        "ksp":              ["ksp.co.il"],
        "terminal x":       ["terminalx.com"],
        "איקאה":            ["ikea.co.il", "ikea.com"],
        "ikea":             ["ikea.co.il", "ikea.com"],
        "רמי לוי":          ["rami-levy.co.il"],
        "שופרסל":           ["shufersal.co.il"],
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

        # ── ספקי אבטחה, מנויים ומסחר ─────────────────────────────────
        # הטבלה הזאת משמשת גם לזיהוי התחזות וגם לזיהוי שולח מוכר
        # (is_trusted_sender). המותגים כאן נוספו בגלל הצד השני:
        # דואר תפעולי שלהם — חידוש מנוי, אישור הזמנה, התראת אבטחה —
        # הוא בדיוק סוג הדואר הלגיטימי שכמעט אינו קיים בקורפוסי
        # האימון, ולכן BERT מסמן אותו כפישינג בביטחון גבוה.
        "temu":             ["temu.com"],
        "aliexpress":       ["aliexpress.com"],
        "booking":          ["booking.com"],
        "airbnb":           ["airbnb.com"],
        "wolt":             ["wolt.com"],
        "malwarebytes":     ["malwarebytes.com"],
        "norton":           ["norton.com", "nortonlifelock.com"],
        "mcafee":           ["mcafee.com"],
        "avast":            ["avast.com"],
        "kaspersky":        ["kaspersky.com"],
        "bitdefender":      ["bitdefender.com"],
        "github":           ["github.com"],
        "adobe":            ["adobe.com"],
        "openai":           ["openai.com"],
        "anthropic":        ["anthropic.com"],
        "discord":          ["discord.com", "discordapp.com"],
        "alibaba":          ["alibaba.com", "alibabagroup.com"],
        "shein":            ["shein.com"],
        "steam":            ["steampowered.com", "valvesoftware.com"],
        "zoom":             ["zoom.us"],
        "slack":            ["slack.com"],
        "trello":           ["trello.com"],
        "notion":           ["notion.so"],
        "canva":            ["canva.com"],

        # ── חנויות ושירותים שדואר תפעולי שלהם נפוץ בתיבה ─────────────
        # אישור הזמנה, הודעת משלוח וקבלה הם הקטגוריה שהמערכת טעתה בה
        # יותר מכל: המבנה שלהם — הרבה קישורים, "order", "account" —
        # מפעיל את מנוע החוקים, והמודל מסמן אותם כמעט תמיד.
        "iherb":            ["iherb.com"],
        "asos":             ["asos.com"],
        "next":             ["next.co.il", "nextdirect.com"],
        "adidas":           ["adidas.com", "adidas.co.il"],
        "nike":             ["nike.com"],
        "zara":             ["zara.com"],
        "castro":           ["castro.com"],
        "fox":              ["fox.co.il"],
        "golf":             ["golfandco.co.il"],
        "מקס":              ["max.co.il"],
        "עזריאלי":          ["azrieli.com"],
        "yes":              ["yes.co.il"],
        "hot":              ["hot.net.il", "hot.co.il"],
        "wix":              ["wix.com"],
        "paypal me":        ["paypal.com"],
        "aliexpress il":    ["aliexpress.com"],
        "trustpilot":       ["trustpilot.com", "trustpilotmail.com"],
        "booking com":      ["booking.com"],
        "ryanair":          ["ryanair.com"],
        "el al":            ["elal.co.il"],
        "אל על":            ["elal.co.il"],
        "issta":            ["issta.co.il"],
        "gett":             ["gett.com"],
        "יאנגו":            ["yango.com"],
        "cibus":            ["cibus.co.il"],
        "סיבוס":            ["cibus.co.il"],
        "10bis":            ["10bis.co.il"],
        "תן ביס":           ["10bis.co.il"],
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

    @classmethod
    def _brand_patterns(cls) -> dict:
        """
        ביטוי לכל מותג, עם גבולות מילה.

        בלי הגבולות ההתאמה היא של תת-מחרוזת: המפתח "cal" נתפס בתוך
        call, local ו-calendar, ומייל תמים של Temu סומן כמתחזה לכאל.
        \b עובד גם על עברית, כי אותיות עבריות הן תווי-מילה — ולכן
        "כאל" לא ייתפס בתוך "כאלה".
        """
        if not hasattr(cls, "_brand_re_cache"):
            cls._brand_re_cache = {
                brand: re.compile(r"\b" + re.escape(brand) + r"\b")
                for brand in cls.BRAND_DOMAINS
            }
        return cls._brand_re_cache

    def _check_brand_impersonation(self, sender: str, subject: str,
                                   content: str) -> tuple[str, str, str] | None:
        """
        מחזיר (מותג, דומיין השולח, מקום ההתאמה) אם המייל מתחזה למותג
        מוכר, אחרת None. מקום ההתאמה הוא "subject" או "body", והוא
        קובע את הניקוד — התאמה בגוף חלשה יותר.

        אם השולח הוא בכל זאת הדומיין הרשמי, אין התחזות.
        """
        domain = self._sender_domain(sender)
        if not domain:
            return None

        patterns = self._brand_patterns()
        subject_l = (subject or "").lower()
        body_l = (content or "").lower()

        # ── שלב א: שורת הנושא ────────────────────────────────────────
        # תוקף שם את שם המותג בנושא כדי לבנות אמון כבר בשורה הראשונה.
        # זהו הסיגנל החזק, ולכן הוא נבדק ראשון ומקבל את הניקוד המלא.
        for brand, official_domains in self.BRAND_DOMAINS.items():
            if not patterns[brand].search(subject_l):
                continue
            if any(self._domain_matches(domain, off) for off in official_domains):
                return None          # נשלח מהדומיין הרשמי — תקין
            return brand, domain, "subject"

        # ── שלב ב: גוף ההודעה, בתנאים מחמירים ────────────────────────
        # בדיקת הגוף בלי תנאים היא זו שסימנה מייל אמיתי של Malwarebytes
        # שהזכיר "Google Chrome" כמתחזה לגוגל: הזכרת מותג אינה התחזות
        # אליו, וניוזלטרים מזכירים מותגים כדבר שבשגרה.
        #
        # אבל דילוג מוחלט על הגוף פותח פער אמיתי: מייל עם הנושא
        # "Action required: your mailbox is full", שמזכיר
        # "Microsoft 365" רק בגוף ומקשר ל-office365-alert.net, קיבל
        # 19 נקודות בלבד — פחות מכל סף סביר. ההתחזות הייתה שם, פשוט
        # לא בשורת הנושא.
        #
        # שני תנאים מפרידים בין השניים:
        #   1. יש קישור, ואף קישור אינו מוביל לדומיין הרשמי של המותג.
        #      ניוזלטר שמזכיר מותג מקשר אליו או לאתר עצמו; מתחזה
        #      מקשר לדומיין שהוא שולט בו.
        #   2. השולח עצמו אינו חברה מוכרת. מייל שנשלח באמת
        #      מ-malwarebytes.com אינו מתחזה לגוגל גם אם הזכיר את
        #      Google Chrome; זה בדיוק המקרה שיצר את ההתרעה השגויה.
        #      לעומתו office365-alert.net אינו הדומיין של אף חברה
        #      בטבלה.
        urls = self._URL_RE.findall(content or "")
        if not urls:
            return None

        if any(
            self._domain_matches(domain, off)
            for offs in self.BRAND_DOMAINS.values()
            for off in offs
        ):
            return None          # השולח הוא חברה מוכרת בזכות עצמה

        for brand, official_domains in self.BRAND_DOMAINS.items():
            if not patterns[brand].search(body_l):
                continue
            if any(self._domain_matches(domain, off) for off in official_domains):
                return None          # נשלח מהדומיין הרשמי — תקין
            # האם קישור כלשהו מוביל בכל זאת למותג האמיתי?
            if any(
                self._domain_matches(url_domain, off)
                for url in urls
                for url_domain in [self._url_domain(url)]
                if url_domain
                for off in official_domains
            ):
                return None          # מקשר למותג האמיתי — לא התחזות
            return brand, domain, "body"

        return None

    # ביטויים שמסגירים דיוור שיווקי או התראת שירות. הם אינם ראיה
    # ללגיטימיות בפני עצמם, אבל הם ראיה לכך שהמייל שייך לקטגוריה אחרת
    # מפישינג — ובזה תפקידם.
    PROMO_MARKERS = [
        # קישור הסרה — הסימן האמין ביותר. חוקי הספאם בארה"ב ובאירופה
        # מחייבים אותו בדיוור שיווקי, ולכן הוא מופיע כמעט תמיד.
        "unsubscribe", "opt out", "opt-out", "manage preferences",
        "email preferences", "notification settings",
        "להסרה מרשימת התפוצה", "להסרה מרשימת הדיוור", "הסרה מרשימת",
        "לביטול קבלת הודעות", "אם אינך מעוניין לקבל",
        # סימון פרסומת מפורש
        "(ad)", "[ad]", "advertisement", "פרסומת", "מודעה",
        # אוצר מילים של מבצעים
        "% off", "discount", "coupon", "promo code", "free shipping",
        "add to cart", "shop now", "limited stock", "best sellers",
        "מבצע", "הנחה", "קופון", "משלוח חינם", "לרכישה", "בהזדמנות",
        "מוצרים חדשים", "הטבות", "במחיר מיוחד",
    ]

    # תת-קבוצה של STRONG_KEYWORDS שמבטלת את סיווג "פרסומת".
    #
    # אי אפשר להשתמש ב-STRONG_KEYWORDS המלאה: היא כוללת "לחץ כאן",
    # "היום בלבד" ו-"limited time" — ניסוחים שמופיעים כמעט בכל דיוור
    # שיווקי לגיטימי, ולכן כל פרסומת הייתה נפסלת והבדיקה הייתה חסרת
    # תועלת. הן סימני ספאם, לא סימני פישינג.
    #
    # מה שנשאר כאן הוא מה שמאפיין תקיפה ולא מכירה: בקשה לאישורים,
    # איום על החשבון, או פיתיון של פרס. פישינג שעוטה מעטה של פרסומת
    # ייתפס בזכות הקבוצה הזאת.
    ATTACK_KEYWORDS = [
        "אמת את חשבונך", "אימות זהות", "החשבון יינעל", "חשבונך ייחסם",
        "החשבון הושעה", "פעילות חריגה", "עדכן פרטים", "הזן סיסמה",
        "הזן פרטי אשראי", "תעודת זהות", "לחץ לאימות", "חשבונך מוקפא",
        "זכית", "זכייה", "הגרלה", "פרס",
        "verify your account", "verify your identity", "account locked",
        "account suspended", "unusual activity", "suspicious activity",
        "confirm your password", "verify your password", "reset password",
        "update your payment", "payment required", "your account has been",
        "social security", "tax refund", "congratulations", "you have won",
        "claim your prize",
    ]

    def looks_promotional(self, subject: str, content: str) -> bool:
        """
        האם המייל הוא דיוור שיווקי או התראת שירות, ולא ניסיון פישינג.

        BERT אומן על קורפוסים שבהם ספאם מתויג כמחלקה החיובית יחד עם
        פישינג, ולכן הוא לא מבדיל ביניהם: פרסומת של Temu מקבלת ממנו
        99.99 בדיוק כמו מייל שמבקש פרטי אשראי. אבל LURA מזהה פישינג,
        לא ספאם — פרסומת מעצבנת אינה איום, וסימונה כ"סכנה" שוחק את
        אמון המשתמש בכל שאר ההתרעות.

        הבדיקה דורשת ראיה חיובית לקטגוריה השיווקית, ולא שקט של מנוע
        החוקים. שקט אינו אומר דבר — ודווקא מייל פישינג מנוסח היטב
        משתיק את החוקים. לכן גם אם נמצא סימן שיווקי, נדרש שלא יופיע
        אף ניסוח של בקשת אישורים או איום על החשבון: "זכית בפרס, לחץ
        כאן" הוא פישינג שעוטה מעטה של פרסומת, וה-STRONG_KEYWORDS
        מכסים אותו.
        """
        haystack = f"{subject or ''} {content or ''}".lower()
        if not any(marker in haystack for marker in self.PROMO_MARKERS):
            return False
        return not any(kw in haystack for kw in self.ATTACK_KEYWORDS)

    # אוצר מילים של דואר תפעולי: אישורי הזמנה, משלוחים, קבלות.
    TRANSACTIONAL_MARKERS = [
        "order", "your order", "shipped", "shipping", "delivery", "delivered",
        "tracking", "receipt", "invoice", "purchase", "subscription renews",
        "has been sent", "on its way", "arriving",
        "הזמנה", "ההזמנה", "משלוח", "נשלח", "מעקב", "קבלה", "חשבונית",
        "רכישה", "נארז", "בדרך אליך", "אישור הזמנה", "מספר הזמנה",
    ]

    def looks_transactional(self, sender: str, subject: str, content: str) -> bool:
        """
        האם זהו דואר תפעולי אמיתי — אישור הזמנה, הודעת משלוח, קבלה.

        זו הקטגוריה הגדולה ביותר שהמערכת טעתה בה. מייל הזמנה מכיל
        באופן טבעי הרבה קישורים ומילים כמו order ו-account, ולכן מנוע
        החוקים נותן לו ניקוד בינוני; BERT מסמן אותו כמעט תמיד, כי
        בקורפוסי האימון אין כמעט דואר מסחרי לגיטימי. שני המנועים
        טועים באותו כיוון, ולכן ההסכמה ביניהם אינה מעידה על דבר.

        מה שמפריד בין אישור הזמנה אמיתי לזיוף שלו הוא **לאן מובילים
        הקישורים**. חנות אמיתית מקשרת לעצמה. תוקף שמחקה אישור הזמנה
        חייב להוביל לדומיין שהוא שולט בו — אחרת אין לו מה להרוויח.

        ארבעה תנאים, וכולם נדרשים:
          1. השולח הוא חברה מזוהה. בלי התנאי הזה הבדיקה חסרת ערך:
             זיוף שנשלח מ-iherb-delivery.info ומקשר לעצמו מקיים את כל
             השאר, כי התוקף שולט בשני הצדדים. "הקישור מוביל לשולח"
             מעיד על עקביות, לא על אמינות — האמינות מגיעה מכך שהשולח
             הוא מי שהוא טוען שהוא.
          2. יש בטקסט אוצר מילים תפעולי.
          3. אין בקשת אישורים או איום על החשבון.
          4. כל קישור מוביל לדומיין של השולח או של מותג מוכר.
        """
        if not self.is_trusted_sender(sender):
            return False

        haystack = f"{subject or ''} {content or ''}".lower()
        if not any(m in haystack for m in self.TRANSACTIONAL_MARKERS):
            return False
        if any(kw in haystack for kw in self.ATTACK_KEYWORDS):
            return False

        domain = self._sender_domain(sender)
        if not domain:
            return False

        known = [off for offs in self.BRAND_DOMAINS.values() for off in offs]
        for url in self._URL_RE.findall(content or ""):
            url_domain = self._url_domain(url)
            if not url_domain:
                continue
            if self._domain_matches(url_domain, domain):
                continue
            if self._shares_registrable_part(url_domain, domain):
                continue
            if any(self._domain_matches(url_domain, off) for off in known):
                continue
            return False          # קישור שיוצא החוצה — לא תפעולי
        return True

    @staticmethod
    def _shares_registrable_part(a: str, b: str) -> bool:
        """
        האם שני דומיינים שייכים לאותו ארגון.

        חנויות שולחות דואר תפעולי מתשתית נלווית — iherb.com מול
        e.iherb.com או iherbemail.com — ולכן השוואה מדויקת בלבד הייתה
        פוסלת אישורי הזמנה אמיתיים.
        """
        core = lambda d: d.rsplit(".", 2)[0].split(".")[-1]
        return bool(core(a)) and core(a) == core(b)

    def is_trusted_sender(self, sender: str) -> bool:
        """
        האם המייל נשלח באמת מדומיין של חברה מוכרת.

        זו ראיה חיובית ללגיטימיות, ולא רק היעדר ראיה להתחזות: תוקף
        יכול לכתוב מה שירצה בגוף המייל, אבל אינו יכול לשלוח
        מ-accounts.google.com. שקט של מנוע החוקים אינו אומר דבר —
        הוא גם שותק על מייל שאין לו שולח כלל.

        משמש להנמכת ציון BERT: המודל אומן על קורפוסים שכמעט אין בהם
        דואר לגיטימי בענייני חשבון ואבטחה, ולכן הוא מסמן ב-99.99
        גם הודעת חידוש מנוי מ-malwarebytes.com וגם איפוס סיסמה
        שהמשתמש עצמו ביקש מ-accounts.google.com.
        """
        domain = self._sender_domain(sender)
        if not domain:
            return False

        # ספק דואר חינמי אינו "החברה עצמה". gmail.com ו-outlook.com
        # מופיעים ב-BRAND_DOMAINS כדומיינים של גוגל ומיקרוסופט, אבל
        # בניגוד ל-accounts.google.com הם כתובות שכל אחד יכול לפתוח
        # תוך דקה. בלי החרגה כאן, כל פישינג שנשלח מ-Gmail קיבל הנמכה
        # של ציון המודל פי ארבעה — וזה אחד הערוצים הנפוצים ביותר
        # לפישינג בפועל. אותה רשימה כבר משמשת את בדיקה 8, שמזהה
        # ארגון רשמי שפונה מכתובת חינמית.
        if any(domain == p or domain.endswith("." + p)
               for p in self.FREE_EMAIL_PROVIDERS):
            return False

        return any(
            self._domain_matches(domain, official)
            for officials in self.BRAND_DOMAINS.values()
            for official in officials
        )

    @staticmethod
    def _url_domain(url: str) -> str:
        """הדומיין מתוך URL, באותיות קטנות. מחרוזת ריקה אם אין."""
        rest = url.split("://", 1)[-1]
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split("@")[-1].split(":", 1)[0]
        return host.lower().rstrip(".")

    def analyze_email(self, sender: str, subject: str, content: str) -> dict:
        start = datetime.now()
        full_text = f"{sender} {subject} {content}".lower()
        risk_score = 0.0
        indicators: list[str] = []

        # בדיקה 1: מילות מפתח חשודות
        strong_hits = [kw for kw in self.STRONG_KEYWORDS if kw.lower() in full_text]
        weak_hits = [kw for kw in self.WEAK_KEYWORDS if kw.lower() in full_text]

        # מילים חזקות נושאות את מלוא הניקוד. מילים חלשות מוגבלות לתקרה
        # נמוכה, כי הן מופיעות גם במייל בנקאי לגיטימי — בלי ההפרדה הזאת
        # כל חשבונית של חברת אשראי נספרה כפישינג.
        if strong_hits:
            risk_score += min(len(strong_hits) * KEYWORD_SCORE_PER_WORD, MAX_KEYWORD_SCORE)
            indicators.append(f"נמצאו {len(strong_hits)} ניסוחים אופייניים לפישינג")

        if weak_hits:
            risk_score += min(len(weak_hits) * WEAK_KEYWORD_SCORE, MAX_WEAK_KEYWORD_SCORE)
            if not strong_hits:
                indicators.append(f"נמצאו {len(weak_hits)} מילים שמופיעות לעיתים בפישינג")

        keyword_hits = strong_hits + weak_hits

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
            brand, domain, where = impersonation
            # התאמה בגוף ההודעה חלשה יותר מהתאמה בנושא, ולכן מנוקדת
            # פחות: המותג יכול להופיע שם גם באזכור לגיטימי.
            risk_score += (
                BRAND_IMPERSONATION_SCORE if where == "subject"
                else BODY_IMPERSONATION_SCORE
            )
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

        # סיכום. רמת הסיכון וההמלצה נקבעות ב-risk_levels, המודול
        # היחיד שמכיר את הספים — כדי שהתווית לא תיקבע בשני מקומות
        # ותיפרד מהם.
        risk_score = min(risk_score, 100.0)
        response_time = (datetime.now() - start).total_seconds()

        return risk_levels.apply({
            "risk_score": round(risk_score, 2),
            "indicators": indicators if indicators else ["לא נמצאו אינדיקטורים חשודים"],
            "response_time": round(response_time, 4),
        })


detector = PhishingDetector()