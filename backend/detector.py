"""
LURA - the rule engine.

Nine weighted checks over the sender, the subject and the body, summed
into a score from 0 to 100. The engine is fully transparent: every point
comes from a check you can point at. That is what lets it tell the user
why a message was flagged, and it is also why it does not depend on the
training corpus - which makes it the part that generalises to mail
nobody has ever seen.
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

    # Words that show up almost only in phishing. Each one is a strong sign.
    STRONG_KEYWORDS = [
        # Hebrew - phrasings a real organisation would not send
        "אמת את חשבונך", "אימות זהות", "החשבון יינעל", "חשבונך ייחסם",
        "החשבון הושעה", "פעילות חריגה", "לחץ כאן", "עדכן פרטים",
        "הזן סיסמה", "הזן פרטי אשראי", "תעודת זהות", "זכית",
        "זכייה", "הגרלה", "פרס", "היום בלבד", "הצעה מוגבלת",
        "לחץ לאימות", "אישור מיידי", "חשבונך מוקפא",
        # English
        "verify your account", "verify your identity", "account locked",
        "account suspended", "unusual activity", "security alert",
        "click here", "update your payment", "confirm your password",
        "reset password", "act now", "limited time", "congratulations",
        "you have won", "claim your prize", "suspicious activity",
        "your account has been", "payment required", "social security",
        "tax refund", "immediately",
    ]

    # Words that also appear in entirely legitimate mail. A real message
    # from a bank or a card company is bound to contain "account",
    # "credit" and "credit card", so these are worth less and capped
    # low. A genuine Cal message was once flagged as phishing on their
    # account alone.
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

    # Backwards compatibility - code or tests expecting a single list
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
    # Brands and the domains they really send from.
    #
    # This is the strongest check in the engine: if a message presents
    # itself as Bank Hapoalim but arrives from bankhapoalim-secure.net,
    # that is impersonation, full stop.
    #
    # The earlier domain check (VALID_DOMAIN_SUFFIXES) only looked at the
    # suffix, so bezeq-pay.net and netflix-il.info sailed through - .net
    # and .info are perfectly valid endings. Measured over 250 Hebrew
    # phishing messages, it never fired once.
    #
    # The key is how the brand appears in the text; the value is the
    # domains the organisation actually sends from. List every spelling
    # likely to turn up in a message.
    # -----------------------------------------------------------------------
    BRAND_DOMAINS = {
        # Banks and credit cards - Israel
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
        # Telecoms
        "פרטנר":            ["partner.co.il", "orange.co.il"],          # פרטנר היה אורנג'
        "partner":          ["partner.co.il", "orange.co.il"],
        "סלקום":            ["cellcom.co.il"],
        "cellcom":          ["cellcom.co.il"],
        "בזק":              ["bezeq.co.il", "bezeqint.net"],
        "bezeq":            ["bezeq.co.il", "bezeqint.net"],
        "גולן טלקום":       ["golantelecom.co.il"],
        # Shipping
        "דואר ישראל":       ["israelpost.co.il"],
        "israel post":      ["israelpost.co.il"],
        "dhl":              ["dhl.com", "dhl.co.il"],
        "fedex":            ["fedex.com"],
        # Retail
        "ksp":              ["ksp.co.il"],
        "terminal x":       ["terminalx.com"],
        "איקאה":            ["ikea.co.il", "ikea.com"],
        "ikea":             ["ikea.co.il", "ikea.com"],
        "רמי לוי":          ["rami-levy.co.il"],
        "שופרסל":           ["shufersal.co.il"],
        # Government
        "רשות המסים":       ["gov.il", "taxes.gov.il"],
        "ביטוח לאומי":      ["btl.gov.il", "gov.il"],
        "משרד התחבורה":     ["gov.il"],
        "חברת החשמל":       ["iec.co.il"],
        # International
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

        # -- Security vendors, subscriptions and retail ---------------
        # This table serves both impersonation detection and recognising
        # a known sender (is_trusted_sender). The brands below were added
        # for the second purpose: their operational mail - a renewal
        # notice, an order confirmation, a security alert - is exactly
        # the kind of legitimate message that barely exists in the
        # training corpora, so BERT flags it as phishing with high
        # confidence.
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

        # -- Shops and services whose operational mail fills an inbox --
        # Order confirmations, shipping notices and receipts are the
        # category the system got wrong most often: their shape - many
        # links, "order", "account" - sets off the rule engine, and the
        # model flags them nearly every time.
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
        """The domain from a sender address, lowercased. Empty if there is none."""
        match = self._SENDER_DOMAIN_RE.search(sender or "")
        return match.group(1).lower().rstrip(".") if match else ""

    def _domain_matches(self, domain: str, official: str) -> bool:
        """
        Is this the official domain, or a subdomain of it?

        mail.netflix.com  vs  netflix.com   -> yes
        netflix-il.info   vs  netflix.com   -> no
        """
        return domain == official or domain.endswith("." + official)

    @classmethod
    def _brand_patterns(cls) -> dict:
        """
        One pattern per brand, with word boundaries.

        Without the boundaries this matches substrings: the key "cal"
        was found inside call, local and calendar, and an innocent Temu
        message got flagged as impersonating Cal. \b works on Hebrew
        too, since Hebrew letters count as word characters - so "כאל"
        will not match inside "כאלה".
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
        Returns (brand, sender domain, where it matched) if the message
        impersonates a known brand, otherwise None. "where" is either
        "subject" or "body" and decides the score - a body match counts
        for less.

        If the sender is the official domain after all, there is no
        impersonation.
        """
        domain = self._sender_domain(sender)
        if not domain:
            return None

        patterns = self._brand_patterns()
        subject_l = (subject or "").lower()
        body_l = (content or "").lower()

        # -- Step 1: the subject line ---------------------------------
        # An attacker puts the brand name in the subject to build trust
        # from the very first line. That is the strong signal, so it is
        # checked first and carries the full score.
        for brand, official_domains in self.BRAND_DOMAINS.items():
            if not patterns[brand].search(subject_l):
                continue
            if any(self._domain_matches(domain, off) for off in official_domains):
                return None          # נשלח מהדומיין הרשמי — תקין
            return brand, domain, "subject"

        # -- Step 2: the body, under stricter conditions ---------------
        # Checking the body with no conditions is what flagged a genuine
        # Malwarebytes message that mentioned "Google Chrome" as
        # impersonating Google. Mentioning a brand is not impersonating
        # it, and newsletters name brands all the time.
        #
        # But skipping the body entirely leaves a real gap: a message
        # subjected "Action required: your mailbox is full", naming
        # "Microsoft 365" only in the body and linking to
        # office365-alert.net, scored just 19 - below any sensible
        # threshold. The impersonation was there, only not in the
        # subject line.
        #
        # Two conditions separate the two cases:
        #   1. There is a link, and no link resolves to the brand's own
        #      domain. A newsletter naming a brand links to it or to its
        #      own site; a forger links to a domain they control.
        #   2. The sender is not itself a recognised company. Mail
        #      genuinely from malwarebytes.com is not impersonating
        #      Google even if it mentioned Google Chrome - which is
        #      exactly what caused the false alarm. office365-alert.net,
        #      by contrast, is nobody's domain in the table.
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
            # Does any link point at the real brand after all?
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

    # Phrases that give away marketing mail or a service notice. They
    # are not evidence of legitimacy on their own, but they are evidence
    # the message belongs to a different category than phishing - and
    # that is their job here.
    PROMO_MARKERS = [
        # Unsubscribe link - the most reliable marker. Spam law in the
        # US and Europe requires it on marketing mail, so it is almost
        # always present.
        "unsubscribe", "opt out", "opt-out", "manage preferences",
        "email preferences", "notification settings",
        "להסרה מרשימת התפוצה", "להסרה מרשימת הדיוור", "הסרה מרשימת",
        "לביטול קבלת הודעות", "אם אינך מעוניין לקבל",
        # Explicit advertisement marker
        "(ad)", "[ad]", "advertisement", "פרסומת", "מודעה",
        # Offer and discount vocabulary
        "% off", "discount", "coupon", "promo code", "free shipping",
        "add to cart", "shop now", "limited stock", "best sellers",
        "מבצע", "הנחה", "קופון", "משלוח חינם", "לרכישה", "בהזדמנות",
        "מוצרים חדשים", "הטבות", "במחיר מיוחד",
    ]

    # A subset of STRONG_KEYWORDS that cancels the "marketing" verdict.
    #
    # The full STRONG_KEYWORDS list cannot be used here: it contains
    # "click here", "today only" and "limited time" - phrasings that
    # appear in nearly all legitimate marketing mail, so every
    # advertisement was rejected and the check was useless. Those are
    # signs of spam, not signs of phishing.
    #
    # What remains marks an attack rather than a sale: a request for
    # credentials, a threat to the account, or a prize as bait. Phishing
    # dressed up as an advertisement is caught by this list.
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

    # Operational mail vocabulary: order confirmations, shipping, receipts.
    TRANSACTIONAL_MARKERS = [
        "order", "your order", "shipped", "shipping", "delivery", "delivered",
        "tracking", "receipt", "invoice", "purchase", "subscription renews",
        "has been sent", "on its way", "arriving",
        "הזמנה", "ההזמנה", "משלוח", "נשלח", "מעקב", "קבלה", "חשבונית",
        "רכישה", "נארז", "בדרך אליך", "אישור הזמנה", "מספר הזמנה",
    ]

    def looks_transactional(self, sender: str, subject: str, content: str) -> bool:
        """
        Is this genuine operational mail - an order confirmation, a
        shipping notice, a receipt?

        This is the largest category the system got wrong. An order
        message naturally carries many links and words like order and
        account, so the rule engine gives it a middling score; BERT
        flags it nearly every time, because the training corpora hold
        almost no legitimate commercial mail. Both engines err in the
        same direction, so their agreement proves nothing.

        What separates a real order confirmation from a forged one is
        **where the links go**. A real shop links to itself. An attacker
        mimicking an order confirmation has to lead somewhere they
        control - otherwise there is nothing in it for them.

        Four conditions, all required:
          1. The sender is a recognised company. Without this the check
             is worthless: a forgery sent from iherb-delivery.info that
             links back to itself satisfies everything else, because the
             attacker controls both ends. "The link points at the
             sender" shows consistency, not trustworthiness - that comes
             from the sender being who it claims to be.
          2. The text carries operational vocabulary.
          3. Nothing asks for credentials or threatens the account.
          4. Every link resolves to the sender's domain or a known brand.
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
        Do two domains belong to the same organisation?

        Shops send operational mail from adjacent infrastructure -
        iherb.com against e.iherb.com or iherbemail.com - so an exact
        match alone would have rejected genuine order confirmations.
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

        # A free mail provider is not "the company itself". gmail.com
        # and outlook.com appear in BRAND_DOMAINS as Google's and
        # Microsoft's domains, but unlike accounts.google.com they are
        # addresses anyone can open in a minute. Without excluding them,
        # every phishing message sent from Gmail had the model's score
        # cut by a factor of four - and a free mailbox is one of the
        # commonest channels phishing actually arrives through. The same
        # list already backs check 8, which flags an official-sounding
        # organisation writing from a free address.
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
        """The domain from a URL, lowercased. Empty if there is none."""
        rest = url.split("://", 1)[-1]
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split("@")[-1].split(":", 1)[0]
        return host.lower().rstrip(".")

    def analyze_email(self, sender: str, subject: str, content: str) -> dict:
        start = datetime.now()
        full_text = f"{sender} {subject} {content}".lower()
        risk_score = 0.0
        indicators: list[str] = []

        # Check 1: suspicious keywords
        strong_hits = [kw for kw in self.STRONG_KEYWORDS if kw.lower() in full_text]
        weak_hits = [kw for kw in self.WEAK_KEYWORDS if kw.lower() in full_text]

        # Strong words carry the full score. Weak ones are held to a low
        # cap, because they also turn up in genuine bank mail - without
        # that split, every credit card statement counted as phishing.
        if strong_hits:
            risk_score += min(len(strong_hits) * KEYWORD_SCORE_PER_WORD, MAX_KEYWORD_SCORE)
            indicators.append(f"נמצאו {len(strong_hits)} ניסוחים אופייניים לפישינג")

        if weak_hits:
            risk_score += min(len(weak_hits) * WEAK_KEYWORD_SCORE, MAX_WEAK_KEYWORD_SCORE)
            if not strong_hits:
                indicators.append(f"נמצאו {len(weak_hits)} מילים שמופיעות לעיתים בפישינג")

        keyword_hits = strong_hits + weak_hits

        # Check 2: lookalike patterns in the sender
        sender_lower = sender.lower()
        if any(pat in sender_lower for pat in self.SUSPICIOUS_SENDER_PATTERNS):
            risk_score += SUSPICIOUS_DOMAIN_SCORE
            indicators.append('כתובת דוא"ל חשודה – תווים מבלבלים')

        # Check 3: too many links
        urls = self._URL_RE.findall(content)
        if len(urls) > URL_COUNT_THRESHOLD:
            risk_score += MULTIPLE_URLS_SCORE
            indicators.append(f"נמצאו {len(urls)} קישורים חשודים")

        # Check 4: urgency language
        urgency_hits = [w for w in self.URGENCY_WORDS if w in full_text]
        if urgency_hits:
            risk_score += URGENCY_SCORE
            indicators.append("דחיפות מלאכותית – לחץ על המשתמש")

        # Check 5: non-standard sending domain
        if "@" in sender and not any(
            sfx in sender.lower() for sfx in self.VALID_DOMAIN_SUFFIXES
        ):
            risk_score += INVALID_DOMAIN_SCORE
            indicators.append("דומיין לא תקני")

        # Check 9: impersonating a known brand
        # The message presents itself as a known organisation but comes
        # from a domain that is not theirs. Strongest signal here, so it
        # carries the highest score.
        impersonation = self._check_brand_impersonation(sender, subject, content)
        if impersonation:
            brand, domain, where = impersonation
            # A body match is weaker than a subject match and scores
            # less: the brand can appear there in a legitimate mention.
            risk_score += (
                BRAND_IMPERSONATION_SCORE if where == "subject"
                else BODY_IMPERSONATION_SCORE
            )
            indicators.append(
                f'המייל מתיימר להיות מ"{brand}" אך נשלח מהדומיין {domain}'
            )

        # Check 6: a raw IP address in a link
        if self._IP_IN_URL.search(content):
            risk_score += 25
            indicators.append("קישור עם כתובת IP ישירה – חשוד מאוד")

        # Check 7: URL shortener (hides the destination)
        if any(s in content.lower() for s in self.URL_SHORTENERS):
            risk_score += 15
            indicators.append("שימוש בקיצור URL – מסתיר יעד")

        # Check 8: official-sounding organisation on a free mailbox
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

        # Wrap up. The risk band and the advice come from risk_levels,
        # the only module that knows the thresholds - so the label is
        # not decided in two places and cannot drift from them.
        risk_score = min(risk_score, 100.0)
        response_time = (datetime.now() - start).total_seconds()

        return risk_levels.apply({
            "risk_score": round(risk_score, 2),
            "indicators": indicators if indicators else ["לא נמצאו אינדיקטורים חשודים"],
            "response_time": round(response_time, 4),
        })


detector = PhishingDetector()