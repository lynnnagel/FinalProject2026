"""
LURA - the rule engine.

Nine weighted checks over the sender, subject and body, summed into a
score from 0 to 100. Every point comes from a check you can point at,
which is what lets it tell the user why a message was flagged - and,
since it does not depend on the training data, it is the part that
generalises to mail nobody has seen.
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

    # Words that also appear in entirely legitimate mail - a real bank
    # message is bound to contain "account" and "credit card" - so they
    # are worth less and capped low. A genuine Cal message was once
    # flagged on their account alone.
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
    # Brands and the domains they really send from. The strongest check in
    # the engine: a message presenting itself as Bank Hapoalim but arriving
    # from bankhapoalim-secure.net is impersonation, full stop.
    #
    # The earlier check (VALID_DOMAIN_SUFFIXES) looked only at the suffix,
    # so bezeq-pay.net and netflix-il.info sailed through. Over 250 Hebrew
    # phishing messages it never fired once.
    #
    # Key: how the brand appears in text - list every likely spelling.
    # Value: the domains the organisation actually sends from.
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
        # The table also backs is_trusted_sender, which is why these are
        # here: their operational mail - renewal notice, security alert -
        # barely exists in the training data, so BERT flags it with high
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
        # The category the system got wrong most often: the shape of an
        # order confirmation - many links, "order", "account" - sets off
        # the rules, and the model flags it nearly every time.
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

    # Brand keys that are also ordinary words. "next", "yes", "hot" and
    # "partner" turn up in normal mail constantly - a LinkedIn digest
    # containing "partner" scored 45 for impersonating Partner. They stay
    # in the table because is_trusted_sender needs their domains, but for
    # impersonation they need more than the word: a link carrying the
    # brand name to a domain that is not the brand's.
    AMBIGUOUS_BRANDS = frozenset({
        "partner", "next", "yes", "hot", "golf", "fox", "booking",
        "steam", "zoom", "slack", "notion", "מקס",
    })

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

        Without them this matches substrings: "cal" was found inside
        call, local and calendar, flagging an innocent Temu message. \b
        works on Hebrew too, so "כאל" will not match inside "כאלה".
        """
        if not hasattr(cls, "_brand_re_cache"):
            cls._brand_re_cache = {
                brand: re.compile(r"\b" + re.escape(brand) + r"\b")
                for brand in cls.BRAND_DOMAINS
            }
        return cls._brand_re_cache

    def _brand_claimed_by_a_domain(self, brand: str, official_domains: list,
                                   domain: str, urls: list) -> bool:
        """
        For an ambiguous brand: does a domain in this message carry the
        brand name without being the brand's own?

        A word alone says nothing - "our partner programme" is English,
        not a claim. A domain wearing the name is the claim, and is also
        the attack itself. A Hebrew key has no Latin token and so never
        qualifies here; it stays recognition-only.
        """
        token = re.sub(r"[^a-z0-9]+", "", brand.lower())
        if not token:
            return False
        hosts = [domain] + [self._url_domain(u) for u in urls]
        for host in hosts:
            if not host or token not in re.sub(r"[^a-z0-9]+", "", host):
                continue
            if any(self._domain_matches(host, off) for off in official_domains):
                continue
            return True
        return False

    def _check_brand_impersonation(self, sender: str, subject: str,
                                   content: str) -> tuple[str, str, str] | None:
        """
        Returns (brand, sender domain, where) if the message impersonates
        a known brand, else None. "where" is "subject" or "body" and
        decides the score - a body match counts for less. A sender on the
        official domain is not impersonating anyone.
        """
        domain = self._sender_domain(sender)
        if not domain:
            return None

        # A recognised company's own domain is not impersonating anybody:
        # nobody but LinkedIn can send from linkedin.com. Without this the
        # check matched whichever brand name appeared in a company's own
        # mail. Free mailboxes are excluded inside is_trusted_sender.
        if self.is_trusted_sender(sender):
            return None

        patterns = self._brand_patterns()
        subject_l = (subject or "").lower()
        body_l = (content or "").lower()
        urls = self._URL_RE.findall(content or "")

        # -- Step 1: the subject line ---------------------------------
        # An attacker puts the brand in the subject to build trust from
        # the first line. The strong signal, so it carries the full score.
        for brand, official_domains in self.BRAND_DOMAINS.items():
            if not patterns[brand].search(subject_l):
                continue
            if any(self._domain_matches(domain, off) for off in official_domains):
                return None          # נשלח מהדומיין הרשמי — תקין
            if (brand in self.AMBIGUOUS_BRANDS
                    and not self._brand_claimed_by_a_domain(
                        brand, official_domains, domain, urls)):
                continue             # מילה רגילה, לא שם מותג
            return brand, domain, "subject"

        # -- Step 2: the body, under stricter conditions ---------------
        # Unconditionally, this flagged a genuine Malwarebytes message
        # mentioning "Google Chrome" as impersonating Google - newsletters
        # name brands all the time. Skipped entirely, a message naming
        # "Microsoft 365" only in the body and linking to
        # office365-alert.net scored 19.
        #
        # The condition: there is a link, and none resolves to the brand's
        # own domain. A newsletter links to the brand or to itself; a
        # forger links to a domain they control.
        if not urls:
            return None

        for brand, official_domains in self.BRAND_DOMAINS.items():
            if not patterns[brand].search(body_l):
                continue
            if any(self._domain_matches(domain, off) for off in official_domains):
                return None          # נשלח מהדומיין הרשמי — תקין
            if (brand in self.AMBIGUOUS_BRANDS
                    and not self._brand_claimed_by_a_domain(
                        brand, official_domains, domain, urls)):
                continue             # מילה רגילה, לא שם מותג
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

    # Phrases that give away marketing mail or a service notice. Not
    # evidence of legitimacy on their own, but evidence the message
    # belongs to a different category than phishing.
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
    # The full list cannot be used: "click here", "today only" and
    # "limited time" appear in nearly all legitimate marketing mail, so
    # every advertisement was rejected. Those are signs of spam, not of
    # phishing. What remains marks an attack rather than a sale - a
    # request for credentials, a threat, or a prize as bait.
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

        המודל אומן על נתונים שבהם ספאם תויג יחד עם פישינג, ולכן פרסומת
        של Temu מקבלת ממנו 99.99 בדיוק כמו בקשה לפרטי אשראי. אבל LURA
        מזהה פישינג, לא ספאם — סימון פרסומת כ"סכנה" שוחק את האמון בכל
        שאר ההתרעות.

        נדרשת ראיה חיובית לקטגוריה השיווקית, ולא שקט של מנוע החוקים —
        דווקא פישינג מנוסח היטב משתיק אותם. בנוסף נדרש שלא תופיע בקשת
        אישורים או איום על החשבון, כי "זכית בפרס, לחץ כאן" הוא פישינג
        שעוטה מעטה של פרסומת.
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

        The largest category the system got wrong. Such a message carries
        many links and words like "order" and "account", so the rules give
        it a middling score, and BERT flags it nearly every time because
        the training data holds almost no legitimate commercial mail. Both
        engines err in the same direction, so their agreement proves
        nothing.

        What separates a real order confirmation from a forged one is
        where the links go: a real shop links to itself, an attacker has
        to lead somewhere they control.

        Four conditions, all required:
          1. The sender is a recognised company. Without this a forgery
             from iherb-delivery.info linking back to itself passes
             everything else - the attacker controls both ends. "The link
             points at the sender" shows consistency, not trust.
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
        Do two domains belong to the same organisation? Shops send from
        adjacent infrastructure - iherb.com against e.iherb.com - so an
        exact match would reject genuine order confirmations.
        """
        core = lambda d: d.rsplit(".", 2)[0].split(".")[-1]
        return bool(core(a)) and core(a) == core(b)

    def is_trusted_sender(self, sender: str) -> bool:
        """
        האם המייל נשלח באמת מדומיין של חברה מוכרת.

        ראיה חיובית ללגיטימיות, לא רק היעדר ראיה להתחזות: תוקף יכול
        לכתוב מה שירצה בגוף המייל, אבל אינו יכול לשלוח מ-
        accounts.google.com. שקט של מנוע החוקים אינו אומר דבר — הוא
        שותק גם על מייל בלי שולח כלל.

        משמש להנמכת ציון BERT, שמסמן ב-99.99 גם איפוס סיסמה שהמשתמש
        עצמו ביקש, כי כמעט אין בנתוני האימון דואר לגיטימי בענייני
        חשבון ואבטחה.
        """
        domain = self._sender_domain(sender)
        if not domain:
            return False

        # A free provider is not "the company itself". gmail.com is in
        # BRAND_DOMAINS as Google's, but unlike accounts.google.com anyone
        # can open one - and a free mailbox is among the commonest
        # channels phishing arrives through. Without this, every phishing
        # mail sent from Gmail had the model's score cut fourfold.
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

        # Check 9: impersonating a known brand - presents itself as a
        # known organisation, comes from a domain that is not theirs.
        # Strongest signal here, so the highest score.
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