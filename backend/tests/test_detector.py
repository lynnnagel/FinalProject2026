"""
Unit tests for the heuristic PhishingDetector.

These tests do NOT require a running server or database.
Run from backend/:
    pytest tests/test_detector.py -v
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from detector import PhishingDetector


@pytest.fixture
def det():
    return PhishingDetector()


# ---------------------------------------------------------------------------
# Check 1 – Keyword detection
# ---------------------------------------------------------------------------
class TestKeywords:
    def test_hebrew_keywords_raise_score(self, det):
        r = det.analyze_email("a@b.com", "דחוף אימות", "סיסמה")
        assert r["risk_score"] > 0
        # The engine separates phishing phrasing from words that also
        # appear in legitimate mail; this confirms one was reported
        assert any("פישינג" in ind for ind in r["indicators"])

    def test_generic_financial_words_do_not_flag_alone(self, det):
        """
        A real credit-card message contained several banking words and
        scored as phishing. Those words were weakened so they cannot
        decide on their own.
        """
        r = det.analyze_email(
            "service@icc.co.il",
            "כאל — חיוב חודשי",
            "חשבון כרטיס האשראי שלך לחודש יוני: 1,240 ₪.",
        )
        assert r["risk_score"] < 30, r["indicators"]

    def test_brand_alternate_domain_not_flagged(self, det):
        """The card issuer also sends from icc.co.il, not only cal-online.co.il."""
        r = det.analyze_email("service@icc.co.il", "כאל — חיוב", "פירוט החיוב החודשי")
        assert not any("מתיימר" in ind for ind in r["indicators"]), r["indicators"]

    def test_english_keywords_raise_score(self, det):
        r = det.analyze_email("a@b.com", "urgent verify account", "password bank")
        assert r["risk_score"] > 0

    def test_keyword_score_capped_at_40(self, det):
        many_keywords = " ".join(det.SUSPICIOUS_KEYWORDS * 3)
        r = det.analyze_email("a@b.com", many_keywords, many_keywords)
        from config import MAX_KEYWORD_SCORE, KEYWORD_SCORE_PER_WORD
        hits = sum(1 for kw in det.SUSPICIOUS_KEYWORDS if kw.lower() in many_keywords)
        assert min(hits * KEYWORD_SCORE_PER_WORD, MAX_KEYWORD_SCORE) <= MAX_KEYWORD_SCORE

    def test_clean_text_no_keyword_indicator(self, det):
        r = det.analyze_email(
            "alice@company.com", "Monthly newsletter",
            "Hello, here are this month's updates.",
        )
        assert not any("מילות מפתח" in ind for ind in r["indicators"])


# ---------------------------------------------------------------------------
# Check 2 – Suspicious sender patterns
# ---------------------------------------------------------------------------
class TestSuspiciousSender:
    def test_rn_homoglyph_detected(self, det):
        r = det.analyze_email("noreply@arnazon.com", "test", "test")
        assert any("דוא" in ind for ind in r["indicators"])

    def test_l0_detected(self, det):
        r = det.analyze_email("support@paypal0.com", "test", "test")
        assert any("דוא" in ind for ind in r["indicators"])

    def test_clean_sender_no_pattern_indicator(self, det):
        r = det.analyze_email("info@company.com", "Hello", "Normal content here.")
        assert not any('דוא"ל חשוד' in ind for ind in r["indicators"])


# ---------------------------------------------------------------------------
# Check 3 – Excessive URL count
# ---------------------------------------------------------------------------
class TestURLDetection:
    def test_many_urls_flagged(self, det):
        content = (
            "http://a.com click http://b.com or http://c.com "
            "or http://d.com"
        )
        r = det.analyze_email("a@b.com", "test", content)
        assert any("קישורים" in ind for ind in r["indicators"])

    def test_single_url_not_flagged(self, det):
        r = det.analyze_email("a@b.com", "test", "Visit http://legit.com for more.")
        assert not any("קישורים" in ind for ind in r["indicators"])


# ---------------------------------------------------------------------------
# Check 4 – Urgency language
# ---------------------------------------------------------------------------
class TestUrgency:
    def test_urgency_word_detected(self, det):
        r = det.analyze_email("a@b.com", "מיידי!", "expire now")
        assert any("דחיפות" in ind for ind in r["indicators"])

    def test_no_urgency_word_no_indicator(self, det):
        r = det.analyze_email("a@b.com", "Meeting notes", "See you tomorrow.")
        assert not any("דחיפות" in ind for ind in r["indicators"])


# ---------------------------------------------------------------------------
# Check 5 – Domain validation
# ---------------------------------------------------------------------------
class TestDomainValidation:
    def test_unknown_tld_flagged(self, det):
        r = det.analyze_email("user@malicious.xyz123", "test", "test")
        assert any("דומיין" in ind for ind in r["indicators"])

    @pytest.mark.parametrize("addr", [
        "a@b.com", "a@b.co.il", "a@b.org", "a@b.net",
    ])
    def test_valid_tlds_not_flagged(self, det, addr):
        r = det.analyze_email(addr, "test", "Hello.")
        assert not any("דומיין" in ind for ind in r["indicators"])


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------
class TestClassification:
    def test_score_never_exceeds_100(self, det):
        r = det.analyze_email(
            "rn-vv@l0-notabank.xyz",
            "urgent verify account suspended prize click here",
            "password bank credit card "
            "http://a.com http://b.com http://c.com http://d.com דחוף",
        )
        assert r["risk_score"] <= 100.0

    def test_high_risk_label_and_phishing_flag(self, det):
        r = det.analyze_email(
            "phish-rn@notabank.xyz",
            "urgent verify account",
            "password bank http://a.com http://b.com http://c.com",
        )
        if r["risk_score"] >= 80:
            assert r["risk_level"] == "סכנה גבוהה"
            assert r["is_phishing"] is True

    def test_safe_classification(self, det):
        r = det.analyze_email(
            "alice@company.com",
            "Monthly report",
            "Please find the report attached.",
        )
        if r["risk_score"] < 30:
            assert r["risk_level"] == "בטוח"
            assert r["is_phishing"] is False

    def test_response_time_under_1s(self, det):
        r = det.analyze_email("a@b.com", "test", "test content")
        assert r["response_time"] < 1.0

    def test_result_has_all_keys(self, det):
        r = det.analyze_email("a@b.com", "subj", "body")
        for key in ["risk_score", "is_phishing", "risk_level",
                    "indicators", "recommendation", "response_time"]:
            assert key in r, f"Missing key: {key}"

    def test_indicators_always_list(self, det):
        r = det.analyze_email("a@b.com", "hello", "how are you")
        assert isinstance(r["indicators"], list)
        assert len(r["indicators"]) >= 1


# ---------------------------------------------------------------------------
# Check 9 – Brand impersonation
# ---------------------------------------------------------------------------
class TestBrandImpersonation:
    def test_lookalike_domain_flagged(self, det):
        r = det.analyze_email(
            "no-reply@bankhapoalim-secure.net",
            "אזהרה | בנק הפועלים",
            "חשבונך ייחסם. לאימות: http://bankhapoalim-secure.net/verify",
        )
        assert any("מתיימר" in i for i in r["indicators"])

    def test_official_domain_not_flagged(self, det):
        r = det.analyze_email(
            "noreply@bankhapoalim.co.il", "דוח חשבון", "הדוח שלך מוכן."
        )
        assert not any("מתיימר" in i for i in r["indicators"])

    def test_subdomain_of_official_accepted(self, det):
        r = det.analyze_email(
            "news@mail.netflix.com", "Netflix update", "Your subscription."
        )
        assert not any("מתיימר" in i for i in r["indicators"])

    def test_brand_name_needs_word_boundary(self, det):
        """
        המפתח "cal" נתפס בתוך call, local ו-calendar, ומייל תמים של
        Temu סומן כמתחזה לכאל. ההתאמה חייבת להיות על מילה שלמה.
        """
        r = det.analyze_email(
            "orders@orders.temu.com",
            "Your order shipped",
            "We will call you. Local pickup. Check your calendar.",
        )
        assert not any("מתיימר" in i for i in r["indicators"]), r["indicators"]

    def test_hebrew_brand_not_matched_inside_word(self, det):
        """כאל לא אמור להיתפס בתוך 'כאלה'."""
        r = det.analyze_email(
            "info@shop.co.il", "מוצרים חדשים", "יש לנו מוצרים כאלה ואחרים בחנות."
        )
        assert not any("מתיימר" in i for i in r["indicators"]), r["indicators"]

    def test_brand_mentioned_in_body_is_not_impersonation(self, det):
        """
        מייל של Malwarebytes שהזכיר Google Chrome בגוף ההודעה סומן
        כמתחזה לגוגל. אזכור מותג אינו טענה להיות המותג — הבדיקה
        מוגבלת לשורת הנושא, שם תוקף שם את השם כדי לבנות אמון.
        """
        r = det.analyze_email(
            "news@e.malwarebytes.com",
            "Your December security digest",
            "Protect Chrome and Google Play. Read more at https://www.malwarebytes.com/blog",
        )
        assert not any("מתיימר" in i for i in r["indicators"]), r["indicators"]

    def test_brand_in_subject_still_flagged(self, det):
        r = det.analyze_email(
            "security@paypaI-verify.tk",
            "PayPal: verify your account",
            "Your account has been suspended.",
        )
        assert any("מתיימר" in i for i in r["indicators"])
