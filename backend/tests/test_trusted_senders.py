"""
Tests for the known-senders list.

The feature lets a user influence the score, so what matters here is
not that it works but that it **cannot be used to silence evidence**. A
user may say "I know this address"; they may not say "ignore what you
found".
"""


class TestTrustedSendersAPI:
    def test_requires_authentication(self, client):
        assert client.get("/trusted-senders").status_code == 401
        assert client.post("/trusted-senders", json={"value": "a@b.com"}).status_code == 401

    def test_add_and_list(self, client, auth_headers):
        r = client.post("/trusted-senders", json={"value": "Office@Dance-Studio.com"},
                        headers=auth_headers)
        assert r.status_code == 200, r.text
        assert r.json()["value"] == "office@dance-studio.com"   # normalised
        assert r.json()["is_domain"] is False

        rows = client.get("/trusted-senders", headers=auth_headers).json()["senders"]
        assert [s["value"] for s in rows] == ["office@dance-studio.com"]

    def test_domain_entry(self, client, auth_headers):
        r = client.post("/trusted-senders", json={"value": "dance-studio.com"},
                        headers=auth_headers)
        assert r.json()["is_domain"] is True

    def test_adding_twice_is_idempotent(self, client, auth_headers):
        for _ in range(3):
            client.post("/trusted-senders", json={"value": "a@b.com"},
                        headers=auth_headers)
        rows = client.get("/trusted-senders", headers=auth_headers).json()["senders"]
        assert len(rows) == 1

    def test_rejects_malformed_values(self, client, auth_headers):
        for bad in ["not an email", "@@@", "a@b", "nodots"]:
            r = client.post("/trusted-senders", json={"value": bad},
                            headers=auth_headers)
            assert r.status_code in (400, 422), f"{bad} was accepted"

    def test_remove(self, client, auth_headers):
        client.post("/trusted-senders", json={"value": "a@b.com"}, headers=auth_headers)
        assert client.delete("/trusted-senders/a@b.com",
                             headers=auth_headers).status_code == 200
        assert client.get("/trusted-senders",
                          headers=auth_headers).json()["senders"] == []

    def test_remove_unknown_returns_404(self, client, auth_headers):
        assert client.delete("/trusted-senders/ghost@b.com",
                             headers=auth_headers).status_code == 404

    def test_list_is_per_user(self, client, auth_headers, parent_headers):
        client.post("/trusted-senders", json={"value": "mine@b.com"},
                    headers=auth_headers)
        other = client.get("/trusted-senders", headers=parent_headers).json()
        assert other["senders"] == [], "one user's list leaked to another"

    def test_one_user_cannot_delete_another_users_entry(
        self, client, auth_headers, parent_headers
    ):
        client.post("/trusted-senders", json={"value": "mine@b.com"},
                    headers=auth_headers)
        assert client.delete("/trusted-senders/mine@b.com",
                             headers=parent_headers).status_code == 404
        rows = client.get("/trusted-senders", headers=auth_headers).json()["senders"]
        assert len(rows) == 1, "one user's entry was deleted by another"


class TestTrustedSendersScoring:
    """What personal trust does change, and what it never changes."""

    BENIGN = {
        "user_email": "test@example.com",
        "sender": "office@dance-studio.com",
        "subject": "לוח שיעורים לחודש הבא",
        "content": "שלום, מצורף לוח השיעורים לחודש הבא. נשמח לראותך.",
    }

    IMPERSONATION = {
        "user_email": "test@example.com",
        "sender": "service@bank-leumi-secure.com",
        "subject": "בנק לאומי: חשבונך ייחסם",
        "content": (
            "זוהתה פעילות חריגה בחשבונך. יש לאמת את פרטי הכניסה "
            "תוך 24 שעות. http://bank-leumi-secure.com/verify"
        ),
    }

    def test_marking_a_sender_lowers_its_score(self, client, auth_headers):
        before = client.post("/scan", json=self.BENIGN).json()["risk_score"]
        client.post("/trusted-senders", json={"value": self.BENIGN["sender"]},
                    headers=auth_headers)
        after = client.post("/scan", json=self.BENIGN).json()["risk_score"]
        assert after <= before

    def test_stored_result_is_recomputed_after_marking(self, client, auth_headers):
        """
        בלי ביטול המטמון, הסימון לא היה משנה דבר בתיבה: התוצאה כבר
        שמורה, והסריקה הבאה הייתה מחזירה אותה כמות שהיא.
        """
        client.post("/scan", json=self.BENIGN)
        r = client.post("/trusted-senders", json={"value": self.BENIGN["sender"]},
                        headers=auth_headers)
        assert r.json()["rescored"] >= 1, "הסריקות השמורות לא סומנו לחישוב מחדש"

    def test_trust_never_silences_the_rule_engine(self, client, auth_headers):
        """
        הבדיקה החשובה ביותר בקובץ.

        גם אם המשתמש סימן את הכתובת כמוכרת, מייל שמתחזה לבנק ומקשר
        לדומיין מזויף נשאר מסווג כפישינג. האמון מנמיך את ניחוש המודל,
        לא את הראיות.
        """
        client.post("/trusted-senders",
                    json={"value": self.IMPERSONATION["sender"]},
                    headers=auth_headers)
        result = client.post("/scan", json=self.IMPERSONATION).json()
        assert result["is_phishing"] is True, (
            "סימון שולח כמוכר השתיק זיהוי התחזות — משתמש יכול להצהיר "
            "שהוא מכיר כתובת, לא לבטל ראיות"
        )

    def test_trusting_a_domain_covers_its_addresses(self, client, auth_headers):
        client.post("/trusted-senders", json={"value": "dance-studio.com"},
                    headers=auth_headers)
        rows = client.get("/trusted-senders", headers=auth_headers).json()["senders"]
        assert rows[0]["is_domain"] is True

        other_address = {**self.BENIGN, "sender": "teacher@mail.dance-studio.com"}
        assert client.post("/scan", json=other_address).status_code == 200


class TestTrustCannotBeAbused:
    """
    הפיצ'ר נותן למשתמש להנמיך את ציון המודל, וזו נקודת התורפה שלו.
    התוקף אינו צריך לפרוץ לשרת — די לו לשכנע את הקורבן ללחוץ
    "אני מכיר את השולח הזה", ומאותו רגע כל מייל שלו מונמך.

    שלוש שכבות עומדות מולו: אי אפשר לכתוב לרשימה של משתמש אחר, אי
    אפשר לסמן כתובת שיש נגדה ראיות, ואי אפשר לסמן ספק דואר חינמי שלם.
    """

    PHISHING = {
        "user_email": "test@example.com",
        "sender": "service@bank-leumi-secure.com",
        "subject": "בנק לאומי: חשבונך ייחסם",
        "content": (
            "זוהתה פעילות חריגה בחשבונך. יש לאמת את פרטי הכניסה "
            "תוך 24 שעות. http://bank-leumi-secure.com/verify"
        ),
    }

    def test_cannot_trust_a_sender_with_impersonation_evidence(
        self, client, auth_headers
    ):
        """
        אחרי שהמערכת ראתה מאותה כתובת מייל שמתחזה למותג, סימונה
        כמוכרת נדחה — גם אם המשתמש ביקש זאת במפורש. ייתכן מאוד
        שהמשתמש הוא זה שהוטעה, וזו בדיוק מטרת התוקף.
        """
        client.post("/scan", json=self.PHISHING)

        r = client.post("/trusted-senders",
                        json={"value": self.PHISHING["sender"]},
                        headers=auth_headers)
        assert r.status_code == 400, "כתובת מתחזה סומנה כמוכרת"
        assert "התחזות" in r.json()["detail"]

        rows = client.get("/trusted-senders", headers=auth_headers).json()["senders"]
        assert rows == []

    def test_refusal_explains_which_evidence_blocked_it(self, client, auth_headers):
        client.post("/scan", json=self.PHISHING)
        detail = client.post("/trusted-senders",
                             json={"value": self.PHISHING["sender"]},
                             headers=auth_headers).json()["detail"]
        assert len(detail) > 40, "הסירוב חייב לומר מה נמצא, לא רק שנדחה"

    def test_cannot_trust_a_whole_free_provider(self, client, auth_headers):
        """
        אמון ברמת דומיין על gmail.com היה מנטרל את הזיהוי עבור כל
        פישינג שנשלח מ-Gmail — אחד הערוצים הנפוצים ביותר.
        """
        for provider in ["gmail.com", "outlook.com", "hotmail.com"]:
            r = client.post("/trusted-senders", json={"value": provider},
                            headers=auth_headers)
            assert r.status_code == 400, f"{provider} התקבל כדומיין מהימן"

    def test_a_single_free_provider_address_is_allowed(self, client, auth_headers):
        """כתובת בודדת מ-Gmail מותרת — היא נוגעת לאדם אחד ולא לספק."""
        r = client.post("/trusted-senders", json={"value": "my.friend@gmail.com"},
                        headers=auth_headers)
        assert r.status_code == 200, r.text

    def test_trusting_before_evidence_still_does_not_hide_it(
        self, client, auth_headers
    ):
        """
        גם אם הכתובת סומנה לפני שהמערכת ראתה ממנה משהו רע, מייל
        מתחזה ממנה עדיין מסווג כפישינג. הסימון מנמיך את המודל; את
        הראיות הוא לא נוגע בהן.
        """
        assert client.post("/trusted-senders",
                           json={"value": self.PHISHING["sender"]},
                           headers=auth_headers).status_code == 200

        result = client.post("/scan", json=self.PHISHING).json()
        assert result["is_phishing"] is True
