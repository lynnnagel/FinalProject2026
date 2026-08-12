"""
Integration tests for LURA API endpoints.

Run from backend/:
    pytest tests/ -v
"""


# ---------------------------------------------------------------------------
# /scan
# ---------------------------------------------------------------------------
class TestScanEndpoint:
    def test_phishing_email_high_risk(self, client, phishing_email):
        r = client.post("/scan", json=phishing_email)
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] >= 70
        assert data["is_phishing"] is True
        assert data["risk_level"] in ["סכנה גבוהה", "חשוד"]
        assert isinstance(data["indicators"], list)
        assert len(data["indicators"]) > 0
        assert isinstance(data["response_time"], float)
        assert data["response_time"] < 2.0

    def test_safe_email_low_risk(self, client, safe_email):
        r = client.post("/scan", json=safe_email)
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] < 70
        assert data["is_phishing"] is False

    def test_first_scan_creates_user(self, client, safe_email, auth_headers):
        """Scanning for the first time should auto-create the user."""
        client.post("/scan", json=safe_email)
        r = client.get(f"/stats/{safe_email['user_email']}", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["total_scanned"] == 1

    def test_phishing_increments_blocked_counter(self, client, phishing_email, auth_headers):
        client.post("/scan", json=phishing_email)
        stats = client.get(
            f"/stats/{phishing_email['user_email']}", headers=auth_headers
        ).json()
        assert stats["phishing_blocked"] >= 1

    def test_multiple_scans_increment_total(self, client, auth_headers):
        for i in range(3):
            client.post("/scan", json={
                "user_email": "test@example.com",
                "sender": f"sender{i}@company.com",
                "subject": f"נושא מספר {i}",
                "content": "תוכן רגיל",
            })
        stats = client.get("/stats/test@example.com", headers=auth_headers).json()
        assert stats["total_scanned"] == 3

    def test_invalid_email_returns_422(self, client):
        r = client.post("/scan", json={
            "user_email": "not-an-email",
            "sender": "a@b.com",
            "subject": "hi",
            "content": "hello",
        })
        assert r.status_code == 422

    def test_missing_field_returns_422(self, client):
        r = client.post("/scan", json={"user_email": "test@example.com"})
        assert r.status_code == 422

    def test_response_under_2_seconds(self, client, phishing_email):
        r = client.post("/scan", json=phishing_email)
        assert r.json()["response_time"] < 2.0

    def test_response_contains_all_required_fields(self, client, safe_email):
        r = client.post("/scan", json=safe_email)
        data = r.json()
        for field in ["risk_score", "is_phishing", "risk_level",
                      "indicators", "recommendation", "response_time"]:
            assert field in data, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# /stats
# ---------------------------------------------------------------------------
class TestStatsEndpoint:
    def test_requires_authentication(self, client):
        """סטטיסטיקות הן נתונים אישיים – ללא טוקן אין גישה."""
        r = client.get("/stats/nobody@example.com")
        assert r.status_code == 401

    def test_other_user_stats_forbidden(self, client, auth_headers):
        """משתמש מחובר לא יכול לקרוא את הסטטיסטיקות של מישהו אחר."""
        r = client.get("/stats/someone-else@example.com", headers=auth_headers)
        assert r.status_code == 403

    def test_returns_correct_structure(self, client, safe_email, auth_headers):
        client.post("/scan", json=safe_email)
        r = client.get(f"/stats/{safe_email['user_email']}", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        for field in ["total_scanned", "phishing_blocked",
                      "risk_score", "daily_active", "recent_alerts"]:
            assert field in data, f"Missing field: {field}"

    def test_risk_score_between_0_and_100(self, client, phishing_email, auth_headers):
        client.post("/scan", json=phishing_email)
        data = client.get(
            f"/stats/{phishing_email['user_email']}", headers=auth_headers
        ).json()
        assert 0.0 <= data["risk_score"] <= 100.0


# ---------------------------------------------------------------------------
# /guardian
# ---------------------------------------------------------------------------
class TestGuardianEndpoint:
    def test_connect_creates_link(self, client, safe_email, parent_headers):
        client.post("/scan", json=safe_email)
        r = client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        }, headers=parent_headers)
        assert r.status_code == 200
        assert "הופעל" in r.json()["message"]

    def test_connect_unknown_child_creates_account(self, client, parent_headers):
        """
        קישור לכתובת שאינה במערכת יוצר עבורה חשבון, כדי שסריקות
        עתידיות מאותה תיבה ישויכו אליו.
        """
        r = client.post("/guardian/connect", json={
            "child_email": "ghost@example.com",
            "parent_email": "parent@example.com",
        }, headers=parent_headers)
        assert r.status_code == 200
        assert r.json()["child"] == "ghost@example.com"

    def test_connect_requires_authentication(self, client, safe_email):
        """ללא טוקן אי אפשר להגדיר מפקח – אחרת כל אחד היה מנטר תיבה זרה."""
        client.post("/scan", json=safe_email)
        r = client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "attacker@evil.com",
        })
        assert r.status_code == 401

    def test_parent_taken_from_token_not_body(self, client, safe_email, parent_headers):
        """שדה parent_email בגוף הבקשה מתעלמים ממנו – המפקח נלקח מהטוקן."""
        client.post("/scan", json=safe_email)
        r = client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "attacker@evil.com",
        }, headers=parent_headers)
        assert r.status_code == 200
        assert r.json()["guardian"] == "parent@example.com"

    def test_cannot_guard_self(self, client, parent_headers):
        r = client.post("/guardian/connect", json={
            "child_email": "parent@example.com",
            "parent_email": "parent@example.com",
        }, headers=parent_headers)
        assert r.status_code == 400

    def test_other_user_dashboard_forbidden(self, client, parent_headers):
        r = client.get("/guardian/someone-else@example.com", headers=parent_headers)
        assert r.status_code == 403

    def test_guardian_data_no_children_returns_404(self, client, safe_email, parent_headers):
        client.post("/scan", json=safe_email)
        # parent without children
        client.post("/scan", json={**safe_email, "user_email": "parent@example.com"})
        r = client.get("/guardian/parent@example.com", headers=parent_headers)
        assert r.status_code == 404

    def test_guardian_data_correct_structure(self, client, safe_email, parent_headers):
        client.post("/scan", json=safe_email)
        client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        }, headers=parent_headers)
        r = client.get("/guardian/parent@example.com", headers=parent_headers)
        assert r.status_code == 200
        data = r.json()
        for field in ["child_name", "child_email", "risk_score",
                      "recent_alerts", "phishing_blocked_today"]:
            assert field in data, f"Missing field: {field}"

    def test_disconnect_requires_being_the_guardian(self, client, safe_email,
                                                    parent_headers, make_user):
        """מי שאינו המפקח בפועל לא יכול לנתק את הקישור."""
        client.post("/scan", json=safe_email)
        client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        }, headers=parent_headers)

        stranger = make_user("stranger@example.com")
        r = client.post("/guardian/disconnect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        }, headers=stranger)
        assert r.status_code == 404

        r = client.post("/guardian/disconnect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        }, headers=parent_headers)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# /metrics
# ---------------------------------------------------------------------------
class TestMetricsEndpoint:
    def test_returns_200(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200

    def test_contains_targets(self, client):
        data = client.get("/metrics").json()
        assert "targets" in data
        assert "total_emails_scanned" in data


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_root_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "version" in r.json()


# ---------------------------------------------------------------------------
# /auth
# ---------------------------------------------------------------------------
class TestAuthEndpoint:
    def test_register_and_login(self, client):
        r = client.post("/auth/register",
                        json={"email": "new@example.com", "password": "goodpass123"})
        assert r.status_code == 200
        assert "token" in r.json()

        r = client.post("/auth/login",
                        json={"email": "new@example.com", "password": "goodpass123"})
        assert r.status_code == 200

    def test_short_password_rejected(self, client):
        r = client.post("/auth/register",
                        json={"email": "weak@example.com", "password": "123"})
        assert r.status_code == 422

    def test_wrong_password_rejected(self, client, make_user):
        make_user("user@example.com", password="correctpass1")
        r = client.post("/auth/login",
                        json={"email": "user@example.com", "password": "wrongpass1"})
        assert r.status_code == 401

    def test_reset_requires_token(self, client, make_user):
        """
        רגרסיה: בעבר אפשר היה לשלוח {email, new_password} ולהחליף סיסמה
        של כל חשבון. הסכמה כבר לא מקבלת email, ולכן הבקשה נדחית.
        """
        make_user("victim@example.com", password="originalpass1")
        r = client.post("/auth/reset-password",
                        json={"email": "victim@example.com", "new_password": "hacked123"})
        assert r.status_code == 422

        # הסיסמה המקורית עדיין תקפה
        r = client.post("/auth/login",
                        json={"email": "victim@example.com", "password": "originalpass1"})
        assert r.status_code == 200

    def test_reset_rejects_invalid_token(self, client):
        r = client.post("/auth/reset-password",
                        json={"token": "not-a-real-token", "new_password": "newpass123"})
        assert r.status_code == 400

    def test_reset_with_valid_token(self, client, make_user):
        from API.auth import create_reset_token
        make_user("reset@example.com", password="originalpass1")

        token = create_reset_token("reset@example.com")
        r = client.post("/auth/reset-password",
                        json={"token": token, "new_password": "brandnewpass2"})
        assert r.status_code == 200

        r = client.post("/auth/login",
                        json={"email": "reset@example.com", "password": "brandnewpass2"})
        assert r.status_code == 200

    def test_reset_token_is_not_an_auth_token(self, client, make_user):
        """אסימון מהמייל לא אמור לשמש כהזדהות מלאה למערכת."""
        from API.auth import create_reset_token
        make_user("sep@example.com")
        token = create_reset_token("sep@example.com")
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_forgot_password_does_not_leak_registered_emails(self, client, make_user):
        """אותה תשובה לכתובת רשומה ולא רשומה – כדי לא לחשוף מי רשום."""
        make_user("known@example.com")
        a = client.post("/auth/forgot-password", json={"email": "known@example.com"})
        b = client.post("/auth/forgot-password", json={"email": "unknown@example.com"})
        assert a.status_code == b.status_code == 200
        assert a.json() == b.json()

    def test_me_requires_token(self, client):
        assert client.get("/auth/me").status_code == 401
