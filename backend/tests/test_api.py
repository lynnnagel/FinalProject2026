"""
Integration tests for LURA API endpoints.

Run from backend/:
    pytest tests/ -v
"""


def reset_token_for(email: str) -> str:
    """
    The reset link a user would receive by mail.

    It is built the same way /auth/forgot-password builds it - from the
    password hash currently stored - because that is what makes the link
    single-use. A token built without it is not the token the system
    issues, and a test using one would prove nothing.
    """
    from API.auth import create_reset_token
    from database import get_db
    from models import User
    from server import app

    # The session the app itself is using. Importing conftest to reach
    # its factory would load a second copy of that module, with a second
    # in-memory database that has no tables in it.
    sessions = app.dependency_overrides[get_db]()
    db = next(sessions)
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None, f"no such user: {email}"
        return create_reset_token(email, user.password_hash)
    finally:
        next(sessions, None)


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
        """Stats are personal data - no token, no access."""
        r = client.get("/stats/nobody@example.com")
        assert r.status_code == 401

    def test_other_user_stats_forbidden(self, client, auth_headers):
        """A signed-in user cannot read someone else's stats."""
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
        Linking an unknown address creates an account for it, so future
        scans from that mailbox attach to it.
        """
        r = client.post("/guardian/connect", json={
            "child_email": "ghost@example.com",
            "parent_email": "parent@example.com",
        }, headers=parent_headers)
        assert r.status_code == 200
        assert r.json()["child"] == "ghost@example.com"

    def test_connect_requires_authentication(self, client, safe_email):
        """No token, no guardian - otherwise anyone could watch a stranger's inbox."""
        client.post("/scan", json=safe_email)
        r = client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "attacker@evil.com",
        })
        assert r.status_code == 401

    def test_parent_taken_from_token_not_body(self, client, safe_email, parent_headers):
        """parent_email in the body is ignored - the guardian comes from the token."""
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

    def test_guardian_data_no_children_returns_empty_state(
        self, client, safe_email, parent_headers
    ):
        """
        A registered guardian who has linked nobody gets an empty
        dashboard, not an error. It used to return 404, and the
        dashboard showed a failure to someone who had done nothing
        wrong.
        """
        client.post("/scan", json=safe_email)
        client.post("/scan", json={**safe_email, "user_email": "parent@example.com"})
        r = client.get("/guardian/parent@example.com", headers=parent_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["child_email"] == ""
        assert body["recent_alerts"] == []
        assert body["phishing_blocked_today"] == 0

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
        """Someone who is not the actual guardian cannot unlink."""
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
        Regression: {email, new_password} once replaced any account's
        password. The schema no longer accepts email.
        """
        make_user("victim@example.com", password="originalpass1")
        r = client.post("/auth/reset-password",
                        json={"email": "victim@example.com", "new_password": "hacked123"})
        assert r.status_code == 422

        # the original password still works
        r = client.post("/auth/login",
                        json={"email": "victim@example.com", "password": "originalpass1"})
        assert r.status_code == 200

    def test_reset_rejects_invalid_token(self, client):
        r = client.post("/auth/reset-password",
                        json={"token": "not-a-real-token", "new_password": "newpass123"})
        assert r.status_code == 400

    def test_reset_with_valid_token(self, client, make_user):
        make_user("reset@example.com", password="originalpass1")

        token = reset_token_for("reset@example.com")
        r = client.post("/auth/reset-password",
                        json={"token": token, "new_password": "brandnewpass2"})
        assert r.status_code == 200

        r = client.post("/auth/login",
                        json={"email": "reset@example.com", "password": "brandnewpass2"})
        assert r.status_code == 200

    def test_reset_token_works_only_once(self, client, make_user):
        """
        The link arrives by mail, so anyone who sees it can try to use
        it again. After one reset it must be dead, even inside the 30
        minutes it is otherwise still valid for.
        """
        make_user("once@example.com", password="originalpass1")
        token = reset_token_for("once@example.com")

        first = client.post("/auth/reset-password",
                            json={"token": token, "new_password": "firstchange1"})
        assert first.status_code == 200

        second = client.post("/auth/reset-password",
                             json={"token": token, "new_password": "attacker999"})
        assert second.status_code == 400

        # the password from the first reset is the one that stands
        assert client.post("/auth/login",
                           json={"email": "once@example.com",
                                 "password": "firstchange1"}).status_code == 200
        assert client.post("/auth/login",
                           json={"email": "once@example.com",
                                 "password": "attacker999"}).status_code == 401

    def test_reset_links_die_when_the_password_changes(self, client, make_user):
        """
        Two links issued before a password change: both must die once
        the first is used, not only the one that was used.
        """
        make_user("two@example.com", password="originalpass1")
        first_link = reset_token_for("two@example.com")
        second_link = reset_token_for("two@example.com")

        assert client.post("/auth/reset-password",
                           json={"token": first_link,
                                 "new_password": "changedonce1"}).status_code == 200
        assert client.post("/auth/reset-password",
                           json={"token": second_link,
                                 "new_password": "changedtwice2"}).status_code == 400

    def test_reset_token_is_not_an_auth_token(self, client, make_user):
        """A token from mail must not work as a full login."""
        make_user("sep@example.com")
        token = reset_token_for("sep@example.com")
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_forgot_password_does_not_leak_registered_emails(self, client, make_user):
        """Same answer for a registered and an unknown address."""
        make_user("known@example.com")
        a = client.post("/auth/forgot-password", json={"email": "known@example.com"})
        b = client.post("/auth/forgot-password", json={"email": "unknown@example.com"})
        assert a.status_code == b.status_code == 200
        assert a.json() == b.json()

    def test_me_requires_token(self, client):
        assert client.get("/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# Guardian mode - the whole flow
#
# This spans three pieces written separately: the scan that creates an
# alert, the record kept for the guardian, and the dashboard that reads
# it. These walk the whole chain, because every failure they cover lived
# in a seam between two of them.
# ---------------------------------------------------------------------------
class TestGuardianFlow:
    @staticmethod
    def _connect(client, parent_headers, child_email):
        r = client.post(
            "/guardian/connect",
            json={"child_email": child_email, "parent_email": "ignored@example.com"},
            headers=parent_headers,
        )
        assert r.status_code == 200, r.text

    def test_phishing_reaches_guardian_dashboard(
        self, client, phishing_email, parent_headers
    ):
        """מייל פישינג אצל המנוטר מופיע בלוח הבקרה של המפקח."""
        self._connect(client, parent_headers, phishing_email["user_email"])
        assert client.post("/scan", json=phishing_email).json()["is_phishing"] is True

        data = client.get("/guardian/parent@example.com", headers=parent_headers).json()
        assert data["child_email"] == phishing_email["user_email"]
        assert data["phishing_blocked_today"] == 1
        assert len(data["recent_alerts"]) == 1

    def test_alert_names_the_monitored_user(
        self, client, phishing_email, parent_headers
    ):
        """
        The alert on the dashboard names the monitored user.

        Two alert records are created per detection - one for the
        monitored user and one for the guardian - and only the
        guardian's says whose message it was. The dashboard used to pull
        the monitored user's, so the guardian's records were written and
        never read.
        """
        self._connect(client, parent_headers, phishing_email["user_email"])
        client.post("/scan", json=phishing_email)

        alerts = client.get(
            "/guardian/parent@example.com", headers=parent_headers
        ).json()["recent_alerts"]
        assert alerts, "לא נוצרה התראה עבור המפקח"
        assert phishing_email["sender"] in alerts[0]["message"]
        assert "קיבל מייל פישינג" in alerts[0]["message"]

    def test_rescanning_does_not_duplicate_the_alert(
        self, client, phishing_email, parent_headers
    ):
        """
        סריקה חוזרת של אותו מייל אינה מייצרת התראה שנייה.

        תוצאות סריקה נשמרות במסד, אך שינוי בנוסחת הניקוד מחשב אותן
        מחדש. בלי התניה על זיהוי *ראשון*, כל שינוי כזה היה מציף את
        המפקח בהתראות על דואר שהמנוטר קיבל לפני שבועות.
        """
        self._connect(client, parent_headers, phishing_email["user_email"])
        for _ in range(3):
            client.post("/scan", json=phishing_email)

        alerts = client.get(
            "/guardian/parent@example.com", headers=parent_headers
        ).json()["recent_alerts"]
        assert len(alerts) == 1, f"נוצרו {len(alerts)} התראות במקום אחת"

    def test_rescanning_does_not_inflate_counters(
        self, client, phishing_email, auth_headers
    ):
        """אותו מייל נספר פעם אחת, גם אם נסרק שוב ושוב."""
        for _ in range(3):
            client.post("/scan", json=phishing_email)

        stats = client.get(
            f"/stats/{phishing_email['user_email']}", headers=auth_headers
        ).json()
        assert stats["total_scanned"] == 1
        assert stats["phishing_blocked"] == 1

    def test_safe_email_creates_no_alert(self, client, safe_email, parent_headers):
        self._connect(client, parent_headers, safe_email["user_email"])
        client.post("/scan", json=safe_email)

        data = client.get("/guardian/parent@example.com", headers=parent_headers).json()
        assert data["recent_alerts"] == []
        assert data["phishing_blocked_today"] == 0

    def test_disconnect_stops_new_alerts(
        self, client, phishing_email, parent_headers
    ):
        self._connect(client, parent_headers, phishing_email["user_email"])
        r = client.post(
            "/guardian/disconnect",
            json={"child_email": phishing_email["user_email"],
                  "parent_email": "ignored@example.com"},
            headers=parent_headers,
        )
        assert r.status_code == 200, r.text

        client.post("/scan", json=phishing_email)
        data = client.get("/guardian/parent@example.com", headers=parent_headers).json()
        assert data["recent_alerts"] == []

    def test_stranger_cannot_disconnect(self, client, phishing_email,
                                        parent_headers, make_user):
        """רק המפקח שמוגדר בפועל יכול לנתק את הקישור."""
        self._connect(client, parent_headers, phishing_email["user_email"])
        stranger = make_user("stranger@example.com")

        r = client.post(
            "/guardian/disconnect",
            json={"child_email": phishing_email["user_email"],
                  "parent_email": "stranger@example.com"},
            headers=stranger,
        )
        assert r.status_code == 404
