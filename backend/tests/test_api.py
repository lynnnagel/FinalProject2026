"""
Integration tests for PhishGuard API endpoints.

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

    def test_first_scan_creates_user(self, client, safe_email):
        """Scanning for the first time should auto-create the user."""
        client.post("/scan", json=safe_email)
        r = client.get(f"/stats/{safe_email['user_email']}")
        assert r.status_code == 200
        assert r.json()["total_scanned"] == 1

    def test_phishing_increments_blocked_counter(self, client, phishing_email):
        client.post("/scan", json=phishing_email)
        stats = client.get(f"/stats/{phishing_email['user_email']}").json()
        assert stats["phishing_blocked"] >= 1

    def test_multiple_scans_increment_total(self, client):
        for i in range(3):
            client.post("/scan", json={
                "user_email": "test@example.com",
                "sender": f"sender{i}@company.com",
                "subject": f"נושא מספר {i}",
                "content": "תוכן רגיל",
            })
        stats = client.get("/stats/test@example.com").json()
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
    def test_nonexistent_user_returns_404(self, client):
        r = client.get("/stats/nobody@example.com")
        assert r.status_code == 404

    def test_returns_correct_structure(self, client, safe_email):
        client.post("/scan", json=safe_email)
        r = client.get(f"/stats/{safe_email['user_email']}")
        assert r.status_code == 200
        data = r.json()
        for field in ["total_scanned", "phishing_blocked",
                      "risk_score", "daily_active", "recent_alerts"]:
            assert field in data, f"Missing field: {field}"

    def test_risk_score_between_0_and_100(self, client, phishing_email):
        client.post("/scan", json=phishing_email)
        data = client.get(f"/stats/{phishing_email['user_email']}").json()
        assert 0.0 <= data["risk_score"] <= 100.0


# ---------------------------------------------------------------------------
# /guardian
# ---------------------------------------------------------------------------
class TestGuardianEndpoint:
    def test_connect_creates_link(self, client, safe_email):
        client.post("/scan", json=safe_email)
        r = client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        })
        assert r.status_code == 200
        assert "הופעל" in r.json()["message"]

    def test_connect_unknown_child_returns_404(self, client):
        r = client.post("/guardian/connect", json={
            "child_email": "ghost@example.com",
            "parent_email": "parent@example.com",
        })
        assert r.status_code == 404

    def test_guardian_data_no_children_returns_404(self, client, safe_email):
        client.post("/scan", json=safe_email)
        # parent without children
        client.post("/scan", json={**safe_email, "user_email": "parent@example.com"})
        r = client.get("/guardian/parent@example.com")
        assert r.status_code == 404

    def test_guardian_data_correct_structure(self, client, safe_email):
        client.post("/scan", json=safe_email)
        client.post("/guardian/connect", json={
            "child_email": safe_email["user_email"],
            "parent_email": "parent@example.com",
        })
        r = client.get("/guardian/parent@example.com")
        assert r.status_code == 200
        data = r.json()
        for field in ["child_name", "child_email", "risk_score",
                      "recent_alerts", "phishing_blocked_today"]:
            assert field in data, f"Missing field: {field}"


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
