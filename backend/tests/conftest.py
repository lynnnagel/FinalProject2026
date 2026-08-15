"""
Pytest configuration and shared fixtures for LURA backend tests.

All tests use an in-memory SQLite database so the production
LURA.db is never touched.
"""
import os
import sys

# חייב להיקבע לפני שמייבאים את config — הבדיקות של איפוס הסיסמה
# קוראות ל-/auth/forgot-password, וכשהדגל דלוק נשלחים מיילים אמיתיים
# לכתובות הבדיקה (known@example.com וכדומה). התוצאה היא מיילי איפוס
# והודעות bounce שמגיעים לתיבה האמיתית בכל הרצת pytest.
#
# load_dotenv אינו דורס משתני סביבה קיימים, ולכן קביעה כאן גוברת על .env
os.environ["EMAIL_ENABLED"] = "false"
os.environ.setdefault("SECRET_KEY", "test-secret-not-used-in-production-0123456789")

# Add backend/ to Python path so imports like 'from models import ...' resolve
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from server import app

# ---------------------------------------------------------------------------
# In-memory test database
# ---------------------------------------------------------------------------
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_db():
    """Create tables before each test and drop them after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client(reset_db):
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Authentication helpers
#
# /stats ו-/guardian דורשים טוקן. הפיקסצ'רים כאן רושמים משתמש
# ומחזירים את כותרת ההזדהות שלו.
# ---------------------------------------------------------------------------
@pytest.fixture
def make_user(client):
    def _make(email: str, password: str = "testpass123", name: str | None = None):
        r = client.post(
            "/auth/register",
            json={"email": email, "password": password, "name": name},
        )
        if r.status_code == 400:          # המשתמש כבר קיים – התחבר במקום
            r = client.post("/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    return _make


@pytest.fixture
def auth_headers(make_user):
    """המשתמש הראשי בבדיקות — test@example.com."""
    return make_user("test@example.com")


@pytest.fixture
def parent_headers(make_user):
    """משתמש המשמש כמפקח — parent@example.com."""
    return make_user("parent@example.com")


@pytest.fixture
def phishing_email():
    """A clear phishing email that should score ≥ 70."""
    return {
        "user_email": "test@example.com",
        "sender": "security-rn@paypal-verify.xyz",
        "subject": "דחוף: אימות חשבון נדרש",
        "content": (
            "verify your account password urgent click here "
            "http://malicious.com/login http://evil.com http://phish.net"
        ),
    }


@pytest.fixture
def safe_email():
    """A clearly legitimate email that should score < 30."""
    return {
        "user_email": "test@example.com",
        "sender": "newsletter@company.com",
        "subject": "חדשות חודשיות",
        "content": "שלום, הנה הניוזלטר החודשי שלנו עם עדכונים מעניינים.",
    }
