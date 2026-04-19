"""
Unit tests for SQLAlchemy ORM models (User, EmailRecord, Alert).

Tests run against an in-memory SQLite database.
Run from backend/:
    pytest tests/test_models.py -v
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from database import Base
from models import User, EmailRecord, Alert


@pytest.fixture(scope="function")
def db():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------
class TestUser:
    def test_create_user_default_values(self, db):
        user = User(email="test@example.com", name="Test")
        db.add(user)
        db.commit()
        assert user.id is not None
        assert user.total_scanned == 0
        assert user.phishing_blocked == 0
        assert user.risk_score == 0.0
        assert user.daily_active is True
        assert user.guardian_id is None
        assert user.created_at is not None

    def test_email_must_be_unique(self, db):
        db.add(User(email="dup@example.com", name="A"))
        db.commit()
        db.add(User(email="dup@example.com", name="B"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

    def test_guardian_relationship(self, db):
        parent = User(email="parent@example.com", name="Parent")
        child = User(email="child@example.com", name="Child")
        db.add_all([parent, child])
        db.commit()
        child.guardian_id = parent.id
        db.commit()
        assert child.guardian_id == parent.id

    def test_update_stats(self, db):
        user = User(email="u@example.com", name="U")
        db.add(user)
        db.commit()
        user.total_scanned += 1
        user.phishing_blocked += 1
        user.risk_score = 75.0
        db.commit()
        db.refresh(user)
        assert user.total_scanned == 1
        assert user.phishing_blocked == 1
        assert user.risk_score == 75.0


# ---------------------------------------------------------------------------
# EmailRecord model
# ---------------------------------------------------------------------------
class TestEmailRecord:
    def _make_user(self, db, email="u@example.com"):
        user = User(email=email, name="U")
        db.add(user)
        db.commit()
        return user

    def test_create_email_record(self, db):
        user = self._make_user(db)
        rec = EmailRecord(
            user_id=user.id,
            sender="phish@evil.com",
            subject="Urgent!",
            content="Click here",
            risk_score=85.0,
            is_phishing=True,
        )
        db.add(rec)
        db.commit()
        assert rec.id is not None
        assert rec.clicked_suspicious is False
        assert rec.scanned_at is not None

    def test_relationship_to_user(self, db):
        user = self._make_user(db)
        rec = EmailRecord(
            user_id=user.id, sender="s@s.com", subject="hi",
            content="body", risk_score=20.0, is_phishing=False,
        )
        db.add(rec)
        db.commit()
        assert len(user.emails) == 1
        assert user.emails[0].sender == "s@s.com"

    def test_safe_email_record(self, db):
        user = self._make_user(db)
        rec = EmailRecord(
            user_id=user.id, sender="news@company.com",
            subject="Newsletter", content="Monthly digest",
            risk_score=10.0, is_phishing=False,
        )
        db.add(rec)
        db.commit()
        assert rec.is_phishing is False
        assert rec.risk_score == 10.0


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------
class TestAlert:
    def _setup(self, db):
        user = User(email="u@example.com", name="U")
        db.add(user)
        db.commit()
        rec = EmailRecord(
            user_id=user.id, sender="x@y.com", subject="s",
            content="c", risk_score=80.0, is_phishing=True,
        )
        db.add(rec)
        db.commit()
        return user, rec

    def test_create_alert(self, db):
        user, rec = self._setup(db)
        alert = Alert(
            user_id=user.id,
            email_id=rec.id,
            risk_level="סכנה גבוהה",
            message="פישינג זוהה",
        )
        db.add(alert)
        db.commit()
        assert alert.id is not None
        assert alert.created_at is not None

    def test_alert_linked_to_user(self, db):
        user, rec = self._setup(db)
        alert = Alert(
            user_id=user.id, email_id=rec.id,
            risk_level="סכנה גבוהה", message="Test",
        )
        db.add(alert)
        db.commit()
        assert len(user.alerts) == 1
        assert user.alerts[0].risk_level == "סכנה גבוהה"

    def test_alert_cascade_delete_with_user(self, db):
        """Deleting a user should cascade-delete their alerts."""
        user, rec = self._setup(db)
        alert = Alert(
            user_id=user.id, email_id=rec.id,
            risk_level="חשוד", message="Test cascade",
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id
        db.delete(user)
        db.commit()
        assert db.query(Alert).filter(Alert.id == alert_id).first() is None
