"""
SQLAlchemy ORM models.
Four tables: users, emails, alerts, trusted_senders.
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    total_scanned = Column(Integer, default=0)
    phishing_blocked = Column(Integer, default=0)
    daily_active = Column(Boolean, default=True)
    # Self-referential FK: child -> parent (guardian)
    guardian_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    emails = relationship(
        "EmailRecord", back_populates="user", cascade="all, delete-orphan"
    )
    alerts = relationship(
        "Alert", back_populates="user", cascade="all, delete-orphan"
    )
    trusted_senders = relationship(
        "TrustedSender", back_populates="user", cascade="all, delete-orphan"
    )


class EmailRecord(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    sender = Column(String, nullable=False)
    subject = Column(String)
    content = Column(String)          # Stored truncated (privacy)
    risk_score = Column(Float, nullable=False)
    is_phishing = Column(Boolean, nullable=False)
    clicked_suspicious = Column(Boolean, default=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)

    # Which formula produced this score. Mail already checked returns the
    # stored result, skipping BERT. Without the stamp, a change to the
    # formula would affect nothing already scanned - the inbox would keep
    # showing scores from old code.
    scoring_version = Column(String, default="", index=True)

    # Fingerprint of the text scored. A record is keyed by (user, sender,
    # subject), so without this the full body scanned after the preview
    # would receive the preview's verdict.
    content_hash = Column(String, default="")

    # The reasons for the score, as a JSON array. Stored because the cache
    # returns a saved verdict without rerunning the engines; without this
    # a rescanned message showed a number and the placeholder "נסרק
    # בעבר", with no reasons behind it.
    indicators = Column(String, default="")

    user = relationship("User", back_populates="emails")
    alerts = relationship(
        "Alert", back_populates="email", cascade="all, delete-orphan"
    )


class TrustedSender(Base):
    """
    A sender the user has marked as known to them.

    The system knows the large brands, but an inbox is full of addresses
    nobody has heard of - an office, a teacher, a supplier - where there
    is no positive evidence of legitimacy at all, so ordinary mail scores
    high on the model's guess alone. This list is that missing evidence,
    and it is personal.

    value is a full address, or a domain when an organisation writes from
    several addresses.
    """
    __tablename__ = "trusted_senders"
    __table_args__ = (
        UniqueConstraint("user_id", "value", name="uq_trusted_sender"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    value = Column(String, nullable=False, index=True)   # always lowercased
    is_domain = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="trusted_senders")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    risk_level = Column(String, nullable=False)
    message = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="alerts")
    email = relationship("EmailRecord", back_populates="alerts")
