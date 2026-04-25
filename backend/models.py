"""
SQLAlchemy ORM models.
Three tables: users, emails, alerts.
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey,
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
    # Self-referential FK: child → parent (guardian)
    guardian_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    emails = relationship(
        "EmailRecord", back_populates="user", cascade="all, delete-orphan"
    )
    alerts = relationship(
        "Alert", back_populates="user", cascade="all, delete-orphan"
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

    user = relationship("User", back_populates="emails")
    alerts = relationship(
        "Alert", back_populates="email", cascade="all, delete-orphan"
    )


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
