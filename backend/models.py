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
    # Self-referential FK: child → parent (guardian)
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

    # גרסת נוסחת הניקוד שהפיקה את הציון. הסריקה מחזירה תוצאה שמורה
    # למייל שכבר נבדק — חיסכון אמיתי, כי הרצת BERT היא החלק היקר.
    # אבל בלי חותמת הגרסה, שינוי בנוסחה או בסף לא היה משפיע על אף
    # מייל שכבר נסרק: התיבה הייתה ממשיכה להציג ציונים שחושבו בקוד
    # ישן, ובדיקה אחרי תיקון הייתה מודדת את הגרסה הקודמת.
    scoring_version = Column(String, default="", index=True)

    # טביעת אצבע של הטקסט שנוסח ממנו הציון. הזיהוי של רשומה הוא
    # (משתמש, שולח, נושא), ולכן בלי החתימה הזאת סריקה שנייה של אותו
    # מייל מקבלת את התוצאה השמורה גם כשהטקסט שנשלח שונה לגמרי —
    # וזה בדיוק המקרה של סריקת הגוף המלא אחרי סריקת התצוגה המקדימה.
    content_hash = Column(String, default="")

    user = relationship("User", back_populates="emails")
    alerts = relationship(
        "Alert", back_populates="email", cascade="all, delete-orphan"
    )


class TrustedSender(Base):
    """
    שולח שהמשתמש סימן כמוכר לו.

    המערכת מכירה מותגים גדולים (BRAND_DOMAINS), אבל התיבה של אדם
    מלאה בכתובות שאיש לא שמע עליהן — משרד שהוא מתכתב איתו, מורה,
    ספק. עבורן אין למערכת שום ראיה חיובית ללגיטימיות, ולכן מייל תקין
    לחלוטין מקבל ציון גבוה על סמך ניחוש המודל בלבד.

    הרשימה הזאת היא הראיה החסרה, והיא אישית: מה שמוכר למשתמש אחד
    אינו אומר דבר על משתמש אחר.

    value מחזיק כתובת מלאה (name@example.com) או דומיין (example.com)
    כשהארגון שולח מכמה כתובות.
    """
    __tablename__ = "trusted_senders"
    __table_args__ = (
        UniqueConstraint("user_id", "value", name="uq_trusted_sender"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    value = Column(String, nullable=False, index=True)   # תמיד באותיות קטנות
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
