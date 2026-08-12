"""
POST /auth/register         – יצירת משתמש חדש
POST /auth/login            – התחברות + קבלת JWT
POST /auth/forgot-password  – בקשת קישור לאיפוס סיסמה
POST /auth/reset-password   – איפוס סיסמה באמצעות אסימון חד-פעמי
GET  /auth/me               – פרטי המשתמש הנוכחי
"""
import hashlib
from datetime import datetime, timedelta

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from config import SECRET_KEY, JWT_ALGORITHM, TOKEN_TTL_DAYS, RESET_TOKEN_TTL_MINUTES
from database import get_db
from email_service import send_password_reset
from models import User
from schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserProfile,
    ForgotPasswordRequest, ResetPasswordRequest,
)
from utils import get_name_from_email

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

ALGORITHM = JWT_ALGORITHM
MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    """גיבוב סיסמה עם bcrypt (מאובטח, עם salt אוטומטי)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, stored: str) -> bool:
    """
    בדיקת סיסמה.
    תומך גם בהאשים ישנים של SHA-256 (לתאימות לאחור).
    """
    if stored.startswith("$2"):
        return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
    # hash SHA-256 ישן – תמיכה לאחור
    return stored == hashlib.sha256(plain.encode("utf-8")).hexdigest()


def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "purpose": "auth",
        "exp": datetime.utcnow() + timedelta(days=TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_reset_token(email: str) -> str:
    """אסימון חד-פעמי קצר-מועד לאיפוס סיסמה."""
    payload = {
        "sub": email,
        "purpose": "reset",
        "exp": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "הטוקן פג תוקף — התחבר מחדש")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "טוקן לא תקין")

    # אסימון איפוס סיסמה אינו אסימון התחברות — אחרת קישור מהמייל
    # היה משמש כהזדהות מלאה למערכת.
    # ("auth" הוא גם ברירת המחדל, לתאימות עם טוקנים שהונפקו לפני השינוי)
    if payload.get("purpose", "auth") != "auth":
        raise HTTPException(401, "טוקן לא תקין")

    return payload["sub"]


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(401, "נדרשת הזדהות")
    email = decode_token(credentials.credentials)
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(401, "משתמש לא נמצא")
    return user


@router.post("/register", response_model=TokenResponse)
async def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == str(data.email)).first():
        raise HTTPException(400, "כתובת המייל כבר רשומה במערכת")
    user = User(
        email=str(data.email),
        name=data.name or get_name_from_email(str(data.email)),
        password_hash=hash_password(data.password),
    )
    db.add(user); db.commit(); db.refresh(user)
    return TokenResponse(token=create_token(str(data.email)), email=str(data.email), name=user.name)


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(data.email)).first()
    if not user or not user.password_hash:
        raise HTTPException(401, "כתובת מייל או סיסמה שגויים")
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "כתובת מייל או סיסמה שגויים")
    # שדרג hash ישן ל-bcrypt
    if not user.password_hash.startswith("$2"):
        user.password_hash = hash_password(data.password)
        db.commit()
    return TokenResponse(token=create_token(str(data.email)), email=str(data.email), name=user.name)


@router.post("/forgot-password", summary="בקשת קישור לאיפוס סיסמה")
async def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    שולח קישור איפוס למייל. התשובה זהה בין אם הכתובת רשומה ובין אם לא,
    כדי לא לחשוף אילו כתובות קיימות במערכת (user enumeration).
    """
    user = db.query(User).filter(User.email == str(data.email)).first()
    if user:
        send_password_reset(
            to_email=user.email,
            name=user.name,
            token=create_reset_token(user.email),
        )
    return {"message": "אם הכתובת רשומה במערכת, נשלח אליה קישור לאיפוס סיסמה"}


@router.post("/reset-password", summary="איפוס סיסמה באמצעות אסימון")
async def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(data.token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(400, "הקישור פג תוקף — בקש קישור חדש")
    except jwt.InvalidTokenError:
        raise HTTPException(400, "קישור לא תקין")

    if payload.get("purpose") != "reset":
        raise HTTPException(400, "קישור לא תקין")

    if len(data.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            400, f"הסיסמה חייבת להכיל לפחות {MIN_PASSWORD_LENGTH} תווים"
        )

    user = db.query(User).filter(User.email == payload["sub"]).first()
    if not user:
        raise HTTPException(404, "משתמש לא נמצא")

    user.password_hash = hash_password(data.new_password)
    db.commit()
    return {"message": "הסיסמה עודכנה בהצלחה"}


@router.get("/me", response_model=UserProfile)
async def me(current_user: User = Depends(get_current_user)):
    return UserProfile(
        email=current_user.email, name=current_user.name,
        total_scanned=current_user.total_scanned,
        phishing_blocked=current_user.phishing_blocked,
        risk_score=current_user.risk_score,
        daily_active=current_user.daily_active,
    )