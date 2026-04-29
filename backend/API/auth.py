"""
POST /auth/register  – יצירת משתמש חדש
POST /auth/login     – התחברות + קבלת JWT
GET  /auth/me        – פרטי המשתמש הנוכחי
"""
import os
import hashlib
from datetime import datetime, timedelta

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import User
from schemas import RegisterRequest, LoginRequest, TokenResponse, UserProfile, ResetPasswordRequest
from utils import get_name_from_email

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

SECRET_KEY = os.getenv("JWT_SECRET", "phishguard-dev-secret-change-in-production")
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "הטוקן פג תוקף — התחבר מחדש")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "טוקן לא תקין")


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
    db.add(user)
    db.commit()
    db.refresh(user)
    return TokenResponse(
        token=create_token(str(data.email)),
        email=str(data.email),
        name=user.name,
    )


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(data.email)).first()
    if not user or not user.password_hash:
        raise HTTPException(401, "כתובת מייל או סיסמה שגויים")
    if user.password_hash != hash_password(data.password):
        raise HTTPException(401, "כתובת מייל או סיסמה שגויים")
    return TokenResponse(
        token=create_token(str(data.email)),
        email=str(data.email),
        name=user.name,
    )

@router.post("/reset-password", summary="איפוס סיסמה")
async def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(data.email)).first()
    if not user:
        raise HTTPException(404, "כתובת המייל לא נמצאה במערכת")
    if len(data.new_password) < 6:
        raise HTTPException(400, "הסיסמה חייבת להכיל לפחות 6 תווים")
    user.password_hash = hash_password(data.new_password)
    db.commit()
    return {"message": "הסיסמה עודכנה בהצלחה"}


@router.get("/me", response_model=UserProfile)
async def me(current_user: User = Depends(get_current_user)):
    return UserProfile(
        email=current_user.email,
        name=current_user.name,
        total_scanned=current_user.total_scanned,
        phishing_blocked=current_user.phishing_blocked,
        risk_score=current_user.risk_score,
        daily_active=current_user.daily_active,
    )