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
    """Hash a password with bcrypt - secure, salted automatically."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, stored: str) -> bool:
    """
    בדיקת סיסמה.
    תומך גם בהאשים ישנים של SHA-256 (לתאימות לאחור).
    """
    if stored.startswith("$2"):
        return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
    # Old SHA-256 hash - kept for backwards compatibility
    return stored == hashlib.sha256(plain.encode("utf-8")).hexdigest()


def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "purpose": "auth",
        "exp": datetime.utcnow() + timedelta(days=TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _password_fingerprint(password_hash: str | None) -> str:
    """A short fingerprint of the stored hash. Never the hash itself."""
    return hashlib.sha256((password_hash or "").encode("utf-8")).hexdigest()[:16]


def create_reset_token(email: str, password_hash: str | None) -> str:
    """
    A short-lived, single-use token for resetting a password.

    Single use is what makes it safe to send by mail, and it needs no
    table of spent tokens: the token carries a fingerprint of the
    password it was issued against. Resetting replaces the password, the
    fingerprint stops matching, and the link is dead - including every
    other link issued earlier. Without this the token was replayable
    for its whole 30 minutes by anyone who saw the mail, which is
    exactly the situation the feature exists to protect against.
    """
    payload = {
        "sub": email,
        "purpose": "reset",
        "pwh": _password_fingerprint(password_hash),
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

    # A password-reset token is not a login token - otherwise a link
    # from an email would work as a full login to the system.
    # ("auth" is also the default, for tokens issued before the change.)
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


def get_optional_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User | None:
    """
    Returns the identified user if a valid token was sent, and None if
    none was sent at all.

    It exists for /scan. The extension's content script sends the address
    it scrapes from Gmail's DOM, which caused two problems at once:
    anyone could post a request in another user's name, and scans were
    recorded under an identity that need not match the account the user
    signed in with - which is why their dashboard came up empty.

    When a token is present it decides, and any address in the request
    body is ignored. A missing token is allowed, so the extension keeps
    working before login.
    """
    if not credentials:
        return None
    try:
        email = decode_token(credentials.credentials)
    except HTTPException:
        # A malformed or expired token counts as no token, not as an
        # error. This path allows an unauthenticated request in the
        # first place, so refusing with a 401 added no protection - it
        # only broke scanning completely for anyone whose token had aged
        # out after seven days, instead of carrying on anonymously.
        return None
    return db.query(User).filter(User.email == email).first()


@router.post("/register", response_model=TokenResponse)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == str(data.email)).first()
    if existing and existing.password_hash:
        raise HTTPException(400, "כתובת המייל כבר רשומה במערכת")

    if existing:
        # A row with no password is a placeholder: guardian mode creates
        # one for an address it is asked to watch, so that later scans
        # have somewhere to attach. Nobody has ever signed into it, so
        # registering claims it rather than colliding with it - without
        # this, being named as someone's monitored account locked that
        # address out of ever creating one.
        existing.name = data.name or existing.name
        existing.password_hash = hash_password(data.password)
        db.commit(); db.refresh(existing)
        return TokenResponse(token=create_token(existing.email),
                             email=existing.email, name=existing.name)

    user = User(
        email=str(data.email),
        name=data.name or get_name_from_email(str(data.email)),
        password_hash=hash_password(data.password),
    )
    db.add(user); db.commit(); db.refresh(user)
    return TokenResponse(token=create_token(str(data.email)), email=str(data.email), name=user.name)


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(data.email)).first()
    if not user or not user.password_hash:
        raise HTTPException(401, "כתובת מייל או סיסמה שגויים")
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "כתובת מייל או סיסמה שגויים")
    # Upgrade an old hash to bcrypt
    if not user.password_hash.startswith("$2"):
        user.password_hash = hash_password(data.password)
        db.commit()
    return TokenResponse(token=create_token(str(data.email)), email=str(data.email), name=user.name)


@router.post("/forgot-password", summary="Request a password reset link")
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    שולח קישור איפוס למייל. התשובה זהה בין אם הכתובת רשומה ובין אם לא,
    כדי לא לחשוף אילו כתובות קיימות במערכת (user enumeration).
    """
    user = db.query(User).filter(User.email == str(data.email)).first()
    if user:
        send_password_reset(
            to_email=user.email,
            name=user.name,
            token=create_reset_token(user.email, user.password_hash),
        )
    return {"message": "אם הכתובת רשומה במערכת, נשלח אליה קישור לאיפוס סיסמה"}


@router.post("/reset-password", summary="Reset a password using a token")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
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

    # The link is good for one reset. Once the password changes the
    # fingerprint in the token no longer matches what is stored, so this
    # link - and any older one still inside its 30 minutes - stops
    # working.
    if payload.get("pwh") != _password_fingerprint(user.password_hash):
        raise HTTPException(
            400, "הקישור כבר שימש לאיפוס סיסמה — בקש קישור חדש"
        )

    user.password_hash = hash_password(data.new_password)
    db.commit()
    return {"message": "הסיסמה עודכנה בהצלחה"}


@router.get("/me", response_model=UserProfile)
def me(current_user: User = Depends(get_current_user)):
    return UserProfile(
        email=current_user.email, name=current_user.name,
        total_scanned=current_user.total_scanned,
        phishing_blocked=current_user.phishing_blocked,
        risk_score=current_user.risk_score,
        daily_active=current_user.daily_active,
    )