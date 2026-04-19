"""
GET /stats/{user_email}  –  Return aggregated stats for a user.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import User, Alert
from schemas import UserStats
from utils import today_start

router = APIRouter(tags=["stats"])


@router.get(
    "/stats/{user_email}",
    response_model=UserStats,
    summary="סטטיסטיקות משתמש",
)
async def get_user_stats(user_email: str, db: Session = Depends(get_db)):
    """Return scan statistics and alert count for the given user."""
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="משתמש לא נמצא")

    recent_alerts = (
        db.query(Alert)
        .filter(Alert.user_id == user.id, Alert.created_at >= today_start())
        .count()
    )

    return UserStats(
        total_scanned=user.total_scanned,
        phishing_blocked=user.phishing_blocked,
        risk_score=user.risk_score,
        daily_active=user.daily_active,
        recent_alerts=recent_alerts,
    )
