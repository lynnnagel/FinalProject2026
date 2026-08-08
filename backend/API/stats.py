from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import User, Alert, EmailRecord
from schemas import UserStats, AlertSummary
from utils import today_start

router = APIRouter(tags=["stats"])

@router.get("/stats/{user_email}", response_model=UserStats)
async def get_user_stats(user_email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="משתמש לא נמצא")

    # daily_active – האם סרק מייל כלשהו היום?
    scanned_today = (
        db.query(EmailRecord)
        .filter(
            EmailRecord.user_id == user.id,
            EmailRecord.scanned_at >= today_start(),
        )
        .count()
    )
    daily_active = scanned_today > 0

    # התראות היום – ללא "התראות מפקח" (כדי למנוע כפילות)
    alerts_today = (
        db.query(Alert)
        .filter(
            Alert.user_id == user.id,
            Alert.created_at >= today_start(),
            Alert.risk_level != "התראת מפקח",
        )
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )

    return UserStats(
        total_scanned=user.total_scanned,
        phishing_blocked=user.phishing_blocked,
        risk_score=user.risk_score,
        daily_active=daily_active,
        recent_alerts=len(alerts_today),
        recent_alerts_list=[
            AlertSummary(
                risk_level=a.risk_level,
                message=a.message,
                created_at=a.created_at.isoformat() if a.created_at else None,
            )
            for a in alerts_today
        ],
    )