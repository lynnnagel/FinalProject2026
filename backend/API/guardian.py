"""
POST /guardian/connect  –  Link a child account to a parent (guardian).
GET  /guardian/{parent_email}  –  Return monitoring dashboard for a parent.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import User, Alert, EmailRecord
from schemas import GuardianConnectRequest, GuardianData
from utils import get_name_from_email, today_start
from config import ALERT_HISTORY_LIMIT

router = APIRouter(prefix="/guardian", tags=["guardian"])


@router.post("/connect", summary="חיבור הורה-ילד")
async def connect_guardian(
    request: GuardianConnectRequest,
    db: Session = Depends(get_db),
):
    # מצא או צור את חשבון הילד
    child = db.query(User).filter(User.email == str(request.child_email)).first()
    if not child:
        # צור אוטומטית אם לא קיים – יחוברו הסריקות שיגיעו בעתיד
        child = User(
            email=str(request.child_email),
            name=get_name_from_email(str(request.child_email)),
        )
        db.add(child)
        db.commit()
        db.refresh(child)

    # מצא או צור את חשבון ההורה
    parent = db.query(User).filter(User.email == str(request.parent_email)).first()
    if not parent:
        parent = User(
            email=str(request.parent_email),
            name=get_name_from_email(str(request.parent_email)),
        )
        db.add(parent)
        db.commit()
        db.refresh(parent)

    child.guardian_id = parent.id
    db.commit()

    return {
        "message": "מצב הורה הופעל בהצלחה",
        "child": str(request.child_email),
        "guardian": str(request.parent_email),
    }

@router.post("/disconnect", summary="ניתוק הורה-ילד")
async def disconnect_guardian(
    request: GuardianConnectRequest,
    db: Session = Depends(get_db),
):
    """Remove the guardian link from a child account."""
    child = db.query(User).filter(User.email == str(request.child_email)).first()
    if not child:
        raise HTTPException(status_code=404, detail="משתמש ילד לא נמצא")

    parent = db.query(User).filter(User.email == str(request.parent_email)).first()
    if not parent or child.guardian_id != parent.id:
        raise HTTPException(status_code=404, detail="חיבור הורה-ילד לא נמצא")

    child.guardian_id = None
    db.commit()

    return {
        "message": "מצב הורה נותק בהצלחה",
        "child": str(request.child_email),
        "guardian": str(request.parent_email),
    }


@router.get("/{parent_email}", response_model=GuardianData, summary="לוח בקרה להורה")
async def get_guardian_data(parent_email: str, db: Session = Depends(get_db)):
    parent = db.query(User).filter(User.email == parent_email).first()
    if not parent:
        raise HTTPException(status_code=404, detail="הורה לא נמצא")

    children = db.query(User).filter(User.guardian_id == parent.id).all()
    if not children:
        raise HTTPException(status_code=404, detail="לא נמצאו ילדים מחוברים")

    # השתמש בילד הראשון (הכי פעיל לפי סריקות)
    child = max(children, key=lambda c: c.total_scanned)

    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == child.id)
        .order_by(Alert.created_at.desc())
        .limit(ALERT_HISTORY_LIMIT)
        .all()
    )

    recent_alerts_data = [
        {
            "risk_level": a.risk_level,
            "message":    a.message,
            "time":       a.created_at.strftime("%H:%M"),
        }
        for a in alerts
    ]

    phishing_today = (
        db.query(EmailRecord)
        .filter(
            EmailRecord.user_id == child.id,
            EmailRecord.is_phishing == True,
            EmailRecord.scanned_at >= today_start(),
        )
        .count()
    )

    return GuardianData(
        child_name=child.name,
        child_email=child.email,
        risk_score=child.risk_score,
        recent_alerts=recent_alerts_data,
        phishing_blocked_today=phishing_today,
    )