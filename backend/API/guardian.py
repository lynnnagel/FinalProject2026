"""
POST /guardian/connect  –  Link a child account to a parent (guardian).
GET  /guardian/{parent_email}  –  Return monitoring dashboard for a parent.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from API.auth import get_current_user
from database import get_db
from models import User, Alert, EmailRecord
from schemas import GuardianConnectRequest, GuardianData
from utils import get_name_from_email, today_start
from config import ALERT_HISTORY_LIMIT

router = APIRouter(prefix="/guardian", tags=["guardian"])


@router.post("/connect", summary="Link a guardian to a monitored account")
def connect_guardian(
    request: GuardianConnectRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Links a monitored account to a guardian.

    The guardian always comes from the token and never from a request
    field - otherwise anyone could make themselves the guardian of a
    stranger's inbox and receive the contents of its alerts.
    """
    parent = current_user

    if str(request.child_email) == parent.email:
        raise HTTPException(status_code=400, detail="לא ניתן להגדיר מפקח על עצמך")

    # Find or create the monitored account, so future scans attach to it
    child = db.query(User).filter(User.email == str(request.child_email)).first()
    if not child:
        child = User(
            email=str(request.child_email),
            name=get_name_from_email(str(request.child_email)),
        )
        db.add(child)
        db.commit()
        db.refresh(child)

    child.guardian_id = parent.id
    db.commit()

    return {
        "message": "מצב מפקח הופעל בהצלחה",
        "child": str(request.child_email),
        "guardian": parent.email,
    }


@router.post("/disconnect", summary="Unlink a guardian")
def disconnect_guardian(
    request: GuardianConnectRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Removes the link. Only the guardian actually set on that account can."""
    child = db.query(User).filter(User.email == str(request.child_email)).first()
    if not child or child.guardian_id != current_user.id:
        raise HTTPException(status_code=404, detail="חיבור מפקח לא נמצא")

    child.guardian_id = None
    db.commit()

    return {
        "message": "מצב מפקח נותק בהצלחה",
        "child": str(request.child_email),
        "guardian": current_user.email,
    }


@router.get("/{parent_email}", response_model=GuardianData, summary="Guardian dashboard")
def get_guardian_data(
    parent_email: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if parent_email != current_user.email:
        raise HTTPException(
            status_code=403, detail="אין הרשאה לצפות בנתונים של משתמש אחר"
        )
    parent = db.query(User).filter(User.email == parent_email).first()
    if not parent:
        raise HTTPException(status_code=404, detail="הורה לא נמצא")

    children = db.query(User).filter(User.guardian_id == parent.id).all()
    if not children:
        # An empty state, not an error. A guardian who is registered
        # but has not linked an account yet is a perfectly normal case,
        # and a 404 made the dashboard show a failure message instead of
        # telling them what to do.
        return GuardianData(
            child_name="", child_email="", risk_score=0.0,
            recent_alerts=[], phishing_blocked_today=0,
        )

    # The most active account. Supporting several monitored accounts at
    # once needs a change to the response shape, and is filed as an open
    # item.
    child = max(children, key=lambda c: c.total_scanned)

    # The guardian's alerts, not the monitored user's. Two records are
    # created per detection: one for the monitored user and one for the
    # guardian, and only the guardian's carries the monitored user's
    # name. Until now the dashboard pulled the monitored user's instead,
    # so the guardian records were written and never read.
    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == parent.id)
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