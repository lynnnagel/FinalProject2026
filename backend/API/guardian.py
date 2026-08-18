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


@router.post("/connect", summary="חיבור מפקח-מנוטר")
def connect_guardian(
    request: GuardianConnectRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    מקשר חשבון מנוטר למפקח.

    המפקח נקבע תמיד לפי הטוקן ולא לפי שדה בבקשה — אחרת כל אחד היה יכול
    להגדיר את עצמו כמפקח על תיבה זרה ולקבל את תוכן ההתראות שלה.
    """
    parent = current_user

    if str(request.child_email) == parent.email:
        raise HTTPException(status_code=400, detail="לא ניתן להגדיר מפקח על עצמך")

    # מצא או צור את חשבון המנוטר – סריקות עתידיות ישויכו אליו
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


@router.post("/disconnect", summary="ניתוק מפקח-מנוטר")
def disconnect_guardian(
    request: GuardianConnectRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """מסיר את הקישור. אפשרי רק למפקח שמוגדר בפועל על אותו חשבון."""
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


@router.get("/{parent_email}", response_model=GuardianData, summary="לוח בקרה למפקח")
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
        # מצב ריק ולא שגיאה. מפקח שרשום במערכת אך טרם חיבר חשבון הוא
        # מצב תקין לחלוטין, ו-404 גרם ללוח הבקרה להציג הודעת תקלה
        # במקום הנחיה מה לעשות.
        return GuardianData(
            child_name="", child_email="", risk_score=0.0,
            recent_alerts=[], phishing_blocked_today=0,
        )

    # החשבון הפעיל ביותר. תמיכה במספר מנוטרים בו-זמנית דורשת שינוי
    # במבנה התשובה, והיא רשומה כפריט פתוח.
    child = max(children, key=lambda c: c.total_scanned)

    # ההתראות של המפקח, לא של המנוטר. שתי רשומות נוצרות לכל זיהוי:
    # אחת למנוטר ואחת למפקח, וזו של המפקח היא היחידה שנושאת את שם
    # המנוטר. עד כה לוח הבקרה שאב דווקא את זו של המנוטר, ולכן רשומות
    # המפקח נכתבו ומעולם לא נקראו.
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