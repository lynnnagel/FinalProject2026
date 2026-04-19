"""
POST /scan  –  Analyse an email and return a risk assessment.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User, EmailRecord, Alert
from schemas import EmailInput, RiskAnalysis
from detector import detector
from utils import get_name_from_email
from config import ALERT_THRESHOLD

router = APIRouter(tags=["scan"])


@router.post("/scan", response_model=RiskAnalysis, summary="סריקת מייל לזיהוי פישינג")
async def scan_email(email_data: EmailInput, db: Session = Depends(get_db)):
    """
    Analyse a single email for phishing indicators.
    Target latency: < 2 s (heuristics ~0.3 s; BERT target ~0.8 s after integration).
    """
    # -- Get or create the scanning user ------------------------------------
    user = db.query(User).filter(User.email == email_data.user_email).first()
    if not user:
        user = User(
            email=str(email_data.user_email),
            name=get_name_from_email(str(email_data.user_email)),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # -- Run heuristic analysis ---------------------------------------------
    analysis = detector.analyze_email(
        email_data.sender,
        email_data.subject,
        email_data.content,
    )

    # -- Persist email record (truncated content for privacy) ---------------
    email_record = EmailRecord(
        user_id=user.id,
        sender=email_data.sender,
        subject=email_data.subject[:200],
        content=email_data.content[:500],
        risk_score=analysis["risk_score"],
        is_phishing=analysis["is_phishing"],
    )
    db.add(email_record)
    db.flush()  # obtain email_record.id before commit

    # -- Update user aggregate stats ----------------------------------------
    user.total_scanned += 1
    if analysis["is_phishing"]:
        user.phishing_blocked += 1

    # Rolling average risk score over the last RECENT_EMAILS_WINDOW emails
    from config import RECENT_EMAILS_WINDOW
    recent = (
        db.query(EmailRecord)
        .filter(EmailRecord.user_id == user.id)
        .order_by(EmailRecord.scanned_at.desc())
        .limit(RECENT_EMAILS_WINDOW)
        .all()
    )
    if recent:
        user.risk_score = round(sum(e.risk_score for e in recent) / len(recent), 2)

    # -- Create alert for high-risk email -----------------------------------
    if analysis["risk_score"] >= ALERT_THRESHOLD:
        alert = Alert(
            user_id=user.id,
            email_id=email_record.id,
            risk_level=analysis["risk_level"],
            message=f"זוהה מייל פישינג מ-{email_data.sender}",
        )
        db.add(alert)

        # Notify the guardian (parent) if one is configured
        if user.guardian_id:
            guardian_alert = Alert(
                user_id=user.guardian_id,
                email_id=email_record.id,
                risk_level="התראת הורה",
                message=(
                    f"ילדך {user.name} קיבל מייל פישינג "
                    f"בסיכון {analysis['risk_score']}%"
                ),
            )
            db.add(guardian_alert)

    db.commit()
    return RiskAnalysis(**analysis)
