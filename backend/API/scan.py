"""
POST /scan – Analyse an email and return a risk assessment.
Ensemble: BERT (when available) + Heuristics weighted average.
"""
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User, EmailRecord, Alert
from schemas import EmailInput, RiskAnalysis
from detector import detector
from utils import get_name_from_email
from config import ALERT_THRESHOLD, RECENT_EMAILS_WINDOW
from email_service import send_guardian_phishing_alert
from config import (
    ALERT_THRESHOLD,
    RECENT_EMAILS_WINDOW,
    PHISHING_THRESHOLD,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD,
)

router = APIRouter(tags=["scan"])

try:
    from ML.bert_model import bert_model
except Exception:
    bert_model = None


def get_risk_score(sender: str, subject: str, content: str) -> dict:
    heuristic_result = detector.analyze_email(sender, subject, content)

    if bert_model is not None:
        try:
            bert_score = bert_model.predict_score(sender, subject, content)
            ensemble_score = round(0.3 * bert_score + 0.7 * heuristic_result["risk_score"], 2)
            heuristic_result["risk_score"] = min(ensemble_score, 100.0)
            heuristic_result["indicators"].append("✨ BERT ניתוח סמנטי")

            risk_score = heuristic_result["risk_score"]
            heuristic_result["is_phishing"] = risk_score >= PHISHING_THRESHOLD
            if risk_score >= HIGH_RISK_THRESHOLD:
                heuristic_result["risk_level"] = "סכנה גבוהה"
                heuristic_result["recommendation"] = "⛔ אל תלחץ על שום קישור! מחק את המייל מיד."
            elif risk_score >= MEDIUM_RISK_THRESHOLD:
                heuristic_result["risk_level"] = "חשוד"
                heuristic_result["recommendation"] = "⚠️ היזהר מאוד. בדוק את המקור לפני כל פעולה."
            elif risk_score >= LOW_RISK_THRESHOLD:
                heuristic_result["risk_level"] = "זהירות"
                heuristic_result["recommendation"] = "🔍 המייל מכיל אלמנטים חשודים. היה ערני."
            else:
                heuristic_result["risk_level"] = "בטוח"
                heuristic_result["recommendation"] = "✅ המייל נראה תקין."
        except Exception:
            pass

    return heuristic_result


@router.post("/scan", response_model=RiskAnalysis, summary="סריקת מייל לזיהוי פישינג")
async def scan_email(
    email_data: EmailInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email_data.user_email).first()
    if not user:
        user = User(
            email=str(email_data.user_email),
            name=get_name_from_email(str(email_data.user_email)),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    existing = (
        db.query(EmailRecord)
        .filter(
            EmailRecord.user_id == user.id,
            EmailRecord.sender == email_data.sender,
            EmailRecord.subject == email_data.subject[:200],
        )
        .first()
    )
    if existing:
        return RiskAnalysis(
            risk_score=existing.risk_score,
            is_phishing=existing.is_phishing,
            risk_level=_get_risk_level(existing.risk_score),
            indicators=["נסרק בעבר"],
            recommendation=_get_recommendation(existing.risk_score),
            response_time=0.0,
        )

    analysis = get_risk_score(
        email_data.sender,
        email_data.subject,
        email_data.content,
    )

    email_record = EmailRecord(
        user_id=user.id,
        sender=email_data.sender,
        subject=email_data.subject[:200],
        content=email_data.content[:500],
        risk_score=analysis["risk_score"],
        is_phishing=analysis["is_phishing"],
    )
    db.add(email_record)
    db.flush()

    user.total_scanned += 1
    if analysis["is_phishing"]:
        user.phishing_blocked += 1

    recent = (
        db.query(EmailRecord)
        .filter(EmailRecord.user_id == user.id)
        .order_by(EmailRecord.scanned_at.desc())
        .limit(RECENT_EMAILS_WINDOW)
        .all()
    )
    if recent:
        user.risk_score = round(sum(e.risk_score for e in recent) / len(recent), 2)

    if analysis["risk_score"] >= ALERT_THRESHOLD:
        db.add(Alert(
            user_id=user.id,
            email_id=email_record.id,
            risk_level=analysis["risk_level"],
            message=f"זוהה מייל פישינג מ-{email_data.sender}",
        ))

        if user.guardian_id:
            # שמור התראה במסד הנתונים עבור המפקח
            guardian = db.query(User).filter(User.id == user.guardian_id).first()
            db.add(Alert(
                user_id=user.guardian_id,
                email_id=email_record.id,
                risk_level="התראת מפקח",
                message=(
                    f"{user.name} קיבל מייל פישינג בסיכון "
                    f"{analysis['risk_score']}% מ-{email_data.sender}"
                ),
            ))

            # שלח מייל למפקח ברקע (ללא עיכוב בתגובה)
            if guardian:
                background_tasks.add_task(
                    send_guardian_phishing_alert,
                    guardian_email=guardian.email,
                    monitored_name=user.name,
                    monitored_email=user.email,
                    risk_score=analysis["risk_score"],
                    phishing_sender=email_data.sender,
                    phishing_subject=email_data.subject,
                    risk_level=analysis["risk_level"],
                )

    db.commit()
    return RiskAnalysis(**analysis)


def _get_risk_level(score: float) -> str:
    if score >= 80: return "סכנה גבוהה"
    if score >= 50: return "חשוד"
    if score >= 30: return "זהירות"
    return "בטוח"


def _get_recommendation(score: float) -> str:
    if score >= 80: return "⛔ אל תלחץ על שום קישור! מחק את המייל מיד."
    if score >= 50: return "⚠️ היזהר מאוד. בדוק את המקור לפני כל פעולה."
    if score >= 30: return "המייל מכיל אלמנטים חשודים. היה ערני."
    return " המייל נראה תקין ✅."