"""
POST /scan – Analyse an email and return a risk assessment.
Ensemble: BERT (when available) + Heuristics weighted average.
"""
import logging

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User, EmailRecord, Alert
from schemas import EmailInput, RiskAnalysis
from detector import detector
from utils import get_name_from_email
from email_service import send_guardian_phishing_alert
from config import (
    ALERT_THRESHOLD,
    RECENT_EMAILS_WINDOW,
    PHISHING_THRESHOLD,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD,
    BERT_WEIGHT,
    HEURISTIC_WEIGHT,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

# המודל נטען ברקע (ראה ML/bert_model.py). get_model מחזיר None עד שהוא
# מוכן, ואז הסריקה רצה על מנוע החוקים בלבד — לכן הייבוא כאן זול ולא חוסם.
try:
    from ML.bert_model import get_model as get_bert_model
except ImportError as exc:
    # torch/transformers לא מותקנים — מצב לגיטימי, לא תקלה
    logger.warning("BERT לא זמין (%s) — מצב חוקים בלבד", exc)

    def get_bert_model():
        return None
except Exception:
    logger.exception("BERT: שגיאה בלתי צפויה בייבוא — מצב חוקים בלבד")

    def get_bert_model():
        return None


def _apply_thresholds(result: dict) -> dict:
    """קובע רמת סיכון והמלצה לפי הציון הסופי."""
    score = result["risk_score"]
    result["is_phishing"] = score >= PHISHING_THRESHOLD

    if score >= HIGH_RISK_THRESHOLD:
        result["risk_level"] = "סכנה גבוהה"
        result["recommendation"] = "אל תלחץ על שום קישור. מחק את המייל מיד."
    elif score >= MEDIUM_RISK_THRESHOLD:
        result["risk_level"] = "חשוד"
        result["recommendation"] = "היזהר מאוד. בדוק את המקור לפני כל פעולה."
    elif score >= LOW_RISK_THRESHOLD:
        result["risk_level"] = "זהירות"
        result["recommendation"] = "המייל מכיל אלמנטים חשודים. היה ערני."
    else:
        result["risk_level"] = "בטוח"
        result["recommendation"] = "המייל נראה תקין."
    return result


def get_risk_score(sender: str, subject: str, content: str) -> dict:
    result = detector.analyze_email(sender, subject, content)

    model = get_bert_model()
    if model is None:
        return result          # fallback: חוקים בלבד

    try:
        bert_score = model.predict_score(sender, subject, content)
    except Exception:
        logger.exception("BERT prediction failed — falling back to heuristics")
        return result

    ensemble = BERT_WEIGHT * bert_score + HEURISTIC_WEIGHT * result["risk_score"]
    result["risk_score"] = min(round(ensemble, 2), 100.0)
    result["indicators"].append("ניתוח סמנטי (BERT)")
    return _apply_thresholds(result)


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