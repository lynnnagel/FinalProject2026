"""
POST /scan – Analyse an email and return a risk assessment.
Ensemble: BERT (when available) + Heuristics weighted average.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User, EmailRecord, Alert
from schemas import EmailInput, RiskAnalysis
from detector import detector
from utils import get_name_from_email
from config import ALERT_THRESHOLD, RECENT_EMAILS_WINDOW

router = APIRouter(tags=["scan"])

# Try to load BERT – returns None if checkpoint not ready yet
try:
    from ML.bert_model import bert_model
except Exception:
    bert_model = None


def get_risk_score(sender: str, subject: str, content: str) -> dict:
    """
    Ensemble: 70% BERT + 30% Heuristics when BERT is available.
    Falls back to 100% Heuristics when checkpoint is missing.
    """
    heuristic_result = detector.analyze_email(sender, subject, content)

    if bert_model is not None:
        try:
            bert_score = bert_model.predict_score(sender, subject, content)
            ensemble_score = round(0.7 * bert_score + 0.3 * heuristic_result["risk_score"], 2)
            heuristic_result["risk_score"] = min(ensemble_score, 100.0)
            heuristic_result["indicators"].append("✨ BERT ניתוח סמנטי")
        except Exception:
            pass  # fall back to heuristics silently

    return heuristic_result


@router.post("/scan", response_model=RiskAnalysis, summary="סריקת מייל לזיהוי פישינג")
async def scan_email(email_data: EmailInput, db: Session = Depends(get_db)):
    # Get or create user
    user = db.query(User).filter(User.email == email_data.user_email).first()
    if not user:
        user = User(
            email=str(email_data.user_email),
            name=get_name_from_email(str(email_data.user_email)),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Run analysis (Heuristics + BERT ensemble)
    analysis = get_risk_score(
        email_data.sender,
        email_data.subject,
        email_data.content,
    )

    # Persist email record
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

    # Update user stats
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

    # Create alert for high-risk email
    if analysis["risk_score"] >= ALERT_THRESHOLD:
        alert = Alert(
            user_id=user.id,
            email_id=email_record.id,
            risk_level=analysis["risk_level"],
            message=f"זוהה מייל פישינג מ-{email_data.sender}",
        )
        db.add(alert)

        if user.guardian_id:
            db.add(Alert(
                user_id=user.guardian_id,
                email_id=email_record.id,
                risk_level="התראת הורה",
                message=f"ילדך {user.name} קיבל מייל פישינג בסיכון {analysis['risk_score']}%",
            ))

    db.commit()
    return RiskAnalysis(**analysis)
