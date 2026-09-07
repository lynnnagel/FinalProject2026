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
    SCORING_VERSION,
)
from API.auth import get_optional_user
import hashlib
import json

from API.trusted import is_trusted_by_user
import risk_levels
from scoring import combine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

# ---------------------------------------------------------------------------
# Plain def, not async def, on purpose. An async endpoint runs on the
# event loop itself, so blocking work inside it stops the whole server.
# Everything here blocks - SQLAlchemy, bcrypt, BERT inference - and there
# is not one await, so async cost everything and added nothing: loading an
# inbox fires 50 scans and they ran one after another. Plain def puts them
# in a threadpool, where they genuinely overlap.
# ---------------------------------------------------------------------------

# The model loads in the background (see ML/bert_model.py). get_model
# returns None until it is ready, and until then scanning runs on the
# rule engine alone - so this import is cheap and never blocks.
try:
    from ML.bert_model import get_model as get_bert_model
except ImportError as exc:
    # torch/transformers not installed - a valid state, not a failure
    logger.warning("BERT לא זמין (%s) — מצב חוקים בלבד", exc)

    def get_bert_model():
        return None
except Exception:
    logger.exception("BERT: שגיאה בלתי צפויה בייבוא — מצב חוקים בלבד")

    def get_bert_model():
        return None


def _apply_thresholds(result: dict, corroborated: bool = True) -> dict:
    """Sets the risk band and the advice from the final score."""
    return risk_levels.apply(result, corroborated=corroborated)


def get_risk_score(sender: str, subject: str, content: str,
                   user_trusts_sender: bool = False) -> dict:
    result = detector.analyze_email(sender, subject, content)

    model = get_bert_model()
    if model is None:
        return result          # fallback: חוקים בלבד

    try:
        bert_score = model.predict_score(sender, subject, content)
    except Exception:
        logger.exception("BERT prediction failed — falling back to heuristics")
        return result

    rule_score = result["risk_score"]
    ensemble = combine(bert_score, rule_score, sender, subject, content,
                       user_trusts_sender=user_trusts_sender)
    result["risk_score"] = round(ensemble, 2)

    # The explanation shown to the user. A bare "semantic analysis (BERT)"
    # tag used to sit next to the rules' default "no suspicious
    # indicators", so a score of 99 arrived with a statement that nothing
    # was found. If the model decided, say so plainly - and say it is a
    # judgement about phrasing, not a finding you can point at.
    if bert_score >= 50:
        result["indicators"] = [
            i for i in result["indicators"]
            if i != "לא נמצאו אינדיקטורים חשודים"
        ]
        result["indicators"].append(
            f"הניסוח דומה לדפוסי פישינג שהמודל אומן עליהם "
            f"({bert_score:.0f}% ביטחון)"
        )
        if rule_score < 15:
            result["indicators"].append(
                "לא נמצאו סימנים טכניים בשולח, בקישורים או בניסוח"
            )

    # "High risk" is reserved for cases both engines agree on. With the
    # rules silent the score rests on the one signal known to flag
    # legitimate account and security mail; spending the top label on that
    # wears away what it means.
    return _apply_thresholds(result, corroborated=rule_score >= 15)


@router.post("/scan", response_model=RiskAnalysis, summary="Scan an email for phishing")
def scan_email(
    email_data: EmailInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    auth_user: User | None = Depends(get_optional_user),
):
    # Identity comes from the token when there is one. The address in the
    # body is scraped from Gmail's DOM, so it can be forged and need not
    # match the signed-in account - which left dashboards empty while the
    # scans were recorded under another identity.
    if auth_user:
        user = auth_user
    else:
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
    # Only a result from the current scoring version is reused; anything
    # older is rescanned and the record updated, so a change to the
    # formula reaches the inbox without the user clearing anything.
    content_hash = hashlib.sha256(
        (email_data.content or "").encode("utf-8")
    ).hexdigest()[:32]

    # The text has to match too. The list scan sends the preview and the
    # open-message scan the full body; without this the second would get
    # the first one's verdict and the body would never be examined.
    if (existing
            and existing.scoring_version == SCORING_VERSION
            and existing.content_hash == content_hash):
        # The reasons come back with the score - a rescanned message used
        # to show a number and no explanation. Records predating the
        # column fall back to the placeholder until they are rescored.
        try:
            saved = json.loads(existing.indicators) if existing.indicators else []
        except (ValueError, TypeError):
            saved = []
        return RiskAnalysis(
            risk_score=existing.risk_score,
            is_phishing=existing.is_phishing,
            risk_level=risk_levels.risk_level(existing.risk_score),
            indicators=saved or ["נסרק בעבר"],
            recommendation=risk_levels.recommendation(existing.risk_score),
            response_time=0.0,
        )

    analysis = get_risk_score(
        email_data.sender,
        email_data.subject,
        email_data.content,
        user_trusts_sender=is_trusted_by_user(db, user.id, email_data.sender),
    )

    if existing:
        was_phishing = existing.is_phishing
        existing.risk_score = analysis["risk_score"]
        existing.is_phishing = analysis["is_phishing"]
        existing.scoring_version = SCORING_VERSION
        existing.content_hash = content_hash
        existing.content = email_data.content[:500]
        existing.indicators = json.dumps(analysis["indicators"], ensure_ascii=False)
        email_record = existing
        # The counter counts unique messages, not scans. A
        # recomputation that changes the verdict should correct it
        # rather than add to it.
        if was_phishing and not analysis["is_phishing"]:
            user.phishing_blocked = max(0, user.phishing_blocked - 1)
        elif not was_phishing and analysis["is_phishing"]:
            user.phishing_blocked += 1
    else:
        was_phishing = False
        email_record = EmailRecord(
            user_id=user.id,
            sender=email_data.sender,
            subject=email_data.subject[:200],
            content=email_data.content[:500],
            risk_score=analysis["risk_score"],
            is_phishing=analysis["is_phishing"],
            scoring_version=SCORING_VERSION,
            content_hash=content_hash,
            indicators=json.dumps(analysis["indicators"], ensure_ascii=False),
        )
        db.add(email_record)
        user.total_scanned += 1
        if analysis["is_phishing"]:
            user.phishing_blocked += 1
    db.flush()

    recent = (
        db.query(EmailRecord)
        .filter(EmailRecord.user_id == user.id)
        .order_by(EmailRecord.scanned_at.desc())
        .limit(RECENT_EMAILS_WINDOW)
        .all()
    )
    if recent:
        user.risk_score = round(sum(e.risk_score for e in recent) / len(recent), 2)

    # An alert only on the *first* time a message counts as phishing.
    # Otherwise every recomputation of older mail - which any change to
    # the formula triggers - would mail the guardian again about the same
    # event, weeks after it arrived.
    newly_flagged = analysis["risk_score"] >= ALERT_THRESHOLD and not was_phishing

    if newly_flagged:
        db.add(Alert(
            user_id=user.id,
            email_id=email_record.id,
            risk_level=analysis["risk_level"],
            message=f"זוהה מייל פישינג מ-{email_data.sender}",
        ))

        if user.guardian_id:
            # A separate alert for the guardian, carrying the monitored
            # user's name - a guardian can watch several accounts, and the
            # user's own alert does not say whose it is.
            guardian = db.query(User).filter(User.id == user.guardian_id).first()
            db.add(Alert(
                user_id=user.guardian_id,
                email_id=email_record.id,
                risk_level=analysis["risk_level"],
                message=(
                    f"{user.name} קיבל מייל פישינג בסיכון "
                    f"{analysis['risk_score']}% מ-{email_data.sender}"
                ),
            ))

            # Mail the guardian in the background, so the response is not delayed
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


