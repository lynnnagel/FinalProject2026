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
# The endpoints are plain def, not async def, on purpose.
#
# In FastAPI an async endpoint runs *on the event loop itself*. Any
# blocking work inside it stops the whole server until it finishes. The
# code here blocks completely - synchronous SQLAlchemy queries, bcrypt
# hashing, and on the scan path BERT inference - and contains not one
# await. So the async added nothing and cost everything: loading an
# inbox fires 50 scans, and they were processed one after another with
# no overlap.
#
# With plain def, FastAPI runs the function in a threadpool and
# concurrent requests genuinely run at the same time.
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

    # The explanation shown to the user.
    #
    # This used to add a bare tag reading "semantic analysis (BERT)"
    # next to whatever the rules found. When the rules found nothing,
    # the list still held the default "no suspicious indicators" - so
    # the user saw a score of 99 alongside a statement that nothing
    # suspicious was found. A flat contradiction, with no way to tell
    # why the message was flagged.
    #
    # If the model is what decided, say so plainly, and say that this is
    # a judgement about phrasing rather than a finding you can point at.
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

    # "High risk" is reserved for cases both engines agree on.
    #
    # With the rule engine silent the score rests on a single signal -
    # and it is the signal known to flag legitimate account, security
    # and marketing mail. Showing "high risk" on that alone wears away
    # what the level means, and in time the user's trust in every other
    # alert.
    return _apply_thresholds(result, corroborated=rule_score >= 15)


@router.post("/scan", response_model=RiskAnalysis, summary="Scan an email for phishing")
def scan_email(
    email_data: EmailInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    auth_user: User | None = Depends(get_optional_user),
):
    # The user's identity comes from the token when there is one. The
    # address in the request body is scraped out of Gmail's DOM, so it
    # can be forged and it may not match the account the user signed in
    # with - which left their dashboard empty while the scans were
    # recorded under a different identity.
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
    # A stored result is returned only if it was computed by the
    # current scoring version. Otherwise the message is scanned again
    # and the existing record updated - so a change to the formula or
    # the threshold shows up in the inbox without the user clearing
    # anything, and the saving still applies to everything else.
    content_hash = hashlib.sha256(
        (email_data.content or "").encode("utf-8")
    ).hexdigest()[:32]

    # A stored result is only valid if both the formula and the text
    # match. The list scan sends the preview, the open-message scan
    # sends the full body - without comparing the text, the second would
    # receive the first one's verdict and the full body would never be
    # examined at all.
    if (existing
            and existing.scoring_version == SCORING_VERSION
            and existing.content_hash == content_hash):
        # The reasons come back with the score. They were once replaced
        # by a placeholder here, which meant a message scanned a second
        # time showed a number and no explanation - and the explanation
        # is the point of the product. Older records predate the column
        # and fall back to the placeholder until they are rescored.
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

    # An alert is created only the *first* time a message counts as
    # phishing. Without this, every recomputation of older mail - which
    # happens on any change to the scoring formula - would add a
    # duplicate alert and mail the guardian again about the same event.
    # The guardian would be flooded with alerts about mail received
    # weeks ago.
    newly_flagged = analysis["risk_score"] >= ALERT_THRESHOLD and not was_phishing

    if newly_flagged:
        db.add(Alert(
            user_id=user.id,
            email_id=email_record.id,
            risk_level=analysis["risk_level"],
            message=f"זוהה מייל פישינג מ-{email_data.sender}",
        ))

        if user.guardian_id:
            # A separate alert for the guardian. It carries the
            # monitored user's name, which is why it is the one shown on
            # their dashboard - a guardian can watch more than one
            # account, and the monitored user's own alert does not say
            # whose it is.
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


