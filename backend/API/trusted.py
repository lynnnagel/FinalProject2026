"""
The user's list of known senders.

GET    /trusted-senders          - the list
POST   /trusted-senders          - add one
DELETE /trusted-senders/{value}  - remove one

The system knows the large brands, but a person's inbox is full of
addresses nobody has heard of: an office they write to, a teacher, a
supplier. For those there is no positive evidence of legitimacy at all,
so entirely ordinary mail gets a high score on the model's guess alone.
This list is the missing evidence.

It is personal: what one user recognises says nothing about another, so
it is filtered by the user in the token and never by a request field.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from API.auth import get_current_user
from database import get_db
from detector import detector
from models import User, TrustedSender, EmailRecord
from schemas import TrustedSenderRequest, TrustedSenderList, TrustedSenderItem

router = APIRouter(tags=["trusted"])

# Rule score above which a sender can no longer be marked as known.
#
# The feature lets a user damp the model's score, and that is its weak
# point: an attacker who talks the user into clicking "I know this
# sender" earns a damping on every future message from that address.
# This check stops it at the root - an address the rule engine has found
# real evidence against cannot be marked at all.
#
# 30 is the level above which there is a substantive finding rather than
# weak words alone: brand impersonation in the body (30), in the subject
# (45), an official-sounding organisation on a free mailbox (30).
MAX_RULE_SCORE_FOR_TRUST = 30

_EMAIL_RE = re.compile(r"^[^@\s]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

MAX_ENTRIES = 500   # sane cap; keeps the table from ballooning


def normalise(raw: str) -> tuple[str, bool]:
    """
    Returns (normalised value, whether it is a domain).

    Accepts a full address or a domain. A value with @ is kept as is; a
    value without one counts as a domain, which lets a user trust an
    organisation that writes from several addresses.
    """
    value = (raw or "").strip().lower().lstrip("@")
    if not value:
        raise HTTPException(400, "כתובת ריקה")
    if "@" in value:
        if not _EMAIL_RE.match(value):
            raise HTTPException(400, "כתובת מייל לא תקינה")
        return value, False
    if not _DOMAIN_RE.match(value):
        raise HTTPException(400, "דומיין לא תקין")

    # Trusting a whole free-mail provider is destructive: it disables
    # detection for *every* phishing message sent from Gmail, one of the
    # commonest channels there is. A single address from that provider
    # is fine, since it concerns one person.
    if value in detector.FREE_EMAIL_PROVIDERS:
        raise HTTPException(
            400,
            f"לא ניתן לסמן דומיין שלם של ספק דואר חינמי ({value}). "
            "אפשר לסמן כתובת מלאה במקום."
        )
    return value, True


def _rule_evidence_against(db: Session, user_id: int,
                           value: str, is_domain: bool) -> tuple[float, list[str]]:
    """
    Re-runs the rule engine over the stored mail from that sender.

    The question it answers: does the system already have evidence
    against this address? It runs over the stored text rather than the
    stored score, because that score includes the model - and the model
    is exactly what the mark is meant to damp. Only the hard findings
    matter here.
    """
    q = db.query(EmailRecord).filter(EmailRecord.user_id == user_id)
    q = q.filter(EmailRecord.sender.ilike(f"%@{value}" if is_domain else f"%{value}%"))

    worst, worst_indicators = 0.0, []
    for record in q.order_by(EmailRecord.scanned_at.desc()).limit(50):
        analysis = detector.analyze_email(
            record.sender or "", record.subject or "", record.content or ""
        )
        if analysis["risk_score"] > worst:
            worst = analysis["risk_score"]
            worst_indicators = analysis["indicators"]
    return worst, worst_indicators


def matches(sender: str, entries: list[TrustedSender]) -> bool:
    """Is the sender on the list, directly or through its domain?"""
    address = (sender or "").strip().lower()
    match = re.search(r"@([A-Za-z0-9.\-]+)", address)
    domain = match.group(1).rstrip(".") if match else ""

    for entry in entries:
        if not entry.is_domain:
            if address == entry.value:
                return True
        elif domain and (domain == entry.value
                         or domain.endswith("." + entry.value)):
            return True
    return False


def is_trusted_by_user(db: Session, user_id: int, sender: str) -> bool:
    return matches(sender, db.query(TrustedSender)
                   .filter(TrustedSender.user_id == user_id).all())


def _invalidate_cached_scores(db: Session, user_id: int, value: str,
                              is_domain: bool) -> int:
    """
    Marks that sender's stored scans for recomputation.

    Without this, marking a sender would change nothing in the inbox:
    the verdicts are already cached, and the next scan would hand them
    back unchanged. Clearing the version stamp makes the next scan
    recompute them, without deleting any history.
    """
    q = db.query(EmailRecord).filter(EmailRecord.user_id == user_id)
    if is_domain:
        q = q.filter(EmailRecord.sender.ilike(f"%@{value}"))
    else:
        q = q.filter(EmailRecord.sender.ilike(f"%{value}%"))
    affected = q.update({EmailRecord.scoring_version: ""},
                        synchronize_session=False)
    db.commit()
    return affected


@router.get("/trusted-senders", response_model=TrustedSenderList,
            summary="The user's known senders")
def list_trusted(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(TrustedSender)
        .filter(TrustedSender.user_id == current_user.id)
        .order_by(TrustedSender.created_at.desc())
        .all()
    )
    return TrustedSenderList(
        senders=[
            TrustedSenderItem(value=r.value, is_domain=r.is_domain)
            for r in rows
        ]
    )


@router.post("/trusted-senders", summary="Mark a sender as known")
def add_trusted(
    request: TrustedSenderRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    value, is_domain = normalise(request.value)

    count = (
        db.query(TrustedSender)
        .filter(TrustedSender.user_id == current_user.id)
        .count()
    )
    if count >= MAX_ENTRIES:
        raise HTTPException(400, f"הרשימה מוגבלת ל-{MAX_ENTRIES} רשומות")

    # Hard evidence outranks what the user says.
    #
    # The user testifying that they know an address is worth something,
    # but it does not override a finding from the rule engine. If the
    # address impersonates a brand or writes from a forged domain, the
    # person asking to trust it may well be the one being deceived -
    # which is precisely what the attacker is working toward: getting
    # the victim to switch off the protection themselves.
    evidence, indicators = _rule_evidence_against(db, current_user.id,
                                                  value, is_domain)
    if evidence >= MAX_RULE_SCORE_FOR_TRUST:
        raise HTTPException(
            400,
            "לא ניתן לסמן את הכתובת הזאת כמוכרת: נמצאו בה סימנים "
            "מובהקים של התחזות. " + " · ".join(indicators[:3])
        )

    existing = (
        db.query(TrustedSender)
        .filter(TrustedSender.user_id == current_user.id,
                TrustedSender.value == value)
        .first()
    )
    if not existing:
        db.add(TrustedSender(user_id=current_user.id, value=value,
                             is_domain=is_domain))
        db.commit()

    rescored = _invalidate_cached_scores(db, current_user.id, value, is_domain)
    return {
        "message": "השולח סומן כמוכר",
        "value": value,
        "is_domain": is_domain,
        "rescored": rescored,
    }


@router.delete("/trusted-senders/{value:path}", summary="Remove a known sender")
def remove_trusted(
    value: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    normalised, is_domain = normalise(value)
    row = (
        db.query(TrustedSender)
        .filter(TrustedSender.user_id == current_user.id,
                TrustedSender.value == normalised)
        .first()
    )
    if not row:
        raise HTTPException(404, "השולח אינו ברשימה")

    db.delete(row)
    db.commit()
    rescored = _invalidate_cached_scores(db, current_user.id, normalised, is_domain)
    return {"message": "השולח הוסר מהרשימה", "value": normalised,
            "rescored": rescored}
