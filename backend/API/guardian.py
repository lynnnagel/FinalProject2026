"""
Guardian mode.

    POST /guardian/connect       link an address to the caller
    POST /guardian/disconnect    remove a link (either side may)
    GET  /guardian/watched       every account the caller watches
    GET  /guardian/{email}       the older single-account dashboard
"""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from API.auth import get_current_user
from database import get_db
from models import User, Alert, EmailRecord
from email_service import send_guardian_link_notice
from schemas import (GuardianConnectRequest, GuardianData,
                     WatchedAccount, WatchedList)
from utils import get_name_from_email, today_start
from config import ALERT_HISTORY_LIMIT

router = APIRouter(prefix="/guardian", tags=["guardian"])


@router.post("/connect", summary="Link a guardian to a monitored account")
def connect_guardian(
    request: GuardianConnectRequest,
    background_tasks: BackgroundTasks,
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

    already_linked = child.guardian_id == parent.id
    child.guardian_id = parent.id
    db.commit()

    # Guardian mode is set up by the guardian alone, so the monitored
    # person would otherwise never learn of it. Only on a new link -
    # re-linking an account already watched by the same guardian is not
    # news, and would let the form be used to send repeated mail.
    #
    # In the background: a mail that cannot go out must not fail the
    # request that created the link.
    if not already_linked:
        background_tasks.add_task(
            send_guardian_link_notice,
            to_email=child.email,
            monitored_name=child.name,
            guardian_email=parent.email,
            guardian_name=parent.name,
        )

    # The state travels back with the response so the page can say what
    # is still missing without a second round trip.
    return {
        "message": "מצב מפקח הופעל בהצלחה",
        "child": str(request.child_email),
        "guardian": parent.email,
        "notified": not already_linked,
        "state": _setup_state(child),
    }


@router.post("/disconnect", summary="Unlink a guardian")
def disconnect_guardian(
    request: GuardianConnectRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Removes the link.

    Either side may do it: the guardian who set it, or the monitored
    account itself. Without the second case someone could be watched
    with no way to stop it - the guardian was the only one who could
    undo what only the guardian could start.
    """
    child = db.query(User).filter(User.email == str(request.child_email)).first()
    if not child or child.guardian_id is None:
        raise HTTPException(status_code=404, detail="חיבור מפקח לא נמצא")
    if current_user.id not in (child.guardian_id, child.id):
        raise HTTPException(status_code=403, detail="אין הרשאה להסיר את השיוך הזה")

    # Read the guardian off the link before clearing it. Reporting the
    # caller instead was fine while only the guardian could call this.
    removed = db.query(User).filter(User.id == child.guardian_id).first()
    child.guardian_id = None
    db.commit()

    return {
        "message": "מצב מפקח נותק בהצלחה",
        "child": str(request.child_email),
        "guardian": removed.email if removed else "",
    }


# ---------------------------------------------------------------------------
def _setup_state(child: User) -> str:
    """
    How far a watched account is through setup.

    Linking is only the first of three steps. Until the person opens an
    account there is nothing to sign the extension in as, and until the
    extension runs there is nothing to scan - so a link on its own sends
    no alerts at all. Naming the missing step is the whole point.
    """
    if not child.password_hash:
        return "needs_account"
    if not child.total_scanned:
        return "needs_extension"
    return "active"


def _watched_account(child: User, db: Session) -> WatchedAccount:
    blocked_today = (
        db.query(EmailRecord)
        .filter(
            EmailRecord.user_id == child.id,
            EmailRecord.is_phishing == True,          # noqa: E712
            EmailRecord.scanned_at >= today_start(),
        )
        .count()
    )
    last = (
        db.query(EmailRecord)
        .filter(EmailRecord.user_id == child.id)
        .order_by(EmailRecord.scanned_at.desc())
        .first()
    )
    return WatchedAccount(
        email=child.email,
        name=child.name,
        state=_setup_state(child),
        risk_score=child.risk_score or 0.0,
        total_scanned=child.total_scanned or 0,
        phishing_blocked_today=blocked_today,
        last_scan=last.scanned_at.strftime("%d/%m/%Y %H:%M") if last else None,
    )


@router.get("/watched", response_model=WatchedList,
            summary="Every account this guardian watches")
def list_watched(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    The guardian's own list, taken from the token.

    This route is declared before /{parent_email} on purpose: FastAPI
    matches in order, and the path parameter would otherwise swallow
    "watched" and try to read it as an address.
    """
    children = (
        db.query(User)
        .filter(User.guardian_id == current_user.id)
        .order_by(User.email)
        .all()
    )
    return WatchedList(accounts=[_watched_account(c, db) for c in children])


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