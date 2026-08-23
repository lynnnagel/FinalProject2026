"""
רשימת השולחים המוכרים של המשתמש.

GET    /trusted-senders          – הרשימה
POST   /trusted-senders          – הוספה
DELETE /trusted-senders/{value}  – הסרה

המערכת מכירה מותגים גדולים, אבל תיבה של אדם מלאה בכתובות שאיש לא שמע
עליהן: משרד שהוא מתכתב איתו, מורה, ספק. עבורן אין שום ראיה חיובית
ללגיטימיות, ולכן מייל תקין לחלוטין מקבל ציון גבוה על סמך ניחוש המודל
בלבד. הרשימה הזאת היא הראיה החסרה.

היא אישית: מה שמוכר למשתמש אחד אינו אומר דבר על משתמש אחר, ולכן היא
מסוננת לפי המשתמש שבטוקן ולא לפי פרמטר בבקשה.
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

# ניקוד חוקים שמעליו לא ניתן לסמן שולח כמוכר.
#
# הפיצ'ר נותן למשתמש להנמיך את ציון המודל, וזו נקודת התורפה שלו:
# תוקף שישכנע את המשתמש ללחוץ "אני מכיר את השולח הזה" ירוויח הנמכה
# על כל מייל עתידי מאותה כתובת. הסינון כאן מונע את זה בשורש — כתובת
# שמנוע החוקים מצא בה ראיות של ממש אינה ניתנת לסימון בכלל.
#
# 30 הוא הרף שמעליו יש ממצא מהותי ולא רק מילים חלשות: התחזות למותג
# בגוף (30), התחזות בנושא (45), ארגון רשמי מכתובת חינמית (30).
MAX_RULE_SCORE_FOR_TRUST = 30

_EMAIL_RE = re.compile(r"^[^@\s]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

MAX_ENTRIES = 500   # תקרה שפויה; מונעת ניפוח של הטבלה


def normalise(raw: str) -> tuple[str, bool]:
    """
    מחזיר (ערך מנורמל, האם זהו דומיין).

    מקבל כתובת מלאה או דומיין. ערך עם @ נשמר כמות שהוא; ערך בלי @
    נחשב לדומיין, מה שמאפשר לסמוך על ארגון ששולח מכמה כתובות.
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

    # אמון ברמת דומיין על ספק דואר חינמי הוא הרסני: הוא מנטרל את
    # הזיהוי עבור *כל* פישינג שנשלח מ-Gmail, אחד הערוצים הנפוצים
    # ביותר. כתובת בודדת מאותו ספק מותרת, כי היא נוגעת לאדם אחד.
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
    מריץ מחדש את מנוע החוקים על המיילים השמורים מאותו שולח.

    השאלה שהוא עונה עליה: האם למערכת יש כבר ראיות שהכתובת הזאת
    בעייתית. הריצה נעשית על התוכן השמור ולא על הציון השמור, כי הציון
    כולל גם את המודל — ודווקא המודל הוא מה שהסימון אמור להנמיך.
    כאן מעניינות רק הראיות הקשות.
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
    """האם השולח מופיע ברשימה, ישירות או דרך הדומיין שלו."""
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
    מסמן את הסריקות השמורות של אותו שולח לחישוב מחדש.

    בלי זה, סימון שולח כמוכר לא היה משנה דבר בתיבה: התוצאות כבר
    שמורות, והסריקה הבאה הייתה מחזירה אותן כמות שהן. איפוס חותמת
    הגרסה גורם לסריקה הבאה לחשב מחדש — בלי למחוק את ההיסטוריה.
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
            summary="השולחים המוכרים של המשתמש")
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


@router.post("/trusted-senders", summary="סימון שולח כמוכר")
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

    # ראיות קשות גוברות על הצהרת המשתמש.
    #
    # המשתמש מעיד שהוא מכיר את הכתובת, וזו עדות בעלת ערך — אבל היא
    # אינה גוברת על ממצא של מנוע החוקים. אם הכתובת מתחזה למותג או
    # שולחת מדומיין מזויף, ייתכן מאוד שהמשתמש הוא זה שהוטעה, וזו
    # בדיוק המטרה של התוקף: לגרום לקורבן לנטרל את ההגנה בעצמו.
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


@router.delete("/trusted-senders/{value:path}", summary="הסרת שולח מוכר")
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
