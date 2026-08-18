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

import risk_levels
from scoring import combine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

# ---------------------------------------------------------------------------
# נקודות הקצה מוגדרות ב-def רגיל ולא ב-async def, בכוונה.
#
# ב-FastAPI, נקודת קצה async רצה *על לולאת האירועים עצמה*. כל פעולה
# חוסמת בתוכה עוצרת את כל השרת עד שתסתיים. הקוד כאן חוסם לחלוטין —
# שאילתות SQLAlchemy סינכרוניות, hashing של bcrypt, ובמסלול הסריקה גם
# הרצת BERT — ואין בו ולו await אחד. כלומר ה-async לא הוסיף דבר וגבה
# את כל המחיר: טעינת תיבה ששולחת 50 סריקות עיבדה אותן בזו אחר זו,
# בלי שום חפיפה.
#
# ב-def רגיל FastAPI מריץ את הפונקציה ב-threadpool, ובקשות מקבילות
# באמת רצות במקביל.
# ---------------------------------------------------------------------------

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


def _apply_thresholds(result: dict, corroborated: bool = True) -> dict:
    """קובע רמת סיכון והמלצה לפי הציון הסופי."""
    return risk_levels.apply(result, corroborated=corroborated)


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

    rule_score = result["risk_score"]
    ensemble = combine(bert_score, rule_score, sender, subject, content)
    result["risk_score"] = round(ensemble, 2)

    # ההסבר למשתמש.
    #
    # קודם נוסף כאן התג "ניתוח סמנטי (BERT)" לצד הרשימה הקיימת. כשמנוע
    # החוקים לא מצא דבר, הרשימה הכילה את ברירת המחדל "לא נמצאו
    # אינדיקטורים חשודים" — והמשתמש ראה ציון 99 עם ההסבר שלא נמצא שום
    # דבר חשוד. סתירה מוחלטת, ובלי שום דרך להבין למה המייל סומן.
    #
    # אם המודל הוא שהכריע, צריך לומר את זה במפורש ולציין שזו הערכת
    # ניסוח ולא ממצא שאפשר להצביע עליו.
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

    # רמת "סכנה גבוהה" נשמרת למקרים ששני המנועים מסכימים עליהם.
    #
    # כשמנוע החוקים שותק, הציון נשען על סיגנל אחד בלבד — וזה הסיגנל
    # שידוע שהוא מסמן דואר לגיטימי בענייני חשבון, אבטחה ושיווק. הצגת
    # "סכנה גבוהה" על סמך עדות יחידה כזאת שוחקת את משמעות הדרגה, ועם
    # הזמן גם את האמון בכל התרעה אחרת.
    return _apply_thresholds(result, corroborated=rule_score >= 15)


@router.post("/scan", response_model=RiskAnalysis, summary="סריקת מייל לזיהוי פישינג")
def scan_email(
    email_data: EmailInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    auth_user: User | None = Depends(get_optional_user),
):
    # זהות המשתמש נלקחת מהטוקן כשהוא קיים. הכתובת בגוף הבקשה מגיעה
    # מגירוד ה-DOM של Gmail, ולכן היא גם ניתנת לזיוף וגם עלולה שלא
    # להתאים לחשבון שאיתו המשתמש התחבר לאתר — מה שהותיר את לוח
    # הבקרה שלו ריק בזמן שהסריקות נרשמו תחת זהות אחרת.
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
    # תוצאה שמורה מוחזרת רק אם חושבה בגרסת הניקוד הנוכחית. אחרת
    # המייל נסרק מחדש והרשומה הקיימת מתעדכנת — כך שינוי בנוסחה או
    # בסף משתקף בתיבה בלי שהמשתמש יצטרך לנקות דבר, והחיסכון נשמר
    # לכל שאר המיילים.
    content_hash = hashlib.sha256(
        (email_data.content or "").encode("utf-8")
    ).hexdigest()[:32]

    # תוצאה שמורה נכונה רק אם גם הנוסחה וגם הטקסט זהים. סריקת הרשימה
    # שולחת את התצוגה המקדימה, וסריקת המייל הפתוח את הגוף המלא —
    # בלי השוואת הטקסט השנייה הייתה מקבלת את תוצאת הראשונה, והגוף
    # המלא לא היה נבדק אף פעם.
    if (existing
            and existing.scoring_version == SCORING_VERSION
            and existing.content_hash == content_hash):
        return RiskAnalysis(
            risk_score=existing.risk_score,
            is_phishing=existing.is_phishing,
            risk_level=risk_levels.risk_level(existing.risk_score),
            indicators=["נסרק בעבר"],
            recommendation=risk_levels.recommendation(existing.risk_score),
            response_time=0.0,
        )

    analysis = get_risk_score(
        email_data.sender,
        email_data.subject,
        email_data.content,
    )

    if existing:
        was_phishing = existing.is_phishing
        existing.risk_score = analysis["risk_score"]
        existing.is_phishing = analysis["is_phishing"]
        existing.scoring_version = SCORING_VERSION
        existing.content_hash = content_hash
        existing.content = email_data.content[:500]
        email_record = existing
        # המונה סופר מיילים ייחודיים, לא סריקות. חישוב מחדש שמשנה
        # סיווג צריך לתקן אותו ולא להוסיף לו.
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

    # התראה נוצרת רק כשמייל נחשב לפישינג *לראשונה*. בלי התנאי הזה
    # כל חישוב מחדש של מייל ישן — מה שקורה בכל שינוי בנוסחת הניקוד —
    # היה מוסיף התראה כפולה ושולח למפקח מייל נוסף על אותו אירוע.
    # המפקח היה מוצף בהתראות על דואר שקיבל לפני שבועות.
    newly_flagged = analysis["risk_score"] >= ALERT_THRESHOLD and not was_phishing

    if newly_flagged:
        db.add(Alert(
            user_id=user.id,
            email_id=email_record.id,
            risk_level=analysis["risk_level"],
            message=f"זוהה מייל פישינג מ-{email_data.sender}",
        ))

        if user.guardian_id:
            # התראה נפרדת עבור המפקח. היא נושאת את שם המנוטר, ולכן
            # היא זו שמוצגת בלוח הבקרה שלו — מפקח יכול לנטר יותר
            # מחשבון אחד, וההתראה של המנוטר עצמה אינה אומרת של מי.
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


