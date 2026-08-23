"""
LURA – תרגום ציון מספרי לרמת סיכון ולהמלצה למשתמש.

מודול נפרד ותלוי-config בלבד, כדי שגם `detector` וגם `scoring` וגם
שכבת ה-API יוכלו לייבא אותו בלי מעגל ייבוא.

הוא קיים כי הלוגיקה הזאת שוכפלה שלוש פעמים, ושני עותקים נשארו מאחור.
העותק ב-`API/scan.py` שימש את מסלול התוצאה השמורה עם ספים קשיחים
(80/50/30) שכבר לא תאמו את הספים האמיתיים — ולכן אותו מייל בדיוק קיבל
תווית אחת בסריקה ראשונה ותווית אחרת כשהוחזר מהמטמון.
"""
from config import (
    PHISHING_THRESHOLD,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD,
)

# הטקסטים נטולי אימוג'י בכוונה. ההודעה מופיעה בתוך Gmail לצד מיילים
# אמיתיים, ובהקשר של אבטחה ניסוח ענייני קורא כמו כלי ולא כמו התראה
# אוטומטית.
_LEVELS = (
    (HIGH_RISK_THRESHOLD,   "סכנה גבוהה", "אל תלחץ על שום קישור. מחק את המייל."),
    (MEDIUM_RISK_THRESHOLD, "חשוד",       "בדוק את זהות השולח לפני כל פעולה."),
    (LOW_RISK_THRESHOLD,    "זהירות",     "המייל מכיל סימנים חריגים. כדאי לשים לב."),
    (float("-inf"),         "בטוח",       "לא נמצאו סימנים חשודים."),
)


def risk_level(score: float) -> str:
    """שם רמת הסיכון עבור ציון."""
    return next(name for cutoff, name, _ in _LEVELS if score >= cutoff)


def recommendation(score: float) -> str:
    """ההמלצה המוצגת למשתמש עבור ציון."""
    return next(text for cutoff, _, text in _LEVELS if score >= cutoff)


def is_phishing(score: float) -> bool:
    return score >= PHISHING_THRESHOLD


def apply(result: dict, corroborated: bool = True) -> dict:
    """
    מוסיף is_phishing, risk_level ו-recommendation לפי risk_score.

    corroborated נשמר בחתימה לתאימות, אך אינו משנה עוד את התווית:
    ריסון המקרה הלא-מתומך נעשה על הציון עצמו ב-scoring.combine, כך
    שהמספר והתווית נגזרים מאותו מקור ואינם יכולים לסתור זה את זה.
    ריסון התווית בלבד הותיר ציון 99 לצד הכיתוב "חשוד".
    """
    score = result["risk_score"]
    result["is_phishing"] = is_phishing(score)
    result["risk_level"] = risk_level(score)
    result["recommendation"] = recommendation(score)
    return result
