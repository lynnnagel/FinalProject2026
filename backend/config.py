"""
LURA – Central configuration.
All tuneable constants live here so they can be changed in one place.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

# ---------------------------------------------------------------------------
# Security
# SECRET_KEY signs the JWTs. It has no default on purpose: a hard-coded
# fallback in a public repository lets anyone forge a token for any user.
# Generate one with:  python -c "import secrets; print(secrets.token_hex(32))"
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY חסר.\n"
        "צור מפתח:  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "והוסף אותו ל-backend/.env בשורה:  SECRET_KEY=<המפתח שנוצר>"
    )

JWT_ALGORITHM = "HS256"
TOKEN_TTL_DAYS = 7            # תוקף טוקן התחברות
RESET_TOKEN_TTL_MINUTES = 30  # תוקף קישור איפוס סיסמה

# כתובת הבסיס שממנה נבנים קישורים שנשלחים במייל
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./lura.db")

# ---------------------------------------------------------------------------
# CORS
# Allow Chrome / Firefox extensions and localhost (dev).
# In production, replace with explicit extension IDs.
# ---------------------------------------------------------------------------
# סקריפט התוכן של התוסף רץ בתוך הדף של Gmail, ולכן ה-Origin של
# בקשותיו הוא https://mail.google.com ולא chrome-extension://.
# בלי הרשומה הזאת בקשת ה-preflight (OPTIONS /scan) נדחית ב-400,
# ה-POST לעולם אינו נשלח, והתוסף אינו מסמן דבר.
CORS_ORIGIN_REGEX = (
    r"chrome-extension://.*"
    r"|moz-extension://.*"
    r"|https://mail\.google\.com"
    r"|https://.*\.mail\.google\.com"
    r"|http://localhost(:\d+)?"
    r"|http://127\.0\.0\.1(:\d+)?"
)

# ---------------------------------------------------------------------------
# Phishing detection thresholds (0-100 score)
#
# PHISHING_THRESHOLD הוא הערך היחיד שמכיילים. שאר הרמות נגזרות ממנו
# ואינן נקבעות בנפרד, כי ארבעה מספרים בלתי תלויים נוטים להיפרד זה מזה:
# כשהסף היה 70 והרמות 30/50/80 הכול היה עקבי, אבל ברגע שהסף יורד ל-35
# — כפי שהכיול על נתונים אמיתיים מחייב — מייל שמקבל 40 מסומן
# is_phishing=True ובו בזמן מוצג למשתמש כ"זהירות" בלבד, כי 40 קטן
# מ-MEDIUM=50. התוסף היה מציג הרגעה על מייל שהמערכת סיווגה כפישינג.
#
# הגזירה שומרת על היחסים המקוריים: בסף 70 היא מחזירה 42/70/84,
# קרוב מאוד ל-30/50/80 שנבחרו ידנית בתחילת הפרויקט.
#
# את הערך עצמו קובעים לפי:  python ML/sanity_check.py
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD = 57       # >= זה → מסווג כפישינג

# "חשוד" מתחיל בדיוק בסף הסיווג — אין תחום שבו מייל הוא פישינג
# אך אינו חשוד.
MEDIUM_RISK_THRESHOLD = PHISHING_THRESHOLD

# "זהירות": 60% מהסף — סימנים חלקיים, לא מספיקים לסיווג.
LOW_RISK_THRESHOLD = round(PHISHING_THRESHOLD * 0.6)

# "סכנה גבוהה": 45% מהדרך מהסף אל 100.
HIGH_RISK_THRESHOLD = round(PHISHING_THRESHOLD + (100 - PHISHING_THRESHOLD) * 0.45)

# שומר שכיול עתידי לא יערבב את הסדר
assert 0 < LOW_RISK_THRESHOLD < MEDIUM_RISK_THRESHOLD <= PHISHING_THRESHOLD \
       < HIGH_RISK_THRESHOLD <= 100, \
       f"רמות סיכון לא עקביות: {LOW_RISK_THRESHOLD}/{MEDIUM_RISK_THRESHOLD}/" \
       f"{HIGH_RISK_THRESHOLD} עם סף {PHISHING_THRESHOLD}"

# ---------------------------------------------------------------------------
# שילוב שני המנועים  (ראה backend/scoring.py לנוסחה ולנימוק)
#
#     score = max( bert·damping + RULE_BOOST·rules ,  rules )
#
# הגרסה הקודמת חישבה ממוצע משוקלל, BERT_WEIGHT·bert + HEURISTIC_WEIGHT·rules.
# היא נזנחה אחרי מדידה: הממוצע הטיל תקרה של BERT_WEIGHT·100 על ציון
# ה-BERT, כך שהמודל לא יכול היה לחצות את הסף לבדו. על סט הבדיקה זה
# נתן 52.8% דיוק ו-93.6% פספוסים, לעומת 99.4% ל-BERT לבדו.
# ---------------------------------------------------------------------------

# כמה ציון החוקים מוסיף על גבי BERT. 0.5 → עד 50 נקודות חיזוק.
RULE_BOOST = float(os.getenv("RULE_BOOST", "0.5"))

# מכפיל לציון BERT כששולח המייל הוא דומיין של חברה מוכרת. 0.25 → ציון
# 99.99 יורד ל-25, מתחת לכל סף סביר. מכוון לכשל מתועד של המודל על דואר
# לגיטימי בענייני חשבון ואבטחה, ודורש ראיה חיובית — דומיין שולח מוכר —
# ולא רק שקט של מנוע החוקים.
TRUST_DAMPING = float(os.getenv("TRUST_DAMPING", "0.25"))

# מכפיל לציון BERT כשהמייל מזוהה כדיוור שיווקי או התראת שירות ואין בו
# בקשת אישורים. 0.30 → ציון 100 יורד ל-30, מתחת לסף. הקורפוסים מתייגים
# ספאם יחד עם פישינג באותה מחלקה, ולכן המודל אינו מבדיל ביניהם: פרסומת
# מקבלת 99.99 בדיוק כמו בקשה לפרטי אשראי. LURA מזהה פישינג ולא ספאם,
# וסימון פרסומת כ"סכנה" שוחק את אמון המשתמש בכל שאר ההתרעות.
PROMO_DAMPING = float(os.getenv("PROMO_DAMPING", "0.30"))

# מכפיל לציון BERT על דואר תפעולי מחברה מזוהה — אישור הזמנה, הודעת
# משלוח, קבלה. זו הקטגוריה שהמערכת טעתה בה יותר מכל: המבנה שלה מפעיל
# את מנוע החוקים (הרבה קישורים, "order", "account"), והמודל מסמן אותה
# כמעט תמיד. ההנמכה חדה יותר מהאחרות כי כאן יש שתי ראיות עצמאיות
# ללגיטימיות — השולח הוא החברה עצמה, וכל הקישורים מובילים אליה.
TRANSACTIONAL_DAMPING = float(os.getenv("TRANSACTIONAL_DAMPING", "0.10"))

# ניקוד מרבי כשרק מנוע אחד תרם לציון.
#
# כשמנוע החוקים שותק, ההכרעה נשענת על עדות יחידה — והיא זו שידוע
# שמסמנת דואר לגיטימי משולח שאינו מוכר לה. ציון 99 במצב כזה מבטיח
# ודאות שאין. התקרה היא ראש תחום "חשוד", ולכן המספר והתווית אומרים
# את אותו הדבר: יש חשד, אין ודאות.
#
# הסיווג עצמו נשמר — 75 גבוה מהסף — ולכן ההתראה נרשמת והמפקח מקבל
# הודעה. מה שמשתנה הוא רק מידת הביטחון שהמערכת מציגה.
UNCORROBORATED_CEILING = HIGH_RISK_THRESHOLD - 1

# ניקוד חוקים שמתחתיו נחשב שהמנוע לא מצא דבר של ממש.
CORROBORATION_FLOOR = 15

# חותמת שמזהה את נוסחת הניקוד הנוכחית. תוצאות סריקה נשמרות במסד כדי
# שמייל שכבר נבדק לא יעבור שוב דרך BERT — זה החלק היקר בצינור. החותמת
# היא מה שמאפשר את החיסכון בלי לשלם עליו בתוצאות מיושנות: היא נגזרת
# מהפרמטרים, ולכן כל שינוי בהם פוסל אוטומטית את כל הציונים שחושבו
# לפניו, והם מחושבים מחדש בסריקה הבאה.
SCORING_VERSION = (
    f"v4|b{RULE_BOOST}|t{TRUST_DAMPING}|p{PROMO_DAMPING}"
    f"|x{TRANSACTIONAL_DAMPING}|th{PHISHING_THRESHOLD}"
)

# נשמרים לתאימות לאחור עבור ML/calibrate.py, שסורק את הנוסחה הישנה
# לשם השוואה. הצינור החי אינו משתמש בהם.
BERT_WEIGHT = float(os.getenv("BERT_WEIGHT", "0.4"))
HEURISTIC_WEIGHT = float(os.getenv("HEURISTIC_WEIGHT", "0.6"))

# ---------------------------------------------------------------------------
# Heuristic scoring weights
# ---------------------------------------------------------------------------
MAX_KEYWORD_SCORE = 40        # Cap for keyword contribution
KEYWORD_SCORE_PER_WORD = 15   # ניקוד לכל ניסוח אופייני לפישינג
WEAK_KEYWORD_SCORE = 4        # מילה שמופיעה גם במייל לגיטימי
MAX_WEAK_KEYWORD_SCORE = 16   # תקרה נמוכה — לבדן הן לא מספיקות
SUSPICIOUS_DOMAIN_SCORE = 25  # Suspicious sender patterns
MULTIPLE_URLS_SCORE = 20      # More than URL_COUNT_THRESHOLD links
URGENCY_SCORE = 15            # Artificial-urgency words
INVALID_DOMAIN_SCORE = 20     # Sender domain not in whitelist
BRAND_IMPERSONATION_SCORE = 45  # מותג מוכר בנושא, שולח מדומיין אחר
BODY_IMPERSONATION_SCORE = 30   # המותג רק בגוף — סיגנל חלש יותר
URL_COUNT_THRESHOLD = 2       # Number of URLs above which we penalise

# ---------------------------------------------------------------------------
# Database / query limits
# ---------------------------------------------------------------------------
RECENT_EMAILS_WINDOW = 10     # Rolling average window for user risk score

# שני אלה היו 70 — כלומר בדיוק סף הסיווג דאז. הם נגזרים ממנו כדי שלא
# ייווצר מצב שמייל מסווג כפישינג אך לא נרשמת עליו התראה והמפקח אינו
# מקבל הודעה. עם סף 35 וערך קבוע 70, מצב מפקח היה מפספס את רוב
# הזיהויים — כולל התחזות למותג שהחוקים נותנים לה ניקוד בינוני.
ALERT_THRESHOLD = PHISHING_THRESHOLD           # ניקוד מינימלי לרישום Alert
GUARDIAN_NOTIFY_THRESHOLD = PHISHING_THRESHOLD  # ניקוד מינימלי להודעה למפקח
ALERT_HISTORY_LIMIT = 5       # Alerts returned in guardian dashboard


# ---------------------------------------------------------------------------
# Email / SMTP –
# ---------------------------------------------------------------------------
SMTP_HOST       = os.getenv("SMTP_HOST",       "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT",   "587"))
SMTP_USER       = os.getenv("SMTP_USER",       "")   # מייל השולח
SMTP_PASSWORD   = os.getenv("SMTP_PASSWORD",   "")   # App Password
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "LURA")
EMAIL_ENABLED   = os.getenv("EMAIL_ENABLED",   "false").lower() == "true"