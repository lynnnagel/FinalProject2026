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
CORS_ORIGIN_REGEX = (
    r"chrome-extension://.*"
    r"|moz-extension://.*"
    r"|http://localhost.*"
    r"|http://127\.0\.0\.1.*"
)

# ---------------------------------------------------------------------------
# Phishing detection thresholds (0-100 score)
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD = 70       # >= 70 → classified as phishing
HIGH_RISK_THRESHOLD = 80      # >= 80 → "סכנה גבוהה"
MEDIUM_RISK_THRESHOLD = 50    # >= 50 → "חשוד"
LOW_RISK_THRESHOLD = 30       # >= 30 → "זהירות"

# ---------------------------------------------------------------------------
# Heuristic scoring weights
# ---------------------------------------------------------------------------
MAX_KEYWORD_SCORE = 40        # Cap for keyword contribution
KEYWORD_SCORE_PER_WORD = 15   # Points per suspicious keyword found
SUSPICIOUS_DOMAIN_SCORE = 25  # Suspicious sender patterns
MULTIPLE_URLS_SCORE = 20      # More than URL_COUNT_THRESHOLD links
URGENCY_SCORE = 15            # Artificial-urgency words
INVALID_DOMAIN_SCORE = 20     # Sender domain not in whitelist
URL_COUNT_THRESHOLD = 2       # Number of URLs above which we penalise

# ---------------------------------------------------------------------------
# Database / query limits
# ---------------------------------------------------------------------------
RECENT_EMAILS_WINDOW = 10     # Rolling average window for user risk score
ALERT_THRESHOLD = 70          # Min risk score to create an Alert record
GUARDIAN_NOTIFY_THRESHOLD = 70
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