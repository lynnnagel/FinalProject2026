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
# SECRET_KEY signs the JWTs. No default on purpose - a hard-coded fallback
# in a public repository lets anyone forge a token for any user.
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing.\n"
        "Generate one:  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "Then add it to backend/.env as:  SECRET_KEY=<the generated key>"
    )

JWT_ALGORITHM = "HS256"
TOKEN_TTL_DAYS = 7            # how long a login token stays valid
RESET_TOKEN_TTL_MINUTES = 30  # how long a password-reset link stays valid

# Base address used to build the links we send by mail
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./lura.db")

# ---------------------------------------------------------------------------
# CORS - extensions and localhost. In production, use explicit extension IDs.
#
# mail.google.com must be here: the content script runs inside the Gmail
# page, so that is the Origin on its requests. Without it the preflight
# (OPTIONS /scan) is refused with a 400 and nothing is ever marked.
# ---------------------------------------------------------------------------
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
# PHISHING_THRESHOLD is the only calibrated value; the bands are derived
# from it. Four independent numbers drift apart: with a fixed MEDIUM=50, a
# message scoring 40 under a threshold of 35 is is_phishing=True but shown
# as merely "caution" - the extension reassuring the user about mail the
# system just called phishing.
#
# To set it:  python ML/evaluate.py --split test --sweep
#             python ML/tradeoff.py    (precision at a real 1% base rate)
#
# 70, raised from 60. The score distribution is bimodal, so almost no
# message sits between 40 and 80: moving the cut-off through that range
# reclassifies very few. Recall falls 0.02 points while precision at a 1%
# base rate rises from 49.3% to 67.4% - the raise is nearly free.
#
# It is also a weak lever. 80% precision needs the false alarms cut from
# 44 to 19, which no cut-off in the measured range delivers; that takes
# new evidence of legitimacy, not a different number here.
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD = 70       # at or above this, classed as phishing


def bands_for(threshold: int) -> tuple[int, int, int]:
    """
    The three derived bands for a given threshold: low, medium, high.

    A function because the sweep in ML/evaluate.py derives them for a
    threshold that is not the configured one. Computed separately, the
    sweep held the ceiling fixed while moving the threshold, making every
    cut-off above the ceiling look catastrophic - an artefact.
    """
    return (
        round(threshold * 0.6),                              # caution
        threshold,                                           # suspicious
        round(threshold + (100 - threshold) * 0.45),         # high risk
    )


LOW_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD, HIGH_RISK_THRESHOLD = \
    bands_for(PHISHING_THRESHOLD)

# Guards against a future calibration scrambling the order
assert 0 < LOW_RISK_THRESHOLD < MEDIUM_RISK_THRESHOLD <= PHISHING_THRESHOLD \
       < HIGH_RISK_THRESHOLD <= 100, \
       f"Inconsistent risk bands: {LOW_RISK_THRESHOLD}/{MEDIUM_RISK_THRESHOLD}/" \
       f"{HIGH_RISK_THRESHOLD} with threshold {PHISHING_THRESHOLD}"

# ---------------------------------------------------------------------------
# Merging the two engines  (reasoning in backend/scoring.py)
#     score = max( bert*damping + RULE_BOOST*rules ,  rules )
# ---------------------------------------------------------------------------

# How much the rule score adds on top of BERT. 0.5 -> up to 50 points.
RULE_BOOST = float(os.getenv("RULE_BOOST", "0.5"))

# BERT multiplier when the sender is a known company's own domain. 0.25
# takes 99.99 down to 25, under any sensible threshold.
TRUST_DAMPING = float(os.getenv("TRUST_DAMPING", "0.25"))

# BERT multiplier for operational mail from a recognised company - order
# confirmation, shipping notice, receipt. The category the system got
# wrong most often: its shape sets off the rule engine ("order",
# "account", many links) and the model flags it almost every time.
# Sharper than the others because two things corroborate it - the sender
# is the company, and every link points back to it.
TRANSACTIONAL_DAMPING = float(os.getenv("TRANSACTIONAL_DAMPING", "0.10"))

# Highest score allowed when only one engine contributed. With the rules
# silent, the verdict rests on the single signal known to flag legitimate
# mail from an unrecognised sender, so 99 promises a certainty that is not
# there. Sits at the top of the "suspicious" band: the classification is
# kept - the alert is still recorded and the guardian still notified -
# only the displayed confidence is held back.
UNCORROBORATED_CEILING = HIGH_RISK_THRESHOLD - 1

# Rule score below which we treat the engine as having found nothing.
CORROBORATION_FLOOR = 15

# Stamp identifying the current formula. Scan results are stored so a
# message already checked skips BERT, the expensive step. Deriving the
# stamp from the parameters is what makes that safe: any change to them
# invalidates every score computed before it.
SCORING_VERSION = (
    f"v5|b{RULE_BOOST}|t{TRUST_DAMPING}"
    f"|x{TRANSACTIONAL_DAMPING}|th{PHISHING_THRESHOLD}"
)

# Kept for ML/calibrate.py, which sweeps the old formula for comparison.
# The live pipeline does not use them.
BERT_WEIGHT = float(os.getenv("BERT_WEIGHT", "0.4"))
HEURISTIC_WEIGHT = float(os.getenv("HEURISTIC_WEIGHT", "0.6"))

# ---------------------------------------------------------------------------
# Heuristic scoring weights
# ---------------------------------------------------------------------------
MAX_KEYWORD_SCORE = 40        # Cap for keyword contribution
KEYWORD_SCORE_PER_WORD = 15   # points per phrase typical of phishing
WEAK_KEYWORD_SCORE = 4        # a word that also shows up in real mail
MAX_WEAK_KEYWORD_SCORE = 16   # low cap - on their own they prove nothing
SUSPICIOUS_DOMAIN_SCORE = 25  # Suspicious sender patterns
MULTIPLE_URLS_SCORE = 20      # More than URL_COUNT_THRESHOLD links
URGENCY_SCORE = 15            # Artificial-urgency words
INVALID_DOMAIN_SCORE = 20     # Sender domain not in whitelist
BRAND_IMPERSONATION_SCORE = 45  # known brand in the subject, other domain
BODY_IMPERSONATION_SCORE = 30   # brand only in the body - weaker signal
URL_COUNT_THRESHOLD = 2       # Number of URLs above which we penalise

# ---------------------------------------------------------------------------
# Database / query limits
# ---------------------------------------------------------------------------
RECENT_EMAILS_WINDOW = 10     # Rolling average window for user risk score

# Derived, so mail classed as phishing can never fail to record an alert
# or reach the guardian. Both were hard-coded at 70; once the threshold
# was calibrated below that, guardian mode silently missed most detections.
ALERT_THRESHOLD = PHISHING_THRESHOLD           # lowest score that records an Alert
GUARDIAN_NOTIFY_THRESHOLD = PHISHING_THRESHOLD  # lowest score that mails the guardian
ALERT_HISTORY_LIMIT = 5       # Alerts returned in guardian dashboard


# ---------------------------------------------------------------------------
# Email / SMTP –
# ---------------------------------------------------------------------------
SMTP_HOST       = os.getenv("SMTP_HOST",       "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT",   "587"))
SMTP_USER       = os.getenv("SMTP_USER",       "")   # sending address
SMTP_PASSWORD   = os.getenv("SMTP_PASSWORD",   "")   # Gmail App Password
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "LURA")
EMAIL_ENABLED   = os.getenv("EMAIL_ENABLED",   "false").lower() == "true"