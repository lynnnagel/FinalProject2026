"""
LURA – Central configuration.
All tuneable constants live here so they can be changed in one place.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

# SECRET_KEY signs the JWTs. No default on purpose: a fallback in a public
# repo lets anyone forge a token.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing.\n"
        "Generate one:  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "Then add it to backend/.env as:  SECRET_KEY=<the generated key>"
    )

JWT_ALGORITHM = "HS256"
TOKEN_TTL_DAYS = 7
RESET_TOKEN_TTL_MINUTES = 30

# Base of the links we send by mail
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./lura.db")

# mail.google.com must be here: the content script runs inside the Gmail
# page, so that is the Origin it sends. Without it the preflight fails.
CORS_ORIGIN_REGEX = (
    r"chrome-extension://.*"
    r"|moz-extension://.*"
    r"|https://mail\.google\.com"
    r"|https://.*\.mail\.google\.com"
    r"|http://localhost(:\d+)?"
    r"|http://127\.0\.0\.1(:\d+)?"
)

# Only the threshold is calibrated; the bands are derived from it, so they
# cannot drift apart. Raised 60 -> 70: same 66 misses, three fewer false
# alarms.  Set it with:  python ML/tradeoff.py
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

# Merging the two engines  (reasoning in backend/scoring.py)
#     score = max( bert*damping + RULE_BOOST*rules ,  rules )

# How much the rule score adds on top of BERT. 0.5 -> up to 50 points.
RULE_BOOST = float(os.getenv("RULE_BOOST", "0.5"))

# BERT multiplier when the sender is a known company's own domain. 0.25
# takes 99.99 down to 25, under any sensible threshold.
TRUST_DAMPING = float(os.getenv("TRUST_DAMPING", "0.25"))

# BERT multiplier for order confirmations and receipts, the category we got
# wrong most often. Sharper than the others: the sender is the company and
# every link points back to it.
TRANSACTIONAL_DAMPING = float(os.getenv("TRANSACTIONAL_DAMPING", "0.10"))

# Cap when only one engine found anything. 99 from the model alone promises
# a certainty that is not there. The classification is kept; only the
# number on screen is held back.
UNCORROBORATED_CEILING = HIGH_RISK_THRESHOLD - 1

# Rule score below which we treat the engine as having found nothing.
CORROBORATION_FLOOR = 15

# Derived from the parameters, so changing any of them invalidates every
# stored score and the next scan recomputes it.
SCORING_VERSION = (
    f"v6|b{RULE_BOOST}|t{TRUST_DAMPING}"
    f"|x{TRANSACTIONAL_DAMPING}|th{PHISHING_THRESHOLD}"
)

# Kept for ML/calibrate.py, which sweeps the old formula for comparison.
# The live pipeline does not use them.
BERT_WEIGHT = float(os.getenv("BERT_WEIGHT", "0.4"))
HEURISTIC_WEIGHT = float(os.getenv("HEURISTIC_WEIGHT", "0.6"))

# What each rule check is worth. Impersonation carries the most because
# it is the one finding an attacker cannot avoid leaving.
MAX_KEYWORD_SCORE = 40
KEYWORD_SCORE_PER_WORD = 15
WEAK_KEYWORD_SCORE = 4          # also common in real mail, so capped low
MAX_WEAK_KEYWORD_SCORE = 16
SUSPICIOUS_DOMAIN_SCORE = 25
MULTIPLE_URLS_SCORE = 20
URGENCY_SCORE = 15
INVALID_DOMAIN_SCORE = 20
BRAND_IMPERSONATION_SCORE = 45  # brand in the subject, sent from elsewhere
BODY_IMPERSONATION_SCORE = 30   # brand only in the body - weaker
URL_COUNT_THRESHOLD = 2

RECENT_EMAILS_WINDOW = 10     # rolling window for the user's risk score
ALERT_HISTORY_LIMIT = 5

# Derived, so phishing can never fail to alert the guardian. Hard-coded at
# 70, they silently missed most detections once the threshold moved.
ALERT_THRESHOLD = PHISHING_THRESHOLD
GUARDIAN_NOTIFY_THRESHOLD = PHISHING_THRESHOLD


# Email / SMTP
SMTP_HOST       = os.getenv("SMTP_HOST",       "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT",   "587"))
SMTP_USER       = os.getenv("SMTP_USER",       "")   # sending address
SMTP_PASSWORD   = os.getenv("SMTP_PASSWORD",   "")   # Gmail App Password
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "LURA")
EMAIL_ENABLED   = os.getenv("EMAIL_ENABLED",   "false").lower() == "true"