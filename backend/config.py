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
# CORS
# Allow Chrome / Firefox extensions and localhost (dev).
# In production, replace with explicit extension IDs.
# ---------------------------------------------------------------------------
# The extension's content script runs inside the Gmail page, so the
# Origin on its requests is https://mail.google.com and not
# chrome-extension://. Without that entry the preflight (OPTIONS /scan)
# is refused with a 400, the POST is never sent, and the extension marks
# nothing at all.
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
# PHISHING_THRESHOLD is the only value we calibrate. The other bands are
# derived from it rather than set separately, because four independent
# numbers tend to drift apart: at a threshold of 70 the bands 30/50/80
# all agreed, but once the threshold drops to 35 - which calibrating on
# real data forces - a message scoring 40 is marked is_phishing=True and
# shown to the user as merely "caution", because 40 is under MEDIUM=50.
# The extension would reassure the user about mail the system had just
# called phishing.
#
# The derivation keeps the original proportions: at a threshold of 70 it
# returns 42/70/84, very close to the 30/50/80 picked by hand early on.
#
# To set the value itself:  python ML/evaluate.py --split test --sweep
#
# 60 was picked off that sweep over the whole test set. From 60 upward
# the misses are flat at 52-53 and the false alarms fall slowly, from 44
# at 60 to 37 at 80 - so the top of the range is a wide plateau rather
# than a peak, and the choice is not balanced on an edge.
#
# 60 is the lowest point on that plateau, which makes it the most
# sensitive setting that still reaches both of the things worth having:
# the minimum number of misses, and no Hebrew false alarms at all.
# Raising it further buys about seven fewer false alarms out of 7,644
# legitimate messages, and pays in sensitivity to well-written phishing
# from a sender the rules do not recognise - the case this corpus
# represents least well.
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD = 70     # at or above this, classed as phishing


def bands_for(threshold: int) -> tuple[int, int, int]:
    """
    The three derived bands for a given threshold: low, medium, high.

    A function rather than three expressions, because the threshold
    sweep in ML/evaluate.py has to derive them for a threshold that is
    not the configured one. When it computed them separately the sweep
    held the ceiling fixed while moving the threshold, which made every
    cut-off above the ceiling look catastrophic - an artefact of the
    measurement, not of the data.
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
# Merging the two engines  (see backend/scoring.py for the reasoning)
#
#     score = max( bert*damping + RULE_BOOST*rules ,  rules )
#
# The previous version used a weighted average,
# BERT_WEIGHT*bert + HEURISTIC_WEIGHT*rules. It was dropped after
# measurement: the average put a ceiling of BERT_WEIGHT*100 on the BERT
# score, so the model could not cross the threshold on its own. On the
# test set that gave 52.8% accuracy and a 93.6% miss rate, against 99.4%
# for BERT alone.
# ---------------------------------------------------------------------------

# How much the rule score adds on top of BERT. 0.5 -> up to 50 points.
RULE_BOOST = float(os.getenv("RULE_BOOST", "0.5"))

# Multiplier on the BERT score when the sender is a known company's own
# domain. 0.25 takes a score of 99.99 down to 25, under any sensible
# threshold. It targets a measured failure of the model on legitimate
# account and security mail, and it requires positive evidence - a
# recognised sender domain - not merely silence from the rules.
TRUST_DAMPING = float(os.getenv("TRUST_DAMPING", "0.25"))

# There used to be a damping here for mail that reads as marketing. It
# was removed after measurement - see the note in scoring.py. In short:
# it was the only damping that needed no sender address, so it fired on
# anything carrying an unsubscribe link, phishing included. On the test
# split it cost 488 missed detections and saved two false alarms, and
# none of the legitimate mail it was written for depended on it.
#
# It was also solving a problem that no longer exists. It dates from
# when the corpora labelled spam as phishing; relabelling spam as
# not-phishing (ML/prepare_data.py) taught the model that distinction
# directly.

# Multiplier on the BERT score for operational mail from a recognised
# company - order confirmation, shipping notice, receipt. This is the
# category the system got wrong most often: its shape sets off the rule
# engine (many links, "order", "account") and the model flags it almost
# every time. The damping is sharper than the others because there are
# two independent pieces of evidence here - the sender is the company
# itself, and every link points back to it.
TRANSACTIONAL_DAMPING = float(os.getenv("TRANSACTIONAL_DAMPING", "0.10"))

# Highest score allowed when only one engine contributed.
#
# With the rule engine silent, the verdict rests on a single piece of
# evidence - and it is the one known to flag legitimate mail from a
# sender it does not recognise. A score of 99 there promises a certainty
# that is not there. The ceiling sits at the top of the "suspicious"
# band, so the number and the label say the same thing: there is
# suspicion, not certainty.
#
# The classification itself is kept - 75 is above the threshold - so the
# alert is still recorded and the guardian still notified. Only the
# confidence on display is held back.
UNCORROBORATED_CEILING = HIGH_RISK_THRESHOLD - 1

# Rule score below which we treat the engine as having found nothing.
CORROBORATION_FLOOR = 15

# Stamp identifying the current scoring formula. Scan results are stored
# so a message already checked does not go through BERT again - that is
# the expensive part of the pipeline. This stamp is what makes the saving
# safe: it is derived from the parameters, so any change to them
# automatically invalidates every score computed before it, and they are
# recomputed on the next scan.

SCORING_VERSION = (
    f"v7|b{RULE_BOOST}|t{TRUST_DAMPING}"
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

# Both of these were 70 - exactly the classification threshold at the
# time. They are derived from it so we never end up with mail classed as
# phishing that records no alert and never reaches the guardian. With a
# threshold of 35 and a fixed 70, guardian mode would have missed most
# detections, including brand impersonation that the rules score in the
# middle.
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