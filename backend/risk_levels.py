"""
LURA - turning a numeric score into a risk level and a message.

A separate module that depends only on config, so `detector`, `scoring`
and the API layer can all import it without an import cycle.

It exists because this logic was duplicated three times and two copies
drifted. The one in `API/scan.py` served the cached-result path with
hard-coded cut-offs (80/50/30) that no longer matched the real ones - so
the same message got one label on its first scan and a different one
when it came back from the cache.
"""
from config import (
    PHISHING_THRESHOLD,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD,
)

# The wording carries no emoji on purpose. This shows up inside Gmail
# next to real mail, and in a security context plain wording reads like
# a tool rather than an automated alert.
_LEVELS = (
    (HIGH_RISK_THRESHOLD,   "סכנה גבוהה", "אל תלחץ על שום קישור. מחק את המייל."),
    (MEDIUM_RISK_THRESHOLD, "חשוד",       "בדוק את זהות השולח לפני כל פעולה."),
    (LOW_RISK_THRESHOLD,    "זהירות",     "המייל מכיל סימנים חריגים. כדאי לשים לב."),
    (float("-inf"),         "בטוח",       "לא נמצאו סימנים חשודים."),
)


def risk_level(score: float) -> str:
    """Name of the risk band for a score."""
    return next(name for cutoff, name, _ in _LEVELS if score >= cutoff)


def recommendation(score: float) -> str:
    """The advice shown to the user for a score."""
    return next(text for cutoff, _, text in _LEVELS if score >= cutoff)


def is_phishing(score: float) -> bool:
    return score >= PHISHING_THRESHOLD


def apply(result: dict, corroborated: bool = True) -> dict:
    """
    Add is_phishing, risk_level and recommendation based on risk_score.

    `corroborated` is kept in the signature for compatibility but no
    longer changes the label: the uncorroborated case is held back on
    the score itself in scoring.combine, so the number and the label
    come from the same place and cannot disagree. Holding back only the
    label used to leave a score of 99 sitting next to the word
    "suspicious".
    """
    score = result["risk_score"]
    result["is_phishing"] = is_phishing(score)
    result["risk_level"] = risk_level(score)
    result["recommendation"] = recommendation(score)
    return result
