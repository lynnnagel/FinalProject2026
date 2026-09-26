"""
LURA - turning a numeric score into a risk level and a message.

Depends only on config, so everything can import it without a cycle. It
exists because this logic was copied three times and drifted: a message
got one label on its first scan and another from the cache.
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


# Lines that say nothing was found. They are indicators in the list, but
# they are not signs, and the advice must not count them as such.
_DENIALS = (
    "לא נמצאו אינדיקטורים חשודים",
    "לא נמצאו סימנים טכניים",
)


def found_signs(indicators) -> bool:
    """Did anything real turn up, as opposed to a line saying nothing did."""
    return any(
        i and not any(i.startswith(d) for d in _DENIALS)
        for i in (indicators or [])
    )


def recommendation(score: float, indicators=None) -> str:
    """
    The advice shown to the user for a score.

    On a safe score the advice used to deny outright, and sat under a
    list of the signs that had just been found: four weak keywords and a
    line of urgency scored 31, and the window said none were found. The
    denial is only correct when the list is empty.
    """
    text = next(text for cutoff, _, text in _LEVELS if score >= cutoff)
    if score < LOW_RISK_THRESHOLD and found_signs(indicators):
        return "הסימנים שנמצאו חלשים מכדי להצביע על פישינג."
    return text


def is_phishing(score: float) -> bool:
    return score >= PHISHING_THRESHOLD


def apply(result: dict, corroborated: bool = True) -> dict:
    """
    Add is_phishing, risk_level and recommendation based on risk_score.

    `corroborated` is kept for compatibility but no longer changes the
    label: scoring.combine holds back the score itself, so the number and
    the label come from one place. Holding back only the label used to
    leave a score of 99 next to the word "suspicious".
    """
    score = result["risk_score"]
    result["is_phishing"] = is_phishing(score)
    result["risk_level"] = risk_level(score)
    result["recommendation"] = recommendation(score, result.get("indicators"))
    return result
