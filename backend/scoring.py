"""
LURA - merging the rule score and the BERT score into one.

    score = min( max( bert*damping + RULE_BOOST*rules , rules ) , 100 )

Either engine can reach 100 alone. Averaging them failed twice: BERT at
full confidence only reached 40 points, under the threshold; and a rule
score of 0 means "nothing to say", which an average reads as innocence.

Damping needs positive evidence the mail is legitimate, never silence.
"""
from __future__ import annotations

from config import (
    RULE_BOOST, TRUST_DAMPING, TRANSACTIONAL_DAMPING,
    UNCORROBORATED_CEILING, CORROBORATION_FLOOR,
)
from detector import detector


def combine(bert_score: float, rule_score: float, sender: str,
            subject: str = "", content: str = "",
            user_trusts_sender: bool = False,
            ceiling: float | None = UNCORROBORATED_CEILING) -> float:
    """
    Final score in [0,100] from the two engine scores.

    sender may be empty - that means "unknown", not "untrusted".
    ceiling is a parameter so the threshold sweep can pass the value
    derived from the threshold it tests, or None to see the raw score.
    """
    bert = bert_score

    # Each damping needs a verified sender, and damps the model only - so
    # impersonation still scores high on a trusted sender. They do not
    # stack. A fourth, for marketing mail, was removed: it needed no
    # sender, so it cost 488 misses to save 2 false alarms.
    #
    # The brand-domain damping asks one more question than it used to: is
    # the message demanding credentials or threatening the account? A real
    # domain plus that demand is the signature of a compromised account,
    # and damping it cost 19 detections on the test split while saving
    # none. looks_transactional already vetoes on the same list.
    asking = detector.asks_for_credentials(subject, content)

    if user_trusts_sender:
        bert *= TRUST_DAMPING
    elif sender and detector.looks_transactional(sender, subject, content):
        bert *= TRANSACTIONAL_DAMPING
    elif sender and detector.is_trusted_sender(sender) and not asking:
        bert *= TRUST_DAMPING

    score = min(max(bert + RULE_BOOST * rule_score, rule_score), 100.0)

    # With no rule finding, the model's 99 sat next to a mild "check who
    # sent it". The cap holds back the number, not the classification.
    if ceiling is not None and rule_score < CORROBORATION_FLOOR:
        score = min(score, float(ceiling))
    return score
