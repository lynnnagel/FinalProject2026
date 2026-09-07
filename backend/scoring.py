"""
LURA - merging the rule score and the BERT score into one.

    score = min( max( bert*damping + RULE_BOOST*rules , rules ) , 100 )

Either engine can reach 100 alone. The first version averaged them
(0.4*bert + 0.6*rules) and that failed twice: BERT at full confidence
contributed only 40 points, under the threshold (52.8% accuracy, 93.6%
miss rate, against 99.4% for BERT alone); and a rule score of 0 means
"nothing to say", which an average reads as evidence of legitimacy.

Damping applies only on positive evidence that the mail is legitimate,
never on silence. It targets a measured weakness: the model gives 99.99
to a real password reset from accounts.google.com, because the training
data holds almost no legitimate account or security mail.
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

    # Each damping needs a verified sender an attacker cannot forge, and
    # damps the model only, never the rules - so impersonation or a
    # raw-IP link still scores high on a sender the user trusts. They do
    # not stack; several would erase the model.
    #
    # A fourth, for marketing-looking mail, was removed: it was the only
    # one needing no sender, so it fired on anything with an unsubscribe
    # link - 1,129 times on the test split, 510 of them real attacks -
    # costing 488 misses to save 2 false alarms.
    if user_trusts_sender:
        bert *= TRUST_DAMPING
    elif sender and detector.looks_transactional(sender, subject, content):
        bert *= TRANSACTIONAL_DAMPING
    elif sender and detector.is_trusted_sender(sender):
        bert *= TRUST_DAMPING

    score = min(max(bert + RULE_BOOST * rule_score, rule_score), 100.0)

    # With no rule finding at all, the model's 99 was displayed as 99 next
    # to a mild "check who sent it" - a number promising certainty that is
    # not there. The ceiling sits at the top of the "suspicious" band, so
    # only the displayed confidence is held back; the classification is
    # untouched.
    if ceiling is not None and rule_score < CORROBORATION_FLOOR:
        score = min(score, float(ceiling))
    return score
