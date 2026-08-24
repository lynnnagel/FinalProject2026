"""
LURA - turning two engine scores into one.

The pipeline produces two independent scores in [0,100]: the rule engine
and BERT. This module decides how to merge them, and keeps that decision
in one place so the extension, the evaluation and the calibration all
measure exactly the same formula.

Why not a weighted average
--------------------------
The first version computed  0.4*bert + 0.6*rules.  Measuring it on the
test set showed two properties of that formula wrecking the results:

1. A ceiling. BERT at full confidence contributes only 40 points, below
   the threshold of 57. So a message the model is 100% sure about, but
   the rules say nothing about, was always classed as safe. On the test
   set that dropped accuracy to 52.8% with a 93.6% miss rate, while BERT
   alone scored 99.4% with F1 0.994 on the same rows.

2. Averaging silence. When the rule engine finds nothing it returns 0,
   and the average reads that as evidence of legitimacy. But 0 means "I
   have nothing to say" - which is also what happens when there is no
   sender at all, and three of the nine checks cannot run.

The formula used here
---------------------
    score = max( bert' + RULE_BOOST * rules ,  rules )

  - Either engine can reach 100 on its own. Rules that spotted a clear
    impersonation do not need the model to agree, and the reverse holds.
  - Rules reinforce BERT instead of averaging it down - two engines
    agreeing is stronger evidence than one.

  - bert' = bert * damping, and damping only ever applies when there is
    positive evidence the mail is legitimate, never just silence. It
    targets a measured weakness of the model: it gives 99.99 both to a
    subscription renewal from malwarebytes.com and to a password reset
    from accounts.google.com, because the training corpora contain
    almost no legitimate account or security mail. Mail genuinely sent
    from a company's own domain cannot be impersonating that company.
"""
from __future__ import annotations

from config import (
    RULE_BOOST, TRUST_DAMPING, PROMO_DAMPING, TRANSACTIONAL_DAMPING,
    UNCORROBORATED_CEILING, CORROBORATION_FLOOR,
)
from detector import detector


def combine(bert_score: float, rule_score: float, sender: str,
            subject: str = "", content: str = "",
            user_trusts_sender: bool = False) -> float:
    """
    Final score in [0,100] from the two engine scores.

    bert_score, rule_score - both in [0,100].
    sender - the sender address; empty when there is none (corpora that
             supply only a message body). Empty means "unknown", not
             "untrusted".
    subject, content - needed to spot marketing mail. Optional so older
             code that passes scores only keeps working.

    The dampings do not stack: one piece of evidence is enough, and
    multiplying by several would wipe out the model's score entirely.
    """
    bert = bert_score

    # Personal trust: the sender is on the user's known-sender list.
    #
    # This damps the model's score only, never the rules - that is what
    # makes the feature safe. If the sender impersonates a brand, writes
    # from a forged domain, or links to a raw IP, the rule engine sees
    # it and the score stays high even after the user marked it. A user
    # can say "I know this address"; they cannot say "ignore the
    # evidence".
    #
    # An attacker would impersonate a known sender in particular, so
    # this is exactly where the evidence has to keep working.
    if user_trusts_sender:
        bert *= TRUST_DAMPING
    elif sender and detector.looks_transactional(sender, subject, content):
        bert *= TRANSACTIONAL_DAMPING
    elif sender and detector.is_trusted_sender(sender):
        bert *= TRUST_DAMPING
    elif detector.looks_promotional(subject, content):
        bert *= PROMO_DAMPING

    score = min(max(bert + RULE_BOOST * rule_score, rule_score), 100.0)

    # Ceiling when nothing corroborates. Mail from an office the user
    # writes to, with no rule finding at all, got 99 from the model and
    # was shown as 99 - a number promising a certainty that is not there,
    # next to a mild suggestion to check who sent it. The number and the
    # label contradicted each other.
    #
    # This is not a return to the weighted-average mistake, where
    # silence from the rules counted as evidence of legitimacy and
    # pushed the score under the threshold. Here the classification is
    # untouched - the ceiling sits at the top of the "suspicious" band -
    # and only the displayed confidence is held back.
    if rule_score < CORROBORATION_FLOOR:
        score = min(score, float(UNCORROBORATED_CEILING))
    return score
