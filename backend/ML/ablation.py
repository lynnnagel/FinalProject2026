"""
What does each engine actually contribute?

The obvious challenge to this design: if BERT alone scores 99.4% and the
combined score is a max, is the rule engine doing anything at all? That
cannot be answered by argument, only by measurement, so this scores the
split once and then evaluates several variants over the same numbers:

    rules only           the rule engine by itself
    BERT only            the model by itself
    ensemble             what the product actually runs
    with promo damping   the earlier version, before that damping was removed
    no damping at all    the ensemble with the model's score untouched

It also counts, message by message, which engine decided the verdict -
how often the rules rescued something BERT missed, how often they caused
a false alarm, and how often a damping turned a BERT positive into a
negative.

    python ML/ablation.py
    python ML/ablation.py --with-sender      # where the rules can run
    python ML/ablation.py --split val --limit 4000
    python ML/ablation.py --no-bert          # rules only, fast
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector                                    # noqa: E402
from scoring import combine                                      # noqa: E402
from config import (                                             # noqa: E402
    PHISHING_THRESHOLD, RULE_BOOST, TRUST_DAMPING,
    TRANSACTIONAL_DAMPING, UNCORROBORATED_CEILING, CORROBORATION_FLOOR,
)
from ML.calibrate import metrics, load_split                      # noqa: E402

# The promotional damping was removed from the product after this script
# measured it. Kept here so the comparison that justified the removal
# stays reproducible.
REMOVED_PROMO_DAMPING = 0.30

HEBREW_CHARS = r"[֐-׿]"


def damping_for(sender: str, subject: str, content: str) -> tuple[float, str]:
    """
    The multiplier scoring.combine would apply, and why.

    This mirrors combine() rather than calling it, because the variants
    below need to switch a damping on or off. main() checks on every row
    that the mirror still matches the real thing.
    """
    if sender and detector.looks_transactional(sender, subject, content):
        return TRANSACTIONAL_DAMPING, "transactional"
    if sender and detector.is_trusted_sender(sender):
        return TRUST_DAMPING, "known sender"
    return 1.0, ""


def damping_with_promo(sender: str, subject: str, content: str) -> tuple[float, str]:
    """The damping as it was before the promotional one was removed."""
    d, why = damping_for(sender, subject, content)
    if why:
        return d, why
    if detector.looks_promotional(subject, content):
        return REMOVED_PROMO_DAMPING, "promotional"
    return 1.0, ""


def assemble(bert: float, rules: float, damping: float) -> float:
    score = min(max(bert * damping + RULE_BOOST * rules, rules), 100.0)
    if rules < CORROBORATION_FLOOR:
        score = min(score, float(UNCORROBORATED_CEILING))
    return score


def report(name: str, y: list[int], scores: list[float], threshold: int) -> dict:
    pred = [1 if s >= threshold else 0 for s in scores]
    m = metrics(y, pred)
    precision = m["tp"] / (m["tp"] + m["fp"]) if (m["tp"] + m["fp"]) else 0.0
    recall = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) else 0.0
    print(f"  {name:<22} {m['accuracy']*100:6.1f}%  {precision*100:7.1f}%  "
          f"{recall*100:7.1f}%  {m['f1']:6.3f}  {m['fp']:>6}  {m['fn']:>6}")
    return {**m, "precision": precision, "recall": recall, "pred": pred}


def main() -> None:
    ap = argparse.ArgumentParser(description="what each engine contributes")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    ap.add_argument("--bert-threshold", type=int, default=50,
                    help="cut-off for the raw model score, which is not on "
                         "the ensemble's scale")
    ap.add_argument("--no-bert", action="store_true")
    ap.add_argument("--with-sender", action="store_true",
                    help="only rows that carry a sender address - the only "
                         "ones where the rule engine can actually run")
    args = ap.parse_args()

    df = load_split(args.data_dir, args.split)
    if args.with_sender:
        # Three of the nine rules read the sender, brand impersonation
        # among them. On a row without one the engine runs crippled, so
        # measuring its contribution there measures nothing. This is the
        # only subset where the question can be answered.
        has_sender = df["sender"].str.strip() != ""
        df = df[has_sender].reset_index(drop=True)
        if df.empty:
            sys.exit("No rows carry a sender in this split.")
    if args.limit:
        df = df.sample(min(args.limit, len(df)), random_state=42).reset_index(drop=True)

    rows = list(df.itertuples(index=False))
    y = df["label"].tolist()
    print(f"\nsplit: {args.split}  |  {len(rows)} examples  |  "
          f"{sum(y)} phishing"
          + ("  |  rows with a sender only" if args.with_sender else "") + "\n")

    print("scoring with the rules ...")
    rules = [detector.analyze_email(r.sender, r.subject, r.content)["risk_score"]
             for r in rows]

    bert = [0.0] * len(rows)
    if not args.no_bert:
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            sys.exit("No checkpoint found. Run with --no-bert, or fetch the model.")
        print("scoring with BERT ...")
        BATCH = 32
        for start in range(0, len(rows), BATCH):
            chunk = rows[start:start + BATCH]
            got = model.predict_scores(
                [(r.sender, r.subject, r.content) for r in chunk], batch_size=BATCH)
            bert[start:start + len(got)] = got
            done = min(start + BATCH, len(rows))
            if done % 1024 < BATCH:
                print(f"    {done}/{len(rows)}", flush=True)

    damps, reasons = [], []
    for r in rows:
        d, why = damping_for(r.sender, r.subject, r.content)
        damps.append(d)
        reasons.append(why)

    ensemble = [assemble(b, h, d) for b, h, d in zip(bert, rules, damps)]

    # The mirror must match the real formula, or everything below is
    # measuring code that is not the product.
    truth = [combine(b, h, r.sender, r.subject, r.content)
             for b, h, r in zip(bert, rules, rows)]
    drift = sum(1 for a, b_ in zip(ensemble, truth) if abs(a - b_) > 1e-9)
    if drift:
        sys.exit(f"the mirror disagrees with scoring.combine on {drift} rows")

    old_damps, old_reasons = [], []
    for r in rows:
        d, why = damping_with_promo(r.sender, r.subject, r.content)
        old_damps.append(d)
        old_reasons.append(why)
    with_promo = [assemble(b, h, d) for b, h, d in zip(bert, rules, old_damps)]
    no_damp = [assemble(b, h, 1.0) for b, h in zip(bert, rules)]

    print("\n" + "=" * 78)
    print("  Each engine, and the combinations")
    print("=" * 78)
    print(f"  {'variant':<22} {'acc':>7}  {'precision':>9}  {'recall':>7}  "
          f"{'F1':>6}  {'FP':>6}  {'FN':>6}")
    print("  " + "-" * 74)
    r_rules = report("rules only", y, rules, args.threshold)
    r_bert = report("BERT only", y, bert, args.bert_threshold)
    r_ens = report("ensemble (shipped)", y, ensemble, args.threshold)
    r_withpromo = report("with promo damping", y, with_promo, args.threshold)
    r_nodamp = report("no damping at all", y, no_damp, args.threshold)
    print("  " + "-" * 74)
    print(f"  thresholds: ensemble {args.threshold}, raw BERT {args.bert_threshold}")

    # -- who decided ------------------------------------------------------
    print("\n" + "=" * 78)
    print("  Where the rule engine changed the verdict")
    print("=" * 78)

    bert_pred = r_bert["pred"]
    ens_pred = r_ens["pred"]

    rescued = [i for i in range(len(y))
               if y[i] == 1 and bert_pred[i] == 0 and ens_pred[i] == 1]
    lost = [i for i in range(len(y))
            if y[i] == 1 and bert_pred[i] == 1 and ens_pred[i] == 0]
    caused = [i for i in range(len(y))
              if y[i] == 0 and bert_pred[i] == 0 and ens_pred[i] == 1]
    prevented = [i for i in range(len(y))
                 if y[i] == 0 and bert_pred[i] == 1 and ens_pred[i] == 0]

    print(f"  phishing BERT missed, the rules caught      {len(rescued):>6}")
    print(f"  phishing BERT caught, the ensemble lost     {len(lost):>6}")
    print(f"  false alarms the rules added                {len(caused):>6}")
    print(f"  BERT false alarms the ensemble prevented    {len(prevented):>6}")

    net = len(rescued) + len(prevented) - len(lost) - len(caused)
    print(f"\n  net effect of the rule engine on this corpus:  {net:+}")
    if net < 0:
        print("  Negative: on this corpus the rules cost more than they add.")
        print("  That is a real result and belongs in the report. What the")
        print("  corpus does not contain is legitimate transactional and")
        print("  marketing mail, which is what the dampings exist for -")
        print("  see ML/sanity_check.py for those cases.")

    if lost:
        by_reason: dict[str, int] = {}
        for i in lost:
            by_reason[old_reasons[i] or "no damping"] = \
                by_reason.get(old_reasons[i] or "no damping", 0) + 1
        print("\n  phishing lost to the ensemble, by cause:")
        for why, n in sorted(by_reason.items(), key=lambda kv: -kv[1]):
            print(f"    {why:<20} {n:>6}")

    # -- how often each damping fires ------------------------------------
    print("\n" + "=" * 78)
    print("  How often each damping fires")
    print("=" * 78)
    counts: dict[str, list[int]] = {}
    for i, why in enumerate(reasons):
        counts.setdefault(why or "none", []).append(i)
    for why, idx in sorted(counts.items(), key=lambda kv: -len(kv[1])):
        phish = sum(y[i] for i in idx)
        print(f"  {why:<20} {len(idx):>7} rows   "
              f"{phish:>6} of them phishing")
    print("""
  A damping firing on phishing is the dangerous case: it lowers the
  model's score on a message that really is an attack.""")
    print()


if __name__ == "__main__":
    main()
