"""
Evaluation - overall and broken out by language.

One accuracy number hides what matters here: most of the corpus is
English, so it barely reflects Hebrew, which is the point of the
project. This runs the full pipeline over a split and reports each
language separately.

    python ML/evaluate.py                  # test split, full ensemble
    python ML/evaluate.py --split val
    python ML/evaluate.py --no-bert        # rules only, for comparison
    python ML/evaluate.py --sweep          # score once, try every threshold
    python ML/evaluate.py --limit 2000     # quick sample
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector                                     # noqa: E402
from config import (                                              # noqa: E402
    PHISHING_THRESHOLD, RULE_BOOST, TRUST_DAMPING, bands_for,
    UNCORROBORATED_CEILING, CORROBORATION_FLOOR,
)
from scoring import combine                                       # noqa: E402
from ML.calibrate import metrics, load_split                      # noqa: E402

HEBREW_CHARS = r"[֐-׿]"


def score_rows(df: pd.DataFrame, use_bert: bool,
               bert_only: bool = False,
               uncapped: bool = False) -> tuple[list[float], list[float]]:
    """
    Returns (scores, rule_scores).

    With uncapped=True the scores come back before the corroboration
    ceiling is applied, so the sweep can apply the ceiling belonging to
    each threshold it tries.
    """
    model = None
    if use_bert:
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            print("  no checkpoint - continuing with rules only\n")

    rows = list(df.itertuples(index=False))

    heur = [0.0] * len(rows)
    if not bert_only:
        for i, row in enumerate(rows, 1):
            heur[i - 1] = detector.analyze_email(
                row.sender, row.subject, row.content
            )["risk_score"]
            if i % 2000 == 0:
                print(f"    rules: {i}/{len(rows)}", flush=True)

    if model is None:
        return heur, heur

    # In batches: one forward per message over the whole split takes
    # tens of minutes on CPU, mostly overhead rather than computation.
    scores = []
    BATCH = 32
    for start in range(0, len(rows), BATCH):
        chunk = rows[start:start + BATCH]
        bert = model.predict_scores(
            [(r.sender, r.subject, r.content) for r in chunk], batch_size=BATCH
        )
        for row, h, b in zip(chunk, heur[start:start + BATCH], bert):
            scores.append(
                b if bert_only
                else combine(b, h, row.sender, row.subject, row.content,
                             ceiling=None if uncapped else UNCORROBORATED_CEILING)
            )
        done = min(start + BATCH, len(rows))
        if done % 512 < BATCH:
            print(f"    BERT: {done}/{len(rows)}", flush=True)
    return scores, heur


def report(title: str, y_true: list[int], y_pred: list[int]) -> None:
    n = len(y_true)
    if n == 0:
        print(f"  {title:<12} - no examples")
        return
    m = metrics(y_true, y_pred)
    pos = sum(y_true)
    print(f"  {title:<12} {n:>6} examples ({pos} phishing)")
    print(f"               acc {m['accuracy']*100:5.1f}%  |  F1 {m['f1']:.3f}  |  "
          f"missed {m['fnr']*100:4.1f}%  |  TP={m['tp']} FP={m['fp']} FN={m['fn']}")
    if n < 200:
        print(f"               !  small sample - these numbers are unstable")


def main() -> None:
    ap = argparse.ArgumentParser(description="evaluation, broken out by language")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--no-bert", action="store_true", help="rules only")
    ap.add_argument("--bert-only", action="store_true",
                    help="BERT only, no rules and no combining")
    ap.add_argument("--with-sender", action="store_true",
                    help="only rows that carry a sender address")
    ap.add_argument("--limit", type=int, default=0, help="cap the number of examples (0 = all)")
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    ap.add_argument("--sweep", action="store_true",
                    help="score once, then report every threshold from 20 to 80")
    args = ap.parse_args()

    if args.no_bert and args.bert_only:
        sys.exit("--no-bert and --bert-only contradict each other")

    df = load_split(args.data_dir, args.split)

    # Most English corpora give the body only, with no From line. Three
    # of the nine rules read the sender - including brand impersonation,
    # the highest-scoring one - so on those rows the engine runs
    # crippled, and the ensemble measured there is not the system that
    # runs in Gmail, where a sender is always present.
    has_sender = df["sender"].str.strip() != ""
    if args.with_sender:
        df = df[has_sender].reset_index(drop=True)
        if df.empty:
            sys.exit("No rows with a sender in this split.")

    if args.limit:
        df = df.sample(min(args.limit, len(df)), random_state=42).reset_index(drop=True)

    is_hebrew = df["text"].str.contains(HEBREW_CHARS, na=False, regex=True) \
        if "text" in df.columns else \
        (df["subject"] + " " + df["content"]).str.contains(HEBREW_CHARS, na=False, regex=True)

    n_sender = int((df["sender"].str.strip() != "").sum())

    print(f"\nsplit: {args.split}  |  {len(df)} examples")
    print(f"  Hebrew: {int(is_hebrew.sum())}  |  English: {int((~is_hebrew).sum())}")
    print(f"  with a sender: {n_sender} ({n_sender / len(df) * 100:.1f}%)")
    if args.no_bert:
        mode = "rules only"
    elif args.bert_only:
        mode = "BERT only"
    else:
        mode = f"ensemble (boost={RULE_BOOST}, trust={TRUST_DAMPING})"
    print(f"  mode: {mode}  |  threshold: {args.threshold}\n")

    # The threshold was calibrated for the ensemble score. It means
    # nothing against a raw BERT probability, so use 50 there.
    threshold = 50 if args.bert_only else args.threshold
    if args.bert_only:
        print("  (threshold 50 on the raw score - the ensemble's does not apply)\n")

    print("scoring ...")
    scores, rule_scores = score_rows(
        df, use_bert=not args.no_bert, bert_only=args.bert_only,
        uncapped=args.sweep and not args.bert_only and not args.no_bert,
    )
    y = df["label"].tolist()

    def at(t: int) -> list[int]:
        """
        Predictions at threshold t, with the ceiling that threshold
        implies. Holding the ceiling fixed while moving the threshold
        made every cut-off above it look like a collapse.
        """
        if args.bert_only or args.no_bert or not args.sweep:
            return [1 if s_ >= t else 0 for s_ in scores]
        cap = bands_for(t)[2] - 1
        return [
            1 if (min(s_, cap) if h_ < CORROBORATION_FLOOR else s_) >= t else 0
            for s_, h_ in zip(scores, rule_scores)
        ]

    pred = at(threshold)

    # Scoring is the expensive part. Trying thresholds one run at a
    # time repeats it for a decision that only reads the scores.
    if args.sweep:
        heb = set(i for i, v in enumerate(is_hebrew) if v)
        print("\n" + "=" * 72)
        print("  Threshold sweep - scored once, every cut-off")
        print("=" * 72)
        print(f"  {'thr':>4} {'acc':>7} {'F1':>7} {'FP':>7} {'FN':>7}"
              f" {'FP-heb':>9} {'FN-heb':>9}")
        print("  " + "-" * 62)
        best = None
        for t in range(20, 81, 5):
            pred_t = at(t)
            m = metrics(y, pred_t)
            hy = [y[i] for i in heb]
            hp = [pred_t[i] for i in heb]
            hm = metrics(hy, hp) if hy else {"fp": 0, "fn": 0}
            print(f"  {t:>4} {m['accuracy']*100:>6.1f}% {m['f1']:>7.3f}"
                  f" {m['fp']:>7} {m['fn']:>7} {hm['fp']:>9} {hm['fn']:>9}")
            if best is None or m["f1"] > best[1]:
                best = (t, m["f1"], m)
        print("  " + "-" * 62)
        print(f"\n  Highest F1: threshold {best[0]}  (F1={best[1]:.3f})")
        print("  But F1 treats both kinds of error as equal. In a real inbox a")
        print("  false alarm costs more trust than a single miss, so prefer a")
        print("  threshold where the FP column is still low.\n")
        return

    print("\n" + "=" * 72)
    print("  Results")
    print("=" * 72)
    report("overall", y, pred)
    print()
    heb_idx = [i for i, v in enumerate(is_hebrew) if v]
    eng_idx = [i for i, v in enumerate(is_hebrew) if not v]
    report("Hebrew", [y[i] for i in heb_idx], [pred[i] for i in heb_idx])
    report("English", [y[i] for i in eng_idx], [pred[i] for i in eng_idx])
    print("=" * 72)

    if len(heb_idx) < 200:
        print(f"\n  !  only {len(heb_idx)} Hebrew examples in this split -")
        print("     too few to claim anything about Hebrew performance.")

    # The old weighted average capped the model at BERT_WEIGHT*100 and
    # kept it from crossing the threshold alone. scoring.combine uses
    # max now, so that warning no longer applies.
    if n_sender < len(df) * 0.5 and not args.bert_only:
        missing = len(df) - n_sender
        print(f"\n  i  {missing} rows ({missing / len(df) * 100:.0f}%) carry no sender, so three")
        print("     of the nine rules - brand impersonation among them - cannot")
        print("     run. In Gmail a sender is always there. To compare on rows")
        print("     where the engine does work:")
        print("       python ML/evaluate.py --split test --with-sender")
    print()


if __name__ == "__main__":
    main()
