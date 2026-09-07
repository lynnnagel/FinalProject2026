"""
The class balance of the data, and what the numbers mean in a real inbox.

The corpus is roughly half phishing; a real mailbox is one percent or
less. That gap does not invalidate every measurement, but it changes what
some of them mean:

    recall (TPR)    unaffected - of the phishing that arrives, the share
                    caught does not depend on how much arrives.
    FPR             unaffected, for the same reason.
    precision       collapses as phishing gets rarer: the false alarms
                    come from a much larger pool.
    accuracy        meaningless - at 1%, "never phishing" scores 99%.

So this reports the actual balance of each split, then projects precision
from the measured TPR and FPR to base rates a real inbox might have.

    python ML/base_rate.py                  # balance + projection
    python ML/base_rate.py --no-bert        # rules only, fast
    python ML/base_rate.py --tpr 0.9928 --fpr 0.00576   # skip scoring
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector                                    # noqa: E402
from scoring import combine                                      # noqa: E402
from config import PHISHING_THRESHOLD                            # noqa: E402
from ML.calibrate import load_split                              # noqa: E402

HEBREW_CHARS = r"[֐-׿]"

# Base rates worth showing. The first few are what the literature and
# mail providers report for real traffic; 50% is what this corpus has,
# included so the contrast is visible in one table.
BASE_RATES = [0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.486]


def balance(data_dir: str) -> None:
    print("=" * 74)
    print("  Class balance in the data")
    print("=" * 74)
    print(f"  {'split':<10} {'rows':>9} {'phishing':>10} {'share':>9}")
    print("  " + "-" * 70)

    frames = {}
    for name in ("train", "val", "test"):
        try:
            df = load_split(data_dir, name)
        except SystemExit:
            print(f"  {name:<10} {'not found':>9}")
            continue
        frames[name] = df
        pos = int(df["label"].sum())
        print(f"  {name:<10} {len(df):>9,} {pos:>10,} {pos / len(df) * 100:>8.1f}%")

    if "test" in frames and "source" in frames["test"].columns:
        print("\n  test split, by source:")
        print(f"  {'source':<28} {'rows':>8} {'phishing':>10} {'share':>9}")
        print("  " + "-" * 70)
        for src, g in frames["test"].groupby("source"):
            pos = int(g["label"].sum())
            print(f"  {src:<28} {len(g):>8,} {pos:>10,} {pos / len(g) * 100:>8.1f}%")
    print()


def measure(data_dir: str, split: str, use_bert: bool,
            threshold: int) -> tuple[float, float, int, int]:
    """Returns (TPR, FPR, positives, negatives) on the split."""
    df = load_split(data_dir, split)
    rows = list(df.itertuples(index=False))
    y = df["label"].tolist()

    print(f"scoring {len(rows)} rows ...")
    heur = [detector.analyze_email(r.sender, r.subject, r.content)["risk_score"]
            for r in rows]

    if use_bert:
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            sys.exit("No checkpoint found. Run with --no-bert, or fetch the model.")
        scores = []
        BATCH = 32
        for start in range(0, len(rows), BATCH):
            chunk = rows[start:start + BATCH]
            bert = model.predict_scores(
                [(r.sender, r.subject, r.content) for r in chunk], batch_size=BATCH)
            for row, h, b in zip(chunk, heur[start:start + BATCH], bert):
                scores.append(combine(b, h, row.sender, row.subject, row.content))
            done = min(start + BATCH, len(rows))
            if done % 2048 < BATCH:
                print(f"    {done}/{len(rows)}", flush=True)
    else:
        scores = heur

    pred = [1 if s >= threshold else 0 for s in scores]
    tp = sum(1 for t, p in zip(y, pred) if t == 1 and p == 1)
    fn = sum(1 for t, p in zip(y, pred) if t == 1 and p == 0)
    fp = sum(1 for t, p in zip(y, pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y, pred) if t == 0 and p == 0)

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"\n  measured on {split}:  TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  TPR (recall) = {tpr*100:.2f}%   FPR = {fpr*100:.3f}%\n")
    return tpr, fpr, tp + fn, fp + tn


def project(tpr: float, fpr: float) -> None:
    print("=" * 74)
    print("  What those rates give at other base rates")
    print("=" * 74)
    print("  Per 1,000 messages arriving, at each share of phishing.")
    print()
    print(f"  {'phishing':>9} {'caught':>8} {'missed':>8} {'false':>8} "
          f"{'precision':>10} {'accuracy':>9}")
    print(f"  {'share':>9} {'':>8} {'':>8} {'alarms':>8} {'':>10} {'':>9}")
    print("  " + "-" * 70)

    for p in BASE_RATES:
        n = 1000
        phish = n * p
        legit = n * (1 - p)
        caught = phish * tpr
        missed = phish - caught
        false = legit * fpr
        precision = caught / (caught + false) if (caught + false) else 0.0
        accuracy = (caught + (legit - false)) / n
        mark = "   <- this corpus" if abs(p - 0.486) < 1e-6 else ""
        print(f"  {p*100:>8.1f}% {caught:>8.1f} {missed:>8.1f} {false:>8.1f} "
              f"{precision*100:>9.1f}% {accuracy*100:>8.1f}%{mark}")

    print("  " + "-" * 70)
    print("""
  Recall does not depend on the mix. Precision does: the false alarms
  come out of the legitimate pile, and the rarer phishing gets, the more
  they outnumber real detections. Accuracy at a 1% base rate is
  meaningless - "never phishing" scores 99% - which is why it is quoted
  alongside the balance rather than on its own.""")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="class balance, and what the numbers mean in a real inbox")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    ap.add_argument("--no-bert", action="store_true")
    ap.add_argument("--tpr", type=float, help="skip scoring, use this TPR")
    ap.add_argument("--fpr", type=float, help="skip scoring, use this FPR")
    args = ap.parse_args()

    print()
    balance(args.data_dir)

    if args.tpr is not None and args.fpr is not None:
        tpr, fpr = args.tpr, args.fpr
        print(f"  using the rates given: TPR {tpr*100:.2f}%, FPR {fpr*100:.3f}%\n")
    else:
        tpr, fpr, _, _ = measure(args.data_dir, args.split,
                                 not args.no_bert, args.threshold)

    project(tpr, fpr)


if __name__ == "__main__":
    main()
