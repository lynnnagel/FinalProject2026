"""
Is the difference between two configurations real, or is it noise?

Accuracy on one split is a point estimate. Two systems measured on the
same 14,862 messages can differ by a few tenths of a percent purely by
which messages happened to land in the split, so a comparison needs a
test rather than a look.

Two are reported here:

  McNemar     the paired test for two classifiers on the same rows. It
              ignores the messages both got right and both got wrong -
              those carry no information about which is better - and
              asks only whether the disagreements are lopsided.
  Bootstrap   resample the rows with replacement, recompute the metric
              on each resample, and read the 2.5th and 97.5th
              percentiles. Gives a confidence interval without assuming
              a distribution.

    python ML/significance.py
    python ML/significance.py --split val
    python ML/significance.py --boot 5000
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from math import sqrt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector                                    # noqa: E402
from scoring import combine                                      # noqa: E402
from config import PHISHING_THRESHOLD                            # noqa: E402
from ML.calibrate import load_split                              # noqa: E402


def mcnemar(a: list[int], b: list[int]) -> tuple[int, int, float, float]:
    """
    Compare two 0/1 correctness vectors over the same rows.

    Returns (b01, b10, chi2, p). b01 is how often the first was wrong
    and the second right; b10 the reverse. The continuity-corrected
    statistic is used because the counts here are small.
    """
    b01 = sum(1 for x, y in zip(a, b) if not x and y)
    b10 = sum(1 for x, y in zip(a, b) if x and not y)
    n = b01 + b10
    if n == 0:
        return b01, b10, 0.0, 1.0
    chi2 = (abs(b01 - b10) - 1) ** 2 / n
    # Survival function of chi-square with one degree of freedom.
    p = _erfc(sqrt(chi2 / 2)) if chi2 > 0 else 1.0
    return b01, b10, chi2, p


def _erfc(x: float) -> float:
    import math
    return math.erfc(x)


def boot_ci(correct: list[int], rounds: int, seed: int = 0) -> tuple[float, float]:
    """A percentile interval for the mean of a 0/1 vector."""
    rng = random.Random(seed)
    n = len(correct)
    means = []
    for _ in range(rounds):
        s = sum(correct[rng.randrange(n)] for _ in range(n))
        means.append(s / n)
    means.sort()
    lo = means[int(0.025 * rounds)]
    hi = means[int(0.975 * rounds) - 1]
    return lo, hi


def main() -> None:
    ap = argparse.ArgumentParser(description="is the difference real?")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    ap.add_argument("--boot", type=int, default=2000, help="bootstrap rounds")
    args = ap.parse_args()

    df = load_split(args.data_dir, args.split)
    rows = list(df.itertuples(index=False))
    y = df["label"].tolist()

    print(f"\nsplit: {args.split}  |  {len(rows)} rows  |  threshold {args.threshold}\n")
    print("scoring with the rules ...")
    heur = [detector.analyze_email(r.sender, r.subject, r.content)["risk_score"]
            for r in rows]

    from ML.bert_model import load_now
    model = load_now()
    if model is None:
        sys.exit("No checkpoint found. This comparison needs the model.")
    print("scoring with BERT ...")
    bert = [0.0] * len(rows)
    BATCH = 32
    for start in range(0, len(rows), BATCH):
        chunk = rows[start:start + BATCH]
        got = model.predict_scores(
            [(r.sender, r.subject, r.content) for r in chunk], batch_size=BATCH)
        bert[start:start + len(got)] = got

    t = args.threshold
    correct = {
        "the system":   [int(((combine(bert[i], heur[i], r.sender, r.subject,
                                       r.content) >= t)) == y[i])
                         for i, r in enumerate(rows)],
        "BERT alone":   [int((bert[i] >= t) == y[i]) for i in range(len(rows))],
        "rules alone":  [int((heur[i] >= t) == y[i]) for i in range(len(rows))],
        "always safe":  [int(0 == y[i]) for i in range(len(rows))],
    }

    print("\n" + "=" * 74)
    print(f"  Accuracy, with a {args.boot}-round bootstrap interval")
    print("=" * 74)
    for name, c in correct.items():
        lo, hi = boot_ci(c, args.boot)
        print(f"  {name:<14} {sum(c)/len(c)*100:6.2f}%   "
              f"95% CI [{lo*100:.2f}%, {hi*100:.2f}%]")

    print("\n" + "=" * 74)
    print("  McNemar, each configuration against the full system")
    print("=" * 74)
    base = correct["the system"]
    for name, c in correct.items():
        if name == "the system":
            continue
        b01, b10, chi2, p = mcnemar(c, base)
        verdict = ("the system is better" if b01 > b10 else
                   "the other is better" if b10 > b01 else "no difference")
        sig = "significant" if p < 0.05 else "NOT significant"
        print(f"\n  vs {name}")
        print(f"    it wrong, system right : {b01}")
        print(f"    it right, system wrong : {b10}")
        print(f"    chi2 = {chi2:.2f}   p = {p:.3g}   -> {sig}, {verdict}")

    print("""
  How to read this. A p below 0.05 means a difference this lopsided
  would be unlikely to appear by chance if the two were equally good.
  A p above it does not prove they are the same - only that this split
  does not show a difference, which is itself worth reporting.
""")


if __name__ == "__main__":
    main()
