"""
Calibrating the ensemble parameters and the decision threshold.

LURA's final score comes from two engines. This script predates the
current formula and still sweeps the old weighted average, which is why
it is kept: it is the comparison that showed the average was wrong.
For the live formula use  ML/evaluate.py --sweep.

The parameters were once picked by hand. This sweeps the combinations
on the validation split and finds the ones that maximise F1, without
retraining the model.

Usage:
    python ML/calibrate.py
    python ML/calibrate.py --metric fnr      # minimise misses instead of F1
    python ML/calibrate.py --no-bert         # threshold only, no BERT

The output is a couple of lines to copy into .env and a before/after
report. test.csv is left alone - it is kept for the final evaluation,
or the numbers come out inflated.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Tuple

import pandas as pd

# Runnable from backend/ and from backend/ML/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector  # noqa: E402
from scoring import combine   # noqa: E402
from config import PHISHING_THRESHOLD, RULE_BOOST, TRUST_DAMPING  # noqa: E402


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def confusion(y_true: List[int], y_pred: List[int]) -> Tuple[int, int, int, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return tp, fp, tn, fn


def metrics(y_true: List[int], y_pred: List[int]) -> dict:
    tp, fp, tn, fn = confusion(y_true, y_pred)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy":  (tp + tn) / len(y_true) if y_true else 0.0,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        # False negative rate - the share of phishing missed.
        "fnr":       fn / (tp + fn) if (tp + fn) else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def fmt(m: dict) -> str:
    return (f"acc={m['accuracy']*100:5.1f}%  P={m['precision']:.3f}  "
            f"R={m['recall']:.3f}  F1={m['f1']:.3f}  FNR={m['fnr']*100:4.1f}%")


# ---------------------------------------------------------------------------
# Loading data and scoring
# ---------------------------------------------------------------------------
def load_split(data_dir: str, name: str) -> pd.DataFrame:
    path = os.path.join(data_dir, "processed", f"{name}.csv")
    if not os.path.exists(path):
        sys.exit(f"{path} not found\nrun first:  python ML/prepare_data.py")

    df = pd.read_csv(path)
    if df.empty:
        sys.exit(f"{path} is empty. If the files are in Git LFS, run:  git lfs pull")

    for col in ("label",):
        if col not in df.columns:
            sys.exit(f"column '{col}' missing from {path}. Present: {list(df.columns)}")

    # prepare_data.py writes a single text column. The rule engine
    # wants sender, subject and content separately, so text maps to
    # content - with empty strings it would find nothing at all.
    if "content" not in df.columns:
        for src in ("content", "body", "text"):
            if src in df.columns:
                df["content"] = df[src]
                break
    for col in ("sender", "subject", "content"):
        if col not in df.columns:
            df[col] = ""
        df[col] = df[col].fillna("").astype(str)

    if not df["sender"].str.strip().any():
        print("  i  no sender column - the sender-based rules will not run.\n"
              "     These numbers reflect content only, so they sit below\n"
              "     what the live system does.")

    df["label"] = df["label"].astype(int)
    return df


def heuristic_scores(df: pd.DataFrame) -> List[float]:
    out = []
    for i, row in enumerate(df.itertuples(index=False), 1):
        out.append(detector.analyze_email(row.sender, row.subject, row.content)["risk_score"])
        if i % 500 == 0:
            print(f"    rules: {i}/{len(df)}", flush=True)
    return out


def bert_scores(df: pd.DataFrame) -> List[float]:
    from ML.bert_model import load_now
    model = load_now()
    if model is None:
        sys.exit("No BERT checkpoint. Run with --no-bert, or train first.")

    out = []
    for i, row in enumerate(df.itertuples(index=False), 1):
        out.append(model.predict_score(row.sender, row.subject, row.content))
        if i % 100 == 0:
            print(f"    BERT: {i}/{len(df)}", flush=True)
    return out


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------
def sweep(y: List[int], h: List[float], b: List[float] | None,
          trusted: List[bool], metric: str):
    """
    Sweeps both parameters of scoring.combine and the threshold.

    The formula is max(bert*damping + boost*rules, rules), not a
    weighted average. The average capped the model at BERT_WEIGHT*100,
    so it could not cross the threshold alone - 52.8% against 99.4% for
    BERT by itself.
    """
    boosts = [round(x * 0.1, 2) for x in range(0, 11)]          # 0.0 - 1.0
    dampings = [1.0] if b is None else [round(x * 0.05, 2) for x in range(1, 21)]
    best = None
    grid = []

    for boost in boosts:
        for damp in dampings:
            combined = [
                min(max((bi * (damp if tr else 1.0)) + boost * hi, hi), 100.0)
                for bi, hi, tr in zip(b if b is not None else [0.0] * len(h), h, trusted)
            ]
            for t in range(20, 96):
                m = metrics(y, [1 if s >= t else 0 for s in combined])
                score = -m["fnr"] if metric == "fnr" else m[metric]
                grid.append((score, boost, damp, t, m))
                if best is None or score > best[0]:
                    best = (score, boost, damp, t, m)

    return best, grid


def main() -> None:
    ap = argparse.ArgumentParser(description="calibrate the ensemble parameters and threshold")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--metric", default="f1", choices=["f1", "accuracy", "fnr"],
                    help="what to maximise (fnr = minimise misses)")
    ap.add_argument("--no-bert", action="store_true", help="calibrate the threshold only")
    ap.add_argument("--split", default="val", choices=["val", "test"])
    ap.add_argument(
        "--with-sender-only", action="store_true",
        help="calibrate only on rows that carry a sender. In production "
             "the extension always sends one, but most corpora hold a "
             "body only - and without it three rules cannot run.",
    )
    args = ap.parse_args()

    if args.split == "test":
        print("!  calibrating on test inflates the result. Use it for the final evaluation only.\n")

    print(f"loading {args.split}.csv ...")
    df = load_split(args.data_dir, args.split)

    has_sender = df["sender"].str.strip() != ""
    if args.with_sender_only:
        if not has_sender.any():
            sys.exit(
                "no rows carry a sender.\n"
                "run  python ML/generate_hebrew.py --n 3000  and then\n"
                "        python ML/prepare_data.py"
            )
        df = df[has_sender].reset_index(drop=True)
        print(f"  kept {int(has_sender.sum())} rows with a sender "
              f"(of {len(has_sender)})")
    elif has_sender.any() and has_sender.mean() < 0.5:
        print(f"  !  only {has_sender.mean()*100:.1f}% of rows carry a sender. Three")
        print(f"     rules read it, so this calibration measures a partial")
        print(f"     engine and will lean toward BERT.")
        print(f"     to compare on complete rows:  --with-sender-only\n")

    y = df["label"].tolist()
    pos = sum(y)
    print(f"  {len(df)} examples | phishing: {pos} ({pos/len(y)*100:.0f}%) | "
          f"legitimate: {len(y)-pos} ({(len(y)-pos)/len(y)*100:.0f}%)\n")

    print("scoring with the rules ...")
    h = heuristic_scores(df)

    b = None
    if not args.no_bert:
        print("\nscoring with BERT (slow - loads the checkpoint) ...")
        b = bert_scores(df)

    trusted = [detector.is_trusted_sender(sd) for sd in df["sender"].tolist()]

    print("\nsweeping combinations ...")
    best, _ = sweep(y, h, b, trusted, args.metric)
    _, boost, damp, t, m = best

    # The current settings, for comparison
    cur_combined = [
        combine(bi, hi, sd)
        for bi, hi, sd in zip(
            b if b is not None else [0.0] * len(h), h, df["sender"].tolist()
        )
    ]
    cur = metrics(y, [1 if s >= PHISHING_THRESHOLD else 0 for s in cur_combined])

    print("\n" + "=" * 72)
    print("  Results")
    print("=" * 72)
    print(f"  current  boost={RULE_BOOST:.2f} trust={TRUST_DAMPING:.2f} "
          f"thr={PHISHING_THRESHOLD:<3}  {fmt(cur)}")
    print(f"  best     boost={boost:.2f} trust={damp:.2f} thr={t:<3}  {fmt(m)}")
    print("-" * 72)
    d_f1 = (m["f1"] - cur["f1"]) * 100
    d_acc = (m["accuracy"] - cur["accuracy"]) * 100
    d_fnr = (m["fnr"] - cur["fnr"]) * 100
    print(f"  change           F1 {d_f1:+.1f} pts | acc {d_acc:+.1f} pts | misses {d_fnr:+.1f} pts")
    print(f"  confusion        TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print("=" * 72)

    if d_f1 <= 0.1 and d_acc <= 0.1:
        print("\n  The current settings are already near optimal.")
        return

    print("\n  To apply, add to backend/.env:\n")
    print(f"      RULE_BOOST={boost}")
    if b is not None:
        print(f"      TRUST_DAMPING={damp}")
    print(f"\n  and the threshold in backend/config.py:\n")
    print(f"      PHISHING_THRESHOLD = {t}")
    print("\n  Afterwards run:")
    print("      python ML/sanity_check.py     # verify on the hard examples")
    print("      python ML/evaluate.py --split test")
    print("  to get the numbers for the report.\n")


if __name__ == "__main__":
    main()
