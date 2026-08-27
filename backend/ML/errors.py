"""
The messages the system gets wrong, and what they have in common.

The threshold is exhausted: from 60 to 80 the false alarms fall only
from 44 to 37, so the remaining errors are ones the model is confident
about. Any further gain has to come from the data or the model, and the
way to find it is to look at the errors rather than guess.

This scores a split, collects every false alarm and every miss, and
groups them - by source, by language, by which engine drove the score.
If the errors cluster, there is a targeted fix. If they do not, that is
worth knowing too.

    python ML/errors.py
    python ML/errors.py --show 30          # more examples
    python ML/errors.py --kind fn          # misses only
    python ML/errors.py --csv errors.csv   # write them all out
"""
from __future__ import annotations

import argparse
import os
import re
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector                                    # noqa: E402
from scoring import combine                                      # noqa: E402
from config import PHISHING_THRESHOLD                            # noqa: E402
from ML.calibrate import load_split                              # noqa: E402

HEBREW = re.compile(r"[֐-׿]")


def snippet(text: str, n: int = 60) -> str:
    one = " ".join(str(text or "").split())
    return one[:n] + ("..." if len(one) > n else "")


def group_counts(rows: list[dict], key: str, title: str) -> None:
    if not rows:
        return
    counts: dict[str, int] = {}
    for r in rows:
        counts[str(r[key])] = counts.get(str(r[key]), 0) + 1
    print(f"\n  by {title}:")
    for value, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        share = n / len(rows) * 100
        print(f"    {value:<26} {n:>5}  ({share:>4.1f}%)")


def main() -> None:
    ap = argparse.ArgumentParser(description="the messages the system gets wrong")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    ap.add_argument("--show", type=int, default=15, help="examples to print")
    ap.add_argument("--kind", default="both", choices=["both", "fp", "fn"])
    ap.add_argument("--csv", help="write every error to this file")
    ap.add_argument("--no-bert", action="store_true")
    args = ap.parse_args()

    df = load_split(args.data_dir, args.split)
    rows = list(df.itertuples(index=False))
    y = df["label"].tolist()
    sources = df["source"].tolist() if "source" in df.columns else [""] * len(rows)

    print(f"\nsplit: {args.split}  |  {len(rows)} rows  |  threshold {args.threshold}\n")
    print("scoring with the rules ...")
    heur = [detector.analyze_email(r.sender, r.subject, r.content)["risk_score"]
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
            if done % 2048 < BATCH:
                print(f"    {done}/{len(rows)}", flush=True)

    errors = {"fp": [], "fn": []}
    for i, row in enumerate(rows):
        score = combine(bert[i], heur[i], row.sender, row.subject, row.content)
        pred = 1 if score >= args.threshold else 0
        if pred == y[i]:
            continue
        kind = "fp" if y[i] == 0 else "fn"
        text = f"{row.subject} {row.content}"
        errors[kind].append({
            "kind": kind,
            "score": round(score, 1),
            "bert": round(bert[i], 1),
            "rules": round(heur[i], 1),
            "source": sources[i] or "unknown",
            "language": "Hebrew" if HEBREW.search(text) else "English",
            "has_sender": "yes" if str(row.sender).strip() else "no",
            # Which engine put the score where it is. On a false alarm
            # this says who to go and fix.
            "driver": ("rules" if heur[i] >= score - 0.01
                       else "model" if bert[i] >= args.threshold else "both"),
            "sender": str(row.sender)[:40],
            "subject": snippet(row.subject, 50),
            "content": snippet(row.content, 90),
        })

    kinds = ["fp", "fn"] if args.kind == "both" else [args.kind]
    titles = {"fp": "False alarms - legitimate mail that was flagged",
              "fn": "Misses - phishing that was not flagged"}

    for kind in kinds:
        group = errors[kind]
        print("\n" + "=" * 78)
        print(f"  {titles[kind]}:  {len(group)}")
        print("=" * 78)
        if not group:
            print("  none")
            continue

        group_counts(group, "source", "source")
        group_counts(group, "language", "language")
        group_counts(group, "has_sender", "sender present")
        group_counts(group, "driver", "what drove the score")

        print(f"\n  {min(args.show, len(group))} of them, highest score first:\n")
        print(f"  {'score':>6} {'bert':>6} {'rules':>6}  {'source':<18} sender / subject")
        print("  " + "-" * 74)
        for r in sorted(group, key=lambda r: -r["score"])[:args.show]:
            print(f"  {r['score']:>6} {r['bert']:>6} {r['rules']:>6}  "
                  f"{r['source']:<18} {r['sender'] or '(no sender)'}")
            print(f"  {'':>6} {'':>6} {'':>6}  {'':<18} {r['subject']}")

    if args.csv:
        allrows = errors["fp"] + errors["fn"]
        pd.DataFrame(allrows).to_csv(args.csv, index=False, encoding="utf-8-sig")
        print(f"\n  {len(allrows)} errors written to {args.csv}")

    print(f"""
  What to read from this. If the false alarms cluster in one source or
  one language, that is where to add data. If they are spread evenly,
  the ceiling is the model rather than the corpus, and the next step is
  a different one - more legitimate mail of the kind the corpora lack,
  or a stronger base model.
""")


if __name__ == "__main__":
    main()
