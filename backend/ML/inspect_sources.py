"""
What columns the raw source files actually carry.

94% of the processed corpus has no sender, which disables three of the
nine rules. Before calling that a limitation of the public data, check
whether it is ours: every loader in prepare_data.py keeps only [text,
label], so a sender column would be discarded without a word.

    python ML/inspect_sources.py
"""
from __future__ import annotations

import argparse
import glob
import os

import pandas as pd

# Names these corpora tend to use.
SENDER_HINTS = ("sender", "from", "from_", "email_from", "sender_email",
                "return_path", "reply_to", "envelope_from")
SUBJECT_HINTS = ("subject", "title", "headline")


def looks_like(name: str, hints: tuple[str, ...]) -> bool:
    low = name.strip().lower().replace(" ", "_")
    return any(low == h or low.startswith(h) or h in low for h in hints)


def surviving_senders(data_dir: str) -> dict[str, tuple[int, int]]:
    """
    Per source, how many processed rows kept a sender.

    Reading the loaders is not enough to tell whether a column survives:
    two of them are handled by a separate path that does carry sender and
    subject through. This checks the processed data instead, which is
    the ground truth.
    """
    path = os.path.join(data_dir, "processed", "test.csv")
    if not os.path.exists(path):
        return {}
    df = pd.read_csv(path)
    if "source" not in df.columns:
        return {}
    if "sender" not in df.columns:
        return {src: (0, len(g)) for src, g in df.groupby("source")}
    out = {}
    for src, g in df.groupby("source"):
        kept = int((g["sender"].fillna("").astype(str).str.strip() != "").sum())
        out[str(src)] = (kept, len(g))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="columns in the raw source files")
    ap.add_argument("--data_dir", default="ML/data")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.data_dir, "*.csv")))
    if not files:
        raise SystemExit(f"no CSV files in {args.data_dir}")

    survived = surviving_senders(args.data_dir)

    print(f"\n{len(files)} source file(s) in {args.data_dir}\n")
    print("=" * 78)
    dropped, kept, absent = [], [], []

    for path in files:
        name = os.path.basename(path)
        stem = name[:-4]
        try:
            head = pd.read_csv(path, nrows=1)
        except Exception as exc:
            print(f"\n  {name}\n    could not read: {exc}")
            continue

        cols = list(head.columns)
        senders = [c for c in cols if looks_like(str(c), SENDER_HINTS)]
        subjects = [c for c in cols if looks_like(str(c), SUBJECT_HINTS)]

        # Match the file to its source tag in the processed data.
        tag = next((t for t in survived if t == stem or stem.startswith(t)
                    or t.startswith(stem.split("_")[0])), None)
        got, total = survived.get(tag, (0, 0)) if tag else (0, 0)

        print(f"\n  {name}")
        print(f"    columns: {cols if len(cols) <= 12 else cols[:12] + ['...']}")
        if tag:
            print(f"    in the processed test split: {got} of {total} rows "
                  f"carry a sender")

        if senders and got:
            print(f"    sender column: {senders}   kept")
            kept.append(name)
        elif senders:
            print(f"    sender column: {senders}   DROPPED by the loader")
            dropped.append((name, senders))
        else:
            print("    no sender column in the source")
            absent.append(name)
        if subjects:
            print(f"    subject-like: {subjects}")

    print("\n" + "=" * 78)
    if dropped:
        print("  Carries a sender that the loader throws away:\n")
        for name, cols in dropped:
            print(f"    {name:<28} {cols}")
        print("\n  Widening that loader would give the rule engine something to")
        print("  work with on those rows.\n")
    if kept:
        print(f"  Sender carried through: {', '.join(kept)}\n")
    if absent:
        print("  No sender in the source at all:\n")
        for name in absent:
            print(f"    {name}")
        print("""
  For these the gap is in the public data, not in our pipeline. They are
  distributed as body text with a label: sender addresses are personal
  data and are usually stripped before release, and the PhishTank file
  is a table of URL features rather than messages at all.

  One exception worth checking by hand: a raw-message column may still
  hold the original headers inside the text. If it does, the From: line
  can be parsed back out - see the note this script prints below.""")

    raw_message = [n for n in absent
                   if "enron" in n.lower() or "message" in n.lower()]
    if raw_message:
        print(f"""
  {', '.join(raw_message)} has a 'message' column. In the usual Enron
  release that field is the complete RFC822 message, headers included -
  so 'From:' and 'Subject:' are probably sitting inside the text and can
  be parsed out. That would add legitimate rows that carry a sender,
  which is exactly what the evaluation is missing. Worth opening the
  file and looking at one row before assuming either way.""")
    print()


if __name__ == "__main__":
    main()
