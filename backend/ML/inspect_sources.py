"""
What columns the raw source files actually carry.

94% of the processed corpus has no sender address, which disables three
of the nine rules. Before calling that a limitation of the public data,
it is worth checking whether it is ours: every loader in prepare_data.py
keeps only [text, label] and discards the rest, so a sender column in a
source file would be thrown away without a word.

This reads the header of each file in the data directory and says which
of them carry something that looks like a sender, a subject or a date.

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


def main() -> None:
    ap = argparse.ArgumentParser(description="columns in the raw source files")
    ap.add_argument("--data_dir", default="ML/data")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.data_dir, "*.csv")))
    if not files:
        raise SystemExit(f"no CSV files in {args.data_dir}")

    print(f"\n{len(files)} source file(s) in {args.data_dir}\n")
    print("=" * 78)
    recoverable = []

    for path in files:
        name = os.path.basename(path)
        try:
            head = pd.read_csv(path, nrows=1)
        except Exception as exc:
            print(f"\n  {name}\n    could not read: {exc}")
            continue

        cols = list(head.columns)
        senders = [c for c in cols if looks_like(str(c), SENDER_HINTS)]
        subjects = [c for c in cols if looks_like(str(c), SUBJECT_HINTS)]

        print(f"\n  {name}")
        print(f"    columns: {cols}")
        if senders:
            print(f"    SENDER-LIKE: {senders}   <- currently discarded")
            recoverable.append((name, senders))
        if subjects:
            print(f"    subject-like: {subjects}")
        if not senders and not subjects:
            print("    no sender or subject column")

    print("\n" + "=" * 78)
    if recoverable:
        print("  These files carry a sender that the loaders throw away:\n")
        for name, cols in recoverable:
            print(f"    {name:<28} {cols}")
        print("""
  Every loader in prepare_data.py keeps only [text, label]. Widening
  them to carry the sender through would give the rule engine something
  to work with on those rows - and would make its contribution
  measurable, which it currently is not.""")
    else:
        print("""  No source file carries a sender column.

  So the gap is in the public data, not in our pipeline. These corpora
  are distributed as body text with a label: sender addresses are
  personal data and are usually stripped before release, and PhishTank
  is a feed of URLs rather than of messages at all.

  That is worth stating plainly as a limitation of the evaluation: the
  corpus cannot exercise the sender-based rules, and no change to our
  code would alter that.""")
    print()


if __name__ == "__main__":
    main()
