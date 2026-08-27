"""
Grow the Hebrew data by machine translation.

The corpus holds only a few hundred Hebrew messages out of ~132,000, so
the model barely sees the language and any claim about Hebrew support
rests on too small a sample. This translates a slice of the English
corpus, which is real phishing with real attack structure.

Known limitation: translated phishing is not the same as phishing
written in Hebrew - the phrasing is too clean, with no slang or typical
mistakes. An improvement on what was there, not a substitute for
authentic data.

Install:
    pip install deep-translator

Usage:
    python ML/augment_hebrew.py --n 3000
    python ML/augment_hebrew.py --n 500 --dry-run    # quick check

Output goes to ML/data/hebrew_translated.csv. Afterwards:
    python ML/prepare_data.py
    python ML/train.py --epochs 6
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

MAX_CHARS = 4500          # length limit for one translation request
SLEEP_BETWEEN = 0.12      # a small pause, to avoid being blocked


def load_source(data_dir: str, n: int, seed: int) -> pd.DataFrame:
    """Sample English messages from the processed splits, class-balanced."""
    path = os.path.join(data_dir, "processed", "train.csv")
    if not os.path.exists(path):
        sys.exit(f"{path} not found\nrun first:  python ML/prepare_data.py")

    df = pd.read_csv(path).dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    # Skip anything already in Hebrew
    df = df[~df["text"].str.contains(r"[֐-׿]", na=False, regex=True)]
    df = df[df["text"].str.len().between(40, MAX_CHARS)]

    per_class = max(n // 2, 1)
    parts = []
    for label in (0, 1):
        sub = df[df["label"] == label]
        if sub.empty:
            continue
        parts.append(sub.sample(min(per_class, len(sub)), random_state=seed))

    out = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed)
    return out.reset_index(drop=True)


def translate_batch(texts: list[str]) -> list[str | None]:
    try:
        from deep_translator import GoogleTranslator
    except ImportError:
        sys.exit(
            "deep-translator is not installed.\n"
            "install it:  pip install deep-translator"
        )

    translator = GoogleTranslator(source="en", target="iw")
    out: list[str | None] = []
    failures = 0

    for i, text in enumerate(texts, 1):
        try:
            out.append(translator.translate(text[:MAX_CHARS]))
        except Exception as exc:
            failures += 1
            out.append(None)
            if failures <= 3:
                print(f"    translation error ({failures}): {exc}")
            if failures > 50:
                print("    too many errors - stopping. Possibly rate limited.")
                out.extend([None] * (len(texts) - i))
                break
        if i % 25 == 0:
            done = sum(1 for t in out if t)
            print(f"    {i}/{len(texts)}  (done: {done})", flush=True)
        time.sleep(SLEEP_BETWEEN)

    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="grow the Hebrew data by translation")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--n", type=int, default=3000, help="how many messages to translate")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true",
                    help="translate 5 examples and print them, without saving")
    args = ap.parse_args()

    print(f"sampling {args.n} English messages ...")
    df = load_source(args.data_dir, args.n, args.seed)
    print(f"  selected {len(df)}  |  phishing: {int(df.label.sum())}  |  "
          f"לגיטימי: {int((df.label == 0).sum())}\n")

    if args.dry_run:
        sample = df.head(5)
        print("תרגום דוגמה:\n")
        for src, heb in zip(sample["text"], translate_batch(sample["text"].tolist())):
            print(f"  EN: {src[:110]}...")
            print(f"  HE: {(heb or '(נכשל)')[:110]}...\n")
        return

    est = len(df) * SLEEP_BETWEEN / 60
    print(f"מתרגם ... (הערכה גסה: {est:.0f}–{est*3:.0f} דקות)")
    print("אפשר להשאיר רץ ברקע.\n")

    translated = translate_batch(df["text"].tolist())

    rows = [
        {"text": heb, "label": int(label)}
        for heb, label in zip(translated, df["label"])
        if heb and len(heb.strip()) > 20
    ]

    if not rows:
        sys.exit("לא הצליח לתרגם דבר. בדקי חיבור לאינטרנט או נסי שוב מאוחר יותר.")

    out_df = pd.DataFrame(rows).drop_duplicates(subset="text")
    out_path = os.path.join(args.data_dir, "hebrew_translated.csv")
    out_df.to_csv(out_path, index=False, encoding="utf-8")

    print(f"\n{'═' * 60}")
    print(f"  נשמרו {len(out_df)} מיילים בעברית → {out_path}")
    print(f"  פישינג: {int(out_df.label.sum())}  |  "
          f"לגיטימי: {int((out_df.label == 0).sum())}")
    print(f"  שיעור הצלחה: {len(rows)/len(df)*100:.0f}%")
    print(f"{'═' * 60}")
    print("\n  הצעדים הבאים:")
    print("    python ML/prepare_data.py      # יאסוף גם את הקובץ החדש")
    print("    python ML/train.py --epochs 6")
    print("    python ML/evaluate.py          # פילוח לפי שפה\n")


if __name__ == "__main__":
    main()
