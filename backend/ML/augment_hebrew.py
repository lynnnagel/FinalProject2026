"""
הגדלת הדאטה העברי בתרגום מכונה
==============================

הבעיה: המאגר מכיל ~300 מיילים בעברית מתוך ~132,000 — כ-0.2%.
המודל למעשה לא רואה עברית, ולכן הטענה על "תמיכה בעברית" נשענת על
מדגם קטן מדי מכדי להיות מדיד.

הפתרון כאן: לתרגם פרוסה מהקורפוס האנגלי הקיים. מיילי הפישינג
באנגלית הם דוגמאות אמיתיות עם מבנה תקיפה אמיתי — התרגום שומר על
המבנה הזה ונותן אלפי דוגמאות בעברית במקום מאות תבניות שנכתבו ביד.

מגבלה שכדאי להכיר: פישינג מתורגם אינו זהה לפישינג שנכתב מלכתחילה
בעברית — הניסוח נקי מדי, ואין בו סלנג או שגיאות אופייניות. זה שיפור
משמעותי על המצב הקיים, לא תחליף לדאטה אותנטי.

התקנה:
    pip install deep-translator

הרצה (מתוך backend/):
    python ML/augment_hebrew.py --n 3000
    python ML/augment_hebrew.py --n 500 --dry-run    # בדיקה מהירה

הפלט נשמר ל-ML/data/hebrew_translated.csv. אחרי ההרצה:
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

MAX_CHARS = 4500          # מגבלת אורך לבקשת תרגום בודדת
SLEEP_BETWEEN = 0.12      # השהיה קלה כדי לא להיחסם


def load_source(data_dir: str, n: int, seed: int) -> pd.DataFrame:
    """דוגם מיילים באנגלית מהסטים המעובדים, מאוזן בין פישינג ללגיטימי."""
    path = os.path.join(data_dir, "processed", "train.csv")
    if not os.path.exists(path):
        sys.exit(f"לא נמצא {path}\nהריצי קודם:  python ML/prepare_data.py")

    df = pd.read_csv(path).dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    # מדלגים על מה שכבר בעברית
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
            "חסרה הספרייה deep-translator.\n"
            "התקיני:  pip install deep-translator"
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
                print(f"    שגיאת תרגום ({failures}): {exc}")
            if failures > 50:
                print("    יותר מדי שגיאות — עוצר. ייתכן חסימה זמנית.")
                out.extend([None] * (len(texts) - i))
                break
        if i % 25 == 0:
            done = sum(1 for t in out if t)
            print(f"    {i}/{len(texts)}  (הצליחו: {done})", flush=True)
        time.sleep(SLEEP_BETWEEN)

    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="הגדלת דאטה עברי בתרגום")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--n", type=int, default=3000, help="כמה מיילים לתרגם")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true",
                    help="מתרגם 5 דוגמאות ומדפיס אותן, בלי לשמור")
    args = ap.parse_args()

    print(f"דוגם {args.n} מיילים באנגלית ...")
    df = load_source(args.data_dir, args.n, args.seed)
    print(f"  נבחרו {len(df)}  |  פישינג: {int(df.label.sum())}  |  "
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
