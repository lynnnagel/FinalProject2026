"""
הערכת המערכת — כללית ובפילוח לפי שפה
=====================================

הדוח הנוכחי מציג מספר דיוק אחד. מכיוון ש-99.8% מהמאגר באנגלית,
המספר הזה כמעט לא מושפע מהביצועים בעברית — שהיא הבידול של הפרויקט.

הסקריפט מריץ את הצינור המלא (חוקים + BERT, אם קיים checkpoint) על
סט הבדיקה, ומדווח בנפרד על עברית ועל אנגלית.

הרצה (מתוך backend/):
    python ML/evaluate.py                  # סט הבדיקה, אנסמבל מלא
    python ML/evaluate.py --split val
    python ML/evaluate.py --no-bert        # חוקים בלבד, להשוואה
    python ML/evaluate.py --limit 2000     # דגימה מהירה
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector                                     # noqa: E402
from config import PHISHING_THRESHOLD, BERT_WEIGHT, HEURISTIC_WEIGHT  # noqa: E402
from ML.calibrate import metrics, load_split                      # noqa: E402

HEBREW_CHARS = r"[֐-׿]"


def score_rows(df: pd.DataFrame, use_bert: bool) -> list[float]:
    model = None
    if use_bert:
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            print("  אין checkpoint — ממשיך עם חוקים בלבד\n")

    scores = []
    for i, row in enumerate(df.itertuples(index=False), 1):
        h = detector.analyze_email(row.sender, row.subject, row.content)["risk_score"]
        if model is None:
            scores.append(h)
        else:
            b = model.predict_score(row.sender, row.subject, row.content)
            scores.append(min(BERT_WEIGHT * b + HEURISTIC_WEIGHT * h, 100.0))
        if i % 500 == 0:
            print(f"    {i}/{len(df)}", flush=True)
    return scores


def report(title: str, y_true: list[int], y_pred: list[int]) -> None:
    n = len(y_true)
    if n == 0:
        print(f"  {title:<12} — אין דוגמאות")
        return
    m = metrics(y_true, y_pred)
    pos = sum(y_true)
    print(f"  {title:<12} {n:>6} דוגמאות ({pos} פישינג)")
    print(f"               דיוק {m['accuracy']*100:5.1f}%  |  F1 {m['f1']:.3f}  |  "
          f"פספוסים {m['fnr']*100:4.1f}%  |  TP={m['tp']} FP={m['fp']} FN={m['fn']}")
    if n < 200:
        print(f"               ⚠  מדגם קטן — המספרים כאן לא יציבים")


def main() -> None:
    ap = argparse.ArgumentParser(description="הערכה בפילוח לפי שפה")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--no-bert", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="הגבלת מספר דוגמאות (0 = הכל)")
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    args = ap.parse_args()

    df = load_split(args.data_dir, args.split)
    if args.limit:
        df = df.sample(min(args.limit, len(df)), random_state=42).reset_index(drop=True)

    is_hebrew = df["text"].str.contains(HEBREW_CHARS, na=False, regex=True) \
        if "text" in df.columns else \
        (df["subject"] + " " + df["content"]).str.contains(HEBREW_CHARS, na=False, regex=True)

    print(f"\nסט: {args.split}  |  {len(df)} דוגמאות")
    print(f"  עברית: {int(is_hebrew.sum())}  |  אנגלית: {int((~is_hebrew).sum())}")
    mode = "חוקים בלבד" if args.no_bert else f"אנסמבל ({BERT_WEIGHT}/{HEURISTIC_WEIGHT})"
    print(f"  מצב: {mode}  |  סף: {args.threshold}\n")

    print("מחשב ציונים ...")
    scores = score_rows(df, use_bert=not args.no_bert)
    y = df["label"].tolist()
    pred = [1 if s >= args.threshold else 0 for s in scores]

    print("\n" + "═" * 72)
    print("  תוצאות")
    print("═" * 72)
    report("כללי", y, pred)
    print()
    heb_idx = [i for i, v in enumerate(is_hebrew) if v]
    eng_idx = [i for i, v in enumerate(is_hebrew) if not v]
    report("עברית", [y[i] for i in heb_idx], [pred[i] for i in heb_idx])
    report("אנגלית", [y[i] for i in eng_idx], [pred[i] for i in eng_idx])
    print("═" * 72)

    if len(heb_idx) < 200:
        print(f"\n  ⚠  רק {len(heb_idx)} דוגמאות בעברית בסט הבדיקה.")
        print("     זה מעט מדי כדי לטעון טענה על ביצועים בעברית.")
        print("     כדי להגדיל: python ML/augment_hebrew.py\n")


if __name__ == "__main__":
    main()
