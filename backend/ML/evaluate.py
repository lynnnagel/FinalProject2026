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
from config import PHISHING_THRESHOLD, RULE_BOOST, TRUST_DAMPING  # noqa: E402
from scoring import combine                                       # noqa: E402
from ML.calibrate import metrics, load_split                      # noqa: E402

HEBREW_CHARS = r"[֐-׿]"


def score_rows(df: pd.DataFrame, use_bert: bool,
               bert_only: bool = False) -> list[float]:
    model = None
    if use_bert:
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            print("  אין checkpoint — ממשיך עם חוקים בלבד\n")

    rows = list(df.itertuples(index=False))

    heur = [0.0] * len(rows)
    if not bert_only:
        for i, row in enumerate(rows, 1):
            heur[i - 1] = detector.analyze_email(
                row.sender, row.subject, row.content
            )["risk_score"]
            if i % 2000 == 0:
                print(f"    חוקים: {i}/{len(rows)}", flush=True)

    if model is None:
        return heur

    # במקבצים ולא שורה-שורה: forward אחד לכל מייל על 16,137 שורות
    # לוקח עשרות דקות על CPU, ורוב הזמן הוא overhead ולא חישוב.
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
                else combine(b, h, row.sender, row.subject, row.content)
            )
        done = min(start + BATCH, len(rows))
        if done % 512 < BATCH:
            print(f"    BERT: {done}/{len(rows)}", flush=True)
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
    ap.add_argument("--no-bert", action="store_true", help="חוקים בלבד")
    ap.add_argument("--bert-only", action="store_true",
                    help="BERT בלבד, בלי מנוע החוקים ובלי משקלול")
    ap.add_argument("--with-sender", action="store_true",
                    help="רק שורות שיש בהן כתובת שולח")
    ap.add_argument("--limit", type=int, default=0, help="הגבלת מספר דוגמאות (0 = הכל)")
    ap.add_argument("--threshold", type=int, default=PHISHING_THRESHOLD)
    args = ap.parse_args()

    if args.no_bert and args.bert_only:
        sys.exit("--no-bert ו---bert-only סותרים זה את זה")

    df = load_split(args.data_dir, args.split)

    # רוב הקורפוסים באנגלית מספקים גוף מייל בלבד, בלי שורת From. שלוש
    # מתשע בדיקות מנוע החוקים קוראות את כתובת השולח — ובהן בדיקת
    # ההתחזות למותג, שנותנת את הניקוד הגבוה ביותר. על שורות בלי שולח
    # המנוע רץ משותק, וכל מדד של האנסמבל עליהן מודד מערכת אחרת מזו
    # שרצה בתוסף, שם Gmail תמיד מספק את השולח.
    has_sender = df["sender"].str.strip() != ""
    if args.with_sender:
        df = df[has_sender].reset_index(drop=True)
        if df.empty:
            sys.exit("אין שורות עם שולח בסט הזה.")

    if args.limit:
        df = df.sample(min(args.limit, len(df)), random_state=42).reset_index(drop=True)

    is_hebrew = df["text"].str.contains(HEBREW_CHARS, na=False, regex=True) \
        if "text" in df.columns else \
        (df["subject"] + " " + df["content"]).str.contains(HEBREW_CHARS, na=False, regex=True)

    n_sender = int((df["sender"].str.strip() != "").sum())

    print(f"\nסט: {args.split}  |  {len(df)} דוגמאות")
    print(f"  עברית: {int(is_hebrew.sum())}  |  אנגלית: {int((~is_hebrew).sum())}")
    print(f"  עם שולח: {n_sender} ({n_sender / len(df) * 100:.1f}%)")
    if args.no_bert:
        mode = "חוקים בלבד"
    elif args.bert_only:
        mode = "BERT בלבד"
    else:
        mode = f"אנסמבל (boost={RULE_BOOST}, trust={TRUST_DAMPING})"
    print(f"  מצב: {mode}  |  סף: {args.threshold}\n")

    # הסף כוון לציון האנסמבל. על ציון BERT גולמי, שנע בין 0 ל-100
    # בפני עצמו, אין לו משמעות — לכן 50.
    threshold = 50 if args.bert_only else args.threshold
    if args.bert_only:
        print("  (סף 50 על הציון הגולמי — סף האנסמבל אינו חל כאן)\n")

    print("מחשב ציונים ...")
    scores = score_rows(df, use_bert=not args.no_bert, bert_only=args.bert_only)
    y = df["label"].tolist()
    pred = [1 if s >= threshold else 0 for s in scores]

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
        print("     כדי להגדיל: python ML/augment_hebrew.py")

    # הנוסחה הישנה, ממוצע משוקלל, הטילה תקרה של BERT_WEIGHT·100 על
    # ציון המודל וכך מנעה ממנו לחצות את הסף לבדו. scoring.combine
    # החליף אותה ב-max, ולכן האזהרה שהייתה כאן אינה רלוונטית עוד:
    # כל מנוע יכול להגיע ל-100 בכוחות עצמו.
    if n_sender < len(df) * 0.5 and not args.bert_only:
        missing = len(df) - n_sender
        print(f"\n  ℹ  ב-{missing} שורות ({missing / len(df) * 100:.0f}%) אין כתובת שולח,")
        print("     ולכן שלוש מתשע בדיקות מנוע החוקים — כולל התחזות למותג —")
        print("     לא יכולות לרוץ עליהן. בתוסף Gmail תמיד מספק שולח.")
        print("     להשוואה על שורות שבהן המנוע כן עובד:")
        print("       python ML/evaluate.py --split test --with-sender")
    print()


if __name__ == "__main__":
    main()
