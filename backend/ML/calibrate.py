"""
כיול משקלי האנסמבל וסף ההחלטה
==============================

הציון הסופי של LURA מורכב משני מנועים:

    final = w * bert_score + (1 - w) * heuristic_score
    phishing  אם  final >= threshold

עד היום `w = 0.3` ו-`threshold = 70` נבחרו ידנית, בלי בסיס בנתונים.
הסקריפט הזה סורק את כל הצירופים על סט הוולידציה ומוצא את אלה
שממקסמים את ה-F1 — בלי לאמן את המודל מחדש.

הרצה (מתוך backend/):
    python ML/calibrate.py
    python ML/calibrate.py --metric fnr      # למזער פספוסים במקום F1
    python ML/calibrate.py --no-bert         # לכייל רק את הסף, בלי BERT

הפלט הוא שתי שורות שאפשר להעתיק ל-.env, ודוח מלא של ההשוואה
לפני ואחרי. סט הבדיקה (test.csv) לא נוגעים בו — הוא נשמר להערכה
סופית, אחרת המספרים שיתקבלו יהיו מנופחים.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Tuple

import pandas as pd

# מאפשר הרצה גם מ-backend/ וגם מ-backend/ML/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector  # noqa: E402
from scoring import combine   # noqa: E402
from config import PHISHING_THRESHOLD, RULE_BOOST, TRUST_DAMPING  # noqa: E402


# ---------------------------------------------------------------------------
# מדדים
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
        # False Negative Rate — אחוז מיילי הפישינג שפספסנו. המדד הכי
        # יקר במוצר אבטחה: פספוס אחד עולה יותר מכמה התראות שווא.
        "fnr":       fn / (tp + fn) if (tp + fn) else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def fmt(m: dict) -> str:
    return (f"acc={m['accuracy']*100:5.1f}%  P={m['precision']:.3f}  "
            f"R={m['recall']:.3f}  F1={m['f1']:.3f}  FNR={m['fnr']*100:4.1f}%")


# ---------------------------------------------------------------------------
# טעינת נתונים וחישוב ציונים
# ---------------------------------------------------------------------------
def load_split(data_dir: str, name: str) -> pd.DataFrame:
    path = os.path.join(data_dir, "processed", f"{name}.csv")
    if not os.path.exists(path):
        sys.exit(f"לא נמצא {path}\nהריצי קודם:  python ML/prepare_data.py")

    df = pd.read_csv(path)
    if df.empty:
        sys.exit(f"{path} ריק. אם הקבצים מנוהלים ב-Git LFS, הריצי:  git lfs pull")

    for col in ("label",):
        if col not in df.columns:
            sys.exit(f"חסרה עמודה '{col}' ב-{path}. עמודות קיימות: {list(df.columns)}")

    # prepare_data.py שומר עמודה אחת בשם text. מנוע החוקים מצפה ל-sender,
    # subject ו-content בנפרד — אם נעביר לו מחרוזות ריקות הוא לא יזהה כלום
    # וכל המדדים יצאו אפס. לכן text ממופה ל-content.
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
        print("  ℹ  אין עמודת sender בנתונים — בדיקות מבוססות שולח לא ירוצו.\n"
              "     המדדים כאן משקפים ניתוח תוכן בלבד, ולכן נמוכים מהמערכת החיה.")

    df["label"] = df["label"].astype(int)
    return df


def heuristic_scores(df: pd.DataFrame) -> List[float]:
    out = []
    for i, row in enumerate(df.itertuples(index=False), 1):
        out.append(detector.analyze_email(row.sender, row.subject, row.content)["risk_score"])
        if i % 500 == 0:
            print(f"    חוקים: {i}/{len(df)}", flush=True)
    return out


def bert_scores(df: pd.DataFrame) -> List[float]:
    from ML.bert_model import load_now
    model = load_now()
    if model is None:
        sys.exit("לא נמצא checkpoint של BERT. הריצי עם --no-bert או אמני קודם.")

    out = []
    for i, row in enumerate(df.itertuples(index=False), 1):
        out.append(model.predict_score(row.sender, row.subject, row.content))
        if i % 100 == 0:
            print(f"    BERT: {i}/{len(df)}", flush=True)
    return out


# ---------------------------------------------------------------------------
# הסריקה
# ---------------------------------------------------------------------------
def sweep(y: List[int], h: List[float], b: List[float] | None,
          trusted: List[bool], metric: str):
    """
    סורק את שני הפרמטרים של scoring.combine ואת סף ההחלטה.

    הנוסחה היא  max(bert·damping + boost·rules, rules)  ולא ממוצע
    משוקלל. המעבר נעשה אחרי שהממוצע נמדד על סט הבדיקה: הוא הטיל
    תקרה של BERT_WEIGHT·100 על ציון המודל, ולכן BERT לא יכול היה
    לחצות את הסף לבדו — 52.8% דיוק מול 99.4% ל-BERT בנפרד.
    """
    boosts = [round(x * 0.1, 2) for x in range(0, 11)]          # 0.0 – 1.0
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
    ap = argparse.ArgumentParser(description="כיול משקלי אנסמבל וסף החלטה")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--metric", default="f1", choices=["f1", "accuracy", "fnr"],
                    help="מה למקסם (fnr = למזער פספוסים)")
    ap.add_argument("--no-bert", action="store_true", help="לכייל רק את הסף")
    ap.add_argument("--split", default="val", choices=["val", "test"])
    ap.add_argument(
        "--with-sender-only", action="store_true",
        help="לכייל רק על שורות שיש בהן כתובת שולח. "
             "בייצור התוסף תמיד שולח שולח ונושא, אבל רוב הקורפוסים "
             "מכילים גוף מייל בלבד — ובלעדיהם שלוש מבדיקות מנוע החוקים "
             "אינן פועלות והכיול מטה את המשקל ל-BERT.",
    )
    args = ap.parse_args()

    if args.split == "test":
        print("⚠  כיול על test מנפח את התוצאות. השתמשי בו רק להערכה סופית.\n")

    print(f"טוען {args.split}.csv ...")
    df = load_split(args.data_dir, args.split)

    has_sender = df["sender"].str.strip() != ""
    if args.with_sender_only:
        if not has_sender.any():
            sys.exit(
                "אין שורות עם כתובת שולח.\n"
                "הריצי  python ML/generate_hebrew.py --n 3000  ואחריו\n"
                "        python ML/prepare_data.py"
            )
        df = df[has_sender].reset_index(drop=True)
        print(f"  סוננו {int(has_sender.sum())} שורות עם שולח "
              f"(מתוך {len(has_sender)})")
    elif has_sender.any() and has_sender.mean() < 0.5:
        print(f"  ⚠  רק {has_sender.mean()*100:.1f}% מהשורות מכילות כתובת שולח.")
        print(f"     שלוש מבדיקות מנוע החוקים קוראות אותה, ולכן הכיול כאן")
        print(f"     ימדוד מנוע חלקי וייטה להעדיף את BERT.")
        print(f"     להשוואה על נתונים מלאים:  --with-sender-only\n")

    y = df["label"].tolist()
    pos = sum(y)
    print(f"  {len(df)} דוגמאות | פישינג: {pos} ({pos/len(y)*100:.0f}%) | "
          f"לגיטימי: {len(y)-pos} ({(len(y)-pos)/len(y)*100:.0f}%)\n")

    print("מחשב ציוני חוקים ...")
    h = heuristic_scores(df)

    b = None
    if not args.no_bert:
        print("\nמחשב ציוני BERT (איטי — טוען checkpoint) ...")
        b = bert_scores(df)

    trusted = [detector.is_trusted_sender(sd) for sd in df["sender"].tolist()]

    print("\nסורק צירופים ...")
    best, _ = sweep(y, h, b, trusted, args.metric)
    _, boost, damp, t, m = best

    # ההגדרות הנוכחיות, להשוואה
    cur_combined = [
        combine(bi, hi, sd)
        for bi, hi, sd in zip(
            b if b is not None else [0.0] * len(h), h, df["sender"].tolist()
        )
    ]
    cur = metrics(y, [1 if s >= PHISHING_THRESHOLD else 0 for s in cur_combined])

    print("\n" + "═" * 72)
    print("  תוצאות")
    print("═" * 72)
    print(f"  נוכחי   boost={RULE_BOOST:.2f} trust={TRUST_DAMPING:.2f} "
          f"סף={PHISHING_THRESHOLD:<3}  {fmt(cur)}")
    print(f"  מומלץ   boost={boost:.2f} trust={damp:.2f} סף={t:<3}  {fmt(m)}")
    print("─" * 72)
    d_f1 = (m["f1"] - cur["f1"]) * 100
    d_acc = (m["accuracy"] - cur["accuracy"]) * 100
    d_fnr = (m["fnr"] - cur["fnr"]) * 100
    print(f"  שינוי           F1 {d_f1:+.1f} נק׳ | דיוק {d_acc:+.1f} נק׳ | פספוסים {d_fnr:+.1f} נק׳")
    print(f"  מטריצת בלבול    TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print("═" * 72)

    if d_f1 <= 0.1 and d_acc <= 0.1:
        print("\n  ההגדרות הנוכחיות כבר קרובות לאופטימום — אין מה לשנות.")
        return

    print("\n  להחלה, הוסיפי ל-backend/.env:\n")
    print(f"      RULE_BOOST={boost}")
    if b is not None:
        print(f"      TRUST_DAMPING={damp}")
    print(f"\n  ואת הסף ב-backend/config.py:\n")
    print(f"      PHISHING_THRESHOLD = {t}")
    print("\n  אחרי השינוי הריצי:")
    print("      python ML/sanity_check.py     # אימות על דוגמאות קשות")
    print("      python ML/evaluate.py --split test")
    print("  כדי לקבל את המספרים לדוח ולמצגת.\n")


if __name__ == "__main__":
    main()
