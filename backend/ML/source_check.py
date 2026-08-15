"""
בדיקת הפרדה לפי מקור
=====================

השאלה: האם המודל לומד לזהות פישינג, או לומד מאיזה קורפוס הגיע הטקסט?

הקורפוסים מגיעים ממקומות שונים לגמרי — Enron הם מיילים עסקיים מ-2001,
PhishTank הוא פישינג עכשווי, SpamAssassin משנות ה-2000. אם כל קורפוס
נוטה למחלקה אחת, מודל יכול לקבל דיוק גבוה מאוד בלי ללמוד דבר על פישינג:
מספיק לו לזהות את הסגנון של המאגר.

זו בעיה מוכרת ומתועדת בספרות, והיא ההסבר הנפוץ לדיוק חריג של 99%+.

שלוש בדיקות, כולן על TF-IDF ורגרסיה לוגיסטית — שניות במקום שעות:

  1. התפלגות התוויות בכל מקור. אם מקור הוא 100% מחלקה אחת, ניבוי המקור
     שקול לניבוי התווית.
  2. עד כמה קל לנחש את המקור מהטקסט. דיוק גבוה פירושו שהמאגרים נבדלים
     בסגנון, לא רק בתוכן.
  3. אימון בלי מקור אחד ובדיקה עליו. זו הבדיקה המכרעת: אם הדיוק צונח,
     המודל נשען על מאפייני מאגר ולא על סימני פישינג.

הרצה (מתוך backend/):
    python ML/source_check.py
    python ML/source_check.py --limit 20000    # מהיר יותר
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import cross_val_score


def load(data_dir: str, limit: int) -> pd.DataFrame:
    path = os.path.join(data_dir, "processed", "train.csv")
    if not os.path.exists(path):
        sys.exit(f"לא נמצא {path}\nהריצי קודם:  python ML/prepare_data.py")

    df = pd.read_csv(path).dropna(subset=["text", "label"])
    if "source" not in df.columns:
        sys.exit(
            "אין עמודת 'source' בנתונים.\n"
            "הריצי מחדש:  python ML/prepare_data.py\n"
            "(הגרסה המעודכנת מתייגת כל שורה במקור שממנו הגיעה)"
        )
    if limit and limit < len(df):
        df = df.sample(limit, random_state=42).reset_index(drop=True)
    return df


def fit_predict(train_texts, train_y, test_texts) -> np.ndarray:
    vec = TfidfVectorizer(max_features=30_000, ngram_range=(1, 2), min_df=2)
    X_train = vec.fit_transform(train_texts)
    X_test = vec.transform(test_texts)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, train_y)
    return clf.predict(X_test)


def main() -> None:
    ap = argparse.ArgumentParser(description="בדיקת הפרדה לפי מקור")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--limit", type=int, default=40_000,
                    help="דגימה כדי לקצר את הריצה (0 = הכל)")
    args = ap.parse_args()

    df = load(args.data_dir, args.limit)
    print(f"\n{len(df):,} שורות | {df['source'].nunique()} מקורות\n")

    # ── 1. התפלגות תוויות לפי מקור ───────────────────────────────────
    print("═" * 68)
    print("  1. התפלגות התוויות בכל מקור")
    print("═" * 68)
    print(f"  {'מקור':<18} {'שורות':>8} {'פישינג':>9} {'לגיטימי':>9}   הערה")
    print("  " + "─" * 64)

    confounded = []
    for src, g in df.groupby("source"):
        pct = g["label"].mean() * 100
        note = ""
        if pct >= 97 or pct <= 3:
            note = "⚠  מחלקה אחת בלבד"
            confounded.append(src)
        print(f"  {src:<18} {len(g):>8,} {pct:>8.1f}% {100-pct:>8.1f}%   {note}")

    if confounded:
        print(f"\n  {len(confounded)} מקורות מכילים מחלקה אחת כמעט בלעדית.")
        print("  עבורם, ניבוי המקור שקול לניבוי התווית.")

    # ── 2. כמה קל לנחש את המקור ──────────────────────────────────────
    print("\n" + "═" * 68)
    print("  2. עד כמה הטקסט מסגיר מאיזה מאגר הוא הגיע")
    print("═" * 68)

    vec = TfidfVectorizer(max_features=30_000, ngram_range=(1, 2), min_df=2)
    X = vec.fit_transform(df["text"].astype(str))
    src_acc = cross_val_score(
        LogisticRegression(max_iter=1000),
        X, df["source"], cv=3, scoring="accuracy",
    ).mean()

    print(f"  דיוק בניבוי המקור: {src_acc*100:.1f}%")
    if src_acc > 0.95:
        print("  ⚠  המאגרים נבדלים זה מזה בבירור — סגנון, אוצר מילים או פורמט.")
        print("     יחד עם ממצא 1, זה אומר שאפשר לקבל דיוק גבוה בלי ללמוד פישינג.")
    else:
        print("  המאגרים מעורבבים למדי — סיכון נמוך יותר להפרדה לפי מקור.")

    # ── 3. אימון בלי מקור אחד, בדיקה עליו ────────────────────────────
    print("\n" + "═" * 68)
    print("  3. הבדיקה המכרעת: אימון בלי מקור, ובדיקה עליו")
    print("═" * 68)
    print("  אם הדיוק צונח, המודל נשען על מאפייני המאגר ולא על סימני פישינג.\n")
    print(f"  {'מקור שהוחזק בחוץ':<20} {'n':>7} {'דיוק':>8} {'F1':>8}   הערה")
    print("  " + "─" * 64)

    results = []
    for src in sorted(df["source"].unique()):
        held = df[df["source"] == src]
        rest = df[df["source"] != src]

        if len(held) < 50 or rest["label"].nunique() < 2:
            print(f"  {src:<20} {len(held):>7,} {'—':>8} {'—':>8}   מדגם קטן מדי")
            continue

        pred = fit_predict(rest["text"].astype(str), rest["label"], held["text"].astype(str))
        acc = accuracy_score(held["label"], pred)

        # מקור חד-מחלקתי: F1 חסר משמעות, אך הדיוק דווקא מאלף —
        # הוא שואל אם המודל עדיין מסווג נכון מאגר שלא ראה. אלה
        # המקורות שההפרדה לפי מקור מסוכנת בהם ביותר, ולכן אין
        # לדלג עליהם.
        single = held["label"].nunique() < 2
        f1 = float("nan") if single else f1_score(held["label"], pred, zero_division=0)
        f1_txt = "—" if single else f"{f1:.3f}"

        note = "⚠  נפילה חדה" if acc < 0.75 else ""
        if single and not note:
            note = "מחלקה אחת"

        results.append((src, acc, f1))
        print(f"  {src:<20} {len(held):>7,} {acc*100:>7.1f}% {f1_txt:>8}   {note}")

    # ── מסקנה ────────────────────────────────────────────────────────
    print("\n" + "═" * 68)
    print("  מסקנה")
    print("═" * 68)

    if not results:
        print("  לא היו מקורות עם שתי המחלקות — לא ניתן להסיק.")
    else:
        mean_acc = float(np.mean([a for _, a, _ in results]))
        print(f"  דיוק ממוצע על מקור שלא נראה באימון: {mean_acc*100:.1f}%")
        if mean_acc < 0.75:
            print("\n  הביצועים צונחים על מקור חדש. חלק ניכר מהדיוק המדווח")
            print("  מגיע מזיהוי המאגר ולא מזיהוי פישינג. יש לדווח על כך")
            print("  ולסייג את המספר הכללי.")
        elif mean_acc < 0.88:
            print("\n  ירידה מתונה. המודל מכליל חלקית, אך מאפייני המאגר תורמים")
            print("  לדיוק המדווח. ראוי לציין זאת במגבלות.")
        else:
            print("\n  הביצועים נשמרים גם על מקור שלא נראה באימון — המודל מכליל.")
            print("  הדיוק המדווח אינו נובע מזיהוי המאגר.")

    print()


if __name__ == "__main__":
    main()
