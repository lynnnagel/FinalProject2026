"""
Data preparation pipeline for LURA BERT training.

Usage:
    cd backend
    python ML/prepare_data.py --data_dir ML/data --output_dir ML/data/processed

Input files in --data_dir:
    emails.csv            - Kaggle dataset
    enron_legitimate.csv  - Enron negatives
    phishtank.csv         - PhishTank positives (optional)
    spamassassin.csv      - SpamAssassin corpus (optional, run download_spamassassin.py first)
    hebrew_emails.csv     - Hebrew email examples (optional, run create_hebrew_dataset.py first)

Output:
    ML/data/processed/train.csv
    ML/data/processed/val.csv
    ML/data/processed/test.csv
"""
import argparse
import logging
import os
import re

import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def clean_text(text: str) -> str:
    """
    ניקוי טקסט לפני אימון.

    הערה חשובה: בעבר עמד כאן  re.sub(r"http\\S+", " URL ", text)  שהחליף
    כל קישור במילה "URL". זה מחק את אחד הסיגנלים החזקים ביותר לזיהוי
    פישינג — 'paypal-verify.tk' ו-'netflix.com' הפכו שניהם לאותה מחרוזת,
    והמודל לא יכול היה ללמוד להבדיל ביניהם. נשארו לו בעיקר מילות דחיפות,
    שקיימות גם במיילים שיווקיים לגיטימיים, ולכן הוא סימן כמעט הכל כפישינג.

    כעת הקישור נשמר, אך נחתך ל-80 תווים כדי שנתיבים ארוכים לא יבלעו את
    תקציב הטוקנים על חשבון גוף המייל.
    """
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"(https?://\S{1,80})\S*", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:1000]


# ---------------------------------------------------------------------------
# ספאם אינו פישינג
#
# הקורפוסים הציבוריים מתייגים אותם יחד: SpamAssassin מסמן ספאם ב-1,
# ומיפוי התוויות של Kaggle העביר גם "spam" וגם "phishing" ל-1. המשמעות
# היא שהמודל **מעולם לא נדרש להבחין ביניהם** — ומדידה בתיבה אמיתית
# הראתה בדיוק את זה: פרסומת מסחרית קיבלה 99.99, אותו ציון כמו בקשה
# לפרטי אשראי.
#
# אבל LURA מזהה פישינג ולא ספאם. פרסומת מעצבנת אינה איום, וסימונה
# כסכנה שוחק את אמון המשתמש בכל שאר ההתרעות.
#
# SPAM_LABEL קובע מה לעשות עם השורות האלה:
#   0     – ספאם הוא לא פישינג. ברירת המחדל, ומה שהמוצר באמת עושה.
#   1     – ההתנהגות הישנה, לצורך השוואה.
#   None  – להשמיט לגמרי; המודל לא רואה ספאם כלל.
#
# הערה למדידה: SPAM_LABEL=0 מוריד את הדיוק המדווח על קורפוס שמתייג
# ספאם כפישינג. זה צפוי — המספר החדש מודד משימה אחרת, וצרה יותר.
# ---------------------------------------------------------------------------
SPAM_LABEL: int | None = 0


def load_kaggle(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    logger.info("Kaggle raw columns: %s", list(df.columns))
    text_col = next((c for c in df.columns if "text" in c.lower() or "body" in c.lower()
                     or "email" in c.lower() or "message" in c.lower()), df.columns[0])
    label_col = next((c for c in df.columns if "label" in c.lower()
                      or "spam" in c.lower() or "class" in c.lower()), df.columns[-1])
    df = df[[text_col, label_col]].dropna()
    df.columns = ["text", "label"]
    unique_labels = df["label"].unique()
    if set(unique_labels).issubset({0, 1}):
        pass
    elif set(unique_labels).issubset({"spam", "ham", "phishing", "legitimate"}):
        spam_rows = (df["label"] == "spam").sum()
        df["label"] = df["label"].map(
            {"spam": SPAM_LABEL, "phishing": 1, "ham": 0, "legitimate": 0}
        )
        if spam_rows:
            logger.info("Kaggle: %d שורות ספאם תויגו כ-%s",
                        spam_rows, "הושמטו" if SPAM_LABEL is None else SPAM_LABEL)
        if SPAM_LABEL is None:
            df = df.dropna(subset=["label"])
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    df["label"] = df["label"].clip(0, 1)
    return df


def load_enron(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    logger.info("Enron raw columns: %s", list(df.columns))
    text_col = df.columns[0]
    df = df[[text_col]].dropna()
    df.columns = ["text"]
    df["label"] = 0
    return df.sample(min(len(df), 40_000), random_state=42)


def load_phishtank(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    logger.info("PhishTank raw columns: %s", list(df.columns))
    text_col = next((c for c in df.columns if "url" in c.lower()
                     or "text" in c.lower()), df.columns[0])
    df = df[[text_col]].dropna()
    df.columns = ["text"]
    df["label"] = 1
    return df


def load_spamassassin(path: str) -> pd.DataFrame:
    """SpamAssassin public corpus - diverse real-world ham + spam."""
    df = pd.read_csv(path)
    logger.info("SpamAssassin raw columns: %s", list(df.columns))
    text_col = next((c for c in df.columns if "text" in c.lower()), df.columns[0])
    label_col = next((c for c in df.columns if "label" in c.lower()), df.columns[-1])
    df = df[[text_col, label_col]].dropna()
    df.columns = ["text", "label"]
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int).clip(0, 1)

    # ב-SpamAssassin, 1 פירושו ספאם ולא פישינג. הקורפוס הזה נאסף
    # בשנות ה-2000 כאוסף ham/spam, ואין בו פישינג כלל.
    spam_rows = int((df["label"] == 1).sum())
    if spam_rows:
        if SPAM_LABEL is None:
            df = df[df["label"] == 0]
            logger.info("SpamAssassin: %d שורות ספאם הושמטו", spam_rows)
        else:
            df.loc[df["label"] == 1, "label"] = SPAM_LABEL
            logger.info("SpamAssassin: %d שורות ספאם תויגו כ-%d",
                        spam_rows, SPAM_LABEL)
    return df


def load_hebrew(path: str) -> pd.DataFrame:
    """Hebrew email examples (legitimate commercial + phishing patterns)."""
    df = pd.read_csv(path)
    logger.info("Hebrew raw columns: %s", list(df.columns))
    text_col = next((c for c in df.columns if "text" in c.lower()), df.columns[0])
    label_col = next((c for c in df.columns if "label" in c.lower()), df.columns[-1])
    df = df[[text_col, label_col]].dropna()
    df.columns = ["text", "label"]
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int).clip(0, 1)
    # ההכפלה נעשית אחרי החלוקה, על סט האימון בלבד (ראה oversample_hebrew).
    # כשהיא נעשתה כאן, חמשת העותקים של כל מייל התפזרו בין train/val/test,
    # כך שכמעט כל מייל עברי בסט הבדיקה הופיע גם באימון — והדיוק המדווח
    # היה מנופח.
    logger.info("Hebrew: %d samples", len(df))
    return df


HEBREW_CHARS = r"[֐-׿]"


def balance_sources(df: pd.DataFrame, max_single_frac: float) -> pd.DataFrame:
    """
    מגביל את משקלם של מקורות חד-מחלקתיים.

    Enron הוא 100% לגיטימי ו-PhishTank 100% פישינג. כשהם מהווים חלק
    גדול מהמאגר, המודל יכול לקבל דיוק גבוה בקיצור דרך: ללמוד לזהות את
    סגנון המאגר ולהסיק ממנו את התווית, בלי ללמוד מה מאפיין פישינג.
    בדיקת leave-one-source-out הראתה שזה בדיוק מה שקרה — הדיוק צנח
    מ-99.6% ל-65.9% על מקור שלא נראה באימון.

    ההגבלה כאן אינה פותרת את הבעיה לגמרי; היא מקטינה את התגמול על
    קיצור הדרך ומאלצת את המודל להישען יותר על המקורות שמכילים את שתי
    המחלקות, שם ההבחנה חייבת להיות מהותית.
    """
    if max_single_frac >= 1.0:
        return df

    is_single = {}
    for src, g in df.groupby("source"):
        pct = g["label"].mean()
        is_single[src] = pct >= 0.97 or pct <= 0.03

    single_sources = [s for s, v in is_single.items() if v]
    if not single_sources:
        return df

    mixed_rows = int((~df["source"].isin(single_sources)).sum())
    if mixed_rows == 0:
        logger.warning("כל המקורות חד-מחלקתיים — אין על מה לאזן")
        return df

    # התקציב הכולל למקורות החד-מחלקתיים, מחולק שווה ביניהם
    budget_total = int(mixed_rows * max_single_frac / (1 - max_single_frac))
    per_source = max(budget_total // len(single_sources), 100)

    kept = []
    for src, g in df.groupby("source"):
        if is_single.get(src) and len(g) > per_source:
            logger.info("איזון מקורות: %s  %d → %d שורות", src, len(g), per_source)
            g = g.sample(per_source, random_state=42)
        kept.append(g)

    out = pd.concat(kept, ignore_index=True)
    out = out.sample(frac=1, random_state=42).reset_index(drop=True)

    single_after = int(out["source"].isin(single_sources).sum())
    logger.info(
        "מקורות חד-מחלקתיים: %.1f%% מהמאגר (היה %.1f%%)",
        single_after / len(out) * 100,
        int(df["source"].isin(single_sources).sum()) / len(df) * 100,
    )
    return out


def oversample_hebrew(df: pd.DataFrame, factor: int = 5) -> pd.DataFrame:
    """
    מכפיל את הדוגמאות בעברית פי *factor* — על סט האימון בלבד.

    הדאטה העברי קטן ביחס לאנגלי, ובלי הכפלה המודל כמעט לא לומד את
    השפה. ההכפלה בטוחה כאן כי היא קורית אחרי החלוקה: העותקים נשארים
    כולם ב-train ולא מגיעים לסטי ההערכה.
    """
    if factor <= 1:
        return df

    is_hebrew = df["text"].str.contains(HEBREW_CHARS, na=False, regex=True)
    hebrew = df[is_hebrew]
    if hebrew.empty:
        logger.warning("לא נמצאו דוגמאות בעברית בסט האימון")
        return df

    extra = pd.concat([hebrew] * (factor - 1), ignore_index=True)
    out = pd.concat([df, extra], ignore_index=True)
    out = out.sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info(
        "Hebrew oversample x%d on train only: %d → %d rows (%d Hebrew originals)",
        factor, len(df), len(out), len(hebrew),
    )
    return out


def prepare(args: argparse.Namespace):
    frames = []

    kaggle_path = os.path.join(args.data_dir, "emails.csv")
    if os.path.exists(kaggle_path):
        df = load_kaggle(kaggle_path)
        df["source"] = "kaggle"
        frames.append(df)
        logger.info("Kaggle: %d samples (phishing=%d)", len(df), df["label"].sum())

    enron_path = os.path.join(args.data_dir, "enron_legitimate.csv")
    if os.path.exists(enron_path):
        df = load_enron(enron_path)
        df["source"] = "enron"
        frames.append(df)
        logger.info("Enron: %d legitimate samples", len(df))

    phishtank_path = os.path.join(args.data_dir, "phishtank.csv")
    if os.path.exists(phishtank_path):
        df = load_phishtank(phishtank_path)
        df["source"] = "phishtank"
        frames.append(df)
        logger.info("PhishTank: %d phishing samples", len(df))

    spamassassin_path = os.path.join(args.data_dir, "spamassassin.csv")
    if os.path.exists(spamassassin_path):
        df = load_spamassassin(spamassassin_path)
        df["source"] = "spamassassin"
        frames.append(df)
        logger.info("SpamAssassin: %d samples (ham=%d, spam=%d)",
                    len(df), int((df["label"] == 0).sum()), int((df["label"] == 1).sum()))
    else:
        logger.warning("SpamAssassin not found - run: python ML/download_spamassassin.py")

    hebrew_path = os.path.join(args.data_dir, "hebrew_emails.csv")
    if os.path.exists(hebrew_path):
        df = load_hebrew(hebrew_path)
        df["source"] = "hebrew_manual"
        frames.append(df)
        logger.info("Hebrew: %d samples (legitimate=%d, phishing=%d)",
                    len(df), int((df["label"] == 0).sum()), int((df["label"] == 1).sum()))
    else:
        logger.warning("Hebrew dataset not found - run: python ML/create_hebrew_dataset.py")

    # מקורות עבריים נוספים, שניהם אופציונליים:
    #   hebrew_generated.csv  – ML/generate_hebrew.py (מחולל קומבינטורי)
    #   hebrew_translated.csv – ML/augment_hebrew.py  (תרגום מכונה)
    for fname, source in (("hebrew_generated.csv", "generated"),
                          ("hebrew_translated.csv", "translated")):
        path = os.path.join(args.data_dir, fname)
        if not os.path.exists(path):
            continue
        df = pd.read_csv(path).dropna(subset=["text", "label"])
        df["label"] = df["label"].astype(int).clip(0, 1)
        # sender ו-subject נשמרים כשהם קיימים. שלוש מבדיקות מנוע החוקים
        # קוראות את כתובת השולח, ובלעדיה אי אפשר לכייל את האנסמבל —
        # calibrate.py היה מודד מנוע משותק וממליץ להעביר את כל המשקל ל-BERT.
        df["source"] = f"hebrew_{source}"
        keep = [c for c in ("sender", "subject", "text", "label", "source")
                if c in df.columns]
        frames.append(df[keep])
        logger.info("Hebrew (%s): %d samples (legitimate=%d, phishing=%d)%s",
                    source, len(df), int((df["label"] == 0).sum()), int(df["label"].sum()),
                    "  [עם שולח ונושא]" if "sender" in df.columns else "")

    # ── דואר תפעולי לגיטימי ──────────────────────────────────────────
    # הקטגוריה שחסרה בקורפוסים לגמרי: אישור הזמנה, חידוש מנוי, קבלה,
    # התראת כניסה, איפוס סיסמה יזום. המודל נתן להם 99.99 פשוט מפני
    # שלא ראה אותם מעולם — הם דומים לפישינג בכל מאפיין שטחי, וההבדל
    # היחיד הוא שהם אמיתיים.
    #     ML/generate_legitimate.py --n 2000
    legit_path = os.path.join(args.data_dir, "legitimate_generated.csv")
    if os.path.exists(legit_path):
        df = pd.read_csv(legit_path).dropna(subset=["text", "label"])
        df["label"] = df["label"].astype(int).clip(0, 1)
        df["source"] = "legitimate_generated"
        keep = [c for c in ("sender", "subject", "text", "label", "source")
                if c in df.columns]
        frames.append(df[keep])
        logger.info("דואר תפעולי לגיטימי: %d דוגמאות", len(df))
    else:
        logger.warning(
            "אין דואר תפעולי לגיטימי. המודל ייתן ציון גבוה לאישורי הזמנה "
            "ולאיפוסי סיסמה. ליצירה:  python ML/generate_legitimate.py --n 2000"
        )

    if not any(os.path.exists(os.path.join(args.data_dir, f))
               for f in ("hebrew_generated.csv", "hebrew_translated.csv")):
        logger.warning(
            "אין מקור עברי מורחב. המאגר יכיל ~300 מיילים בעברית בלבד (0.2%%). "
            "להרחבה:  python ML/generate_hebrew.py --n 3000"
        )

    if not frames:
        raise FileNotFoundError(f"No CSV files found in {args.data_dir}")

    combined = pd.concat(frames, ignore_index=True)
    combined["text"] = combined["text"].apply(clean_text)
    combined = combined[combined["text"].str.len() > 10].reset_index(drop=True)

    # רוב המקורות מספקים גוף מייל אחד בלבד. השדות מולאו כדי ששלוש
    # בדיקות מנוע החוקים שקוראות את השולח לא ייפלו על עמודה חסרה.
    for col in ("sender", "subject"):
        if col not in combined.columns:
            combined[col] = ""
        combined[col] = combined[col].fillna("").astype(str)

    # מקור הקורפוס נשמר כדי שאפשר יהיה לבדוק אם המחלקות ניתנות
    # להפרדה לפי מקור — מצב שבו המודל לומד "מאיזה מאגר זה הגיע"
    # במקום "האם זה פישינג". ראה ML/source_check.py.
    if "source" not in combined.columns:
        combined["source"] = "unknown"
    combined["source"] = combined["source"].fillna("unknown").astype(str)

    with_sender = int((combined["sender"] != "").sum())
    logger.info(
        "שורות עם שולח ונושא: %d מתוך %d (%.1f%%) — רק הן מאפשרות "
        "להעריך את מנוע החוקים במלואו",
        with_sender, len(combined), with_sender / len(combined) * 100,
    )

    # ── הסרת כפילויות — חייבת לקרות לפני החלוקה ────────────────────────
    # מייל שמופיע פעמיים ומתפצל בין train ל-test גורם למודל להיבחן על
    # טקסט שהוא כבר שינן, וכל מדד שיתקבל יהיה גבוה מהאמת.
    before = len(combined)
    combined = combined.drop_duplicates(subset="text").reset_index(drop=True)
    removed = before - len(combined)
    if removed:
        logger.info("Removed %d duplicate emails (%.1f%%)", removed, removed / before * 100)

    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    combined = balance_sources(combined, args.max_single_class_frac)

    phishing_pct = combined["label"].mean() * 100
    logger.info(
        "Combined: %d total | Phishing: %.1f%% | Legitimate: %.1f%%",
        len(combined), phishing_pct, 100 - phishing_pct,
    )

    train, tmp = train_test_split(combined, test_size=0.30, stratify=combined["label"], random_state=42)
    val, test = train_test_split(tmp, test_size=0.50, stratify=tmp["label"], random_state=42)

    # ── הכפלת העברית — אחרי החלוקה, ורק על סט האימון ───────────────────
    train = oversample_hebrew(train, factor=args.hebrew_factor)

    os.makedirs(args.output_dir, exist_ok=True)
    train.to_csv(os.path.join(args.output_dir, "train.csv"), index=False)
    val.to_csv(os.path.join(args.output_dir, "val.csv"), index=False)
    test.to_csv(os.path.join(args.output_dir, "test.csv"), index=False)

    # אימות: אחרי התיקון החפיפה חייבת להיות אפס
    leak_val = len(set(train["text"]) & set(val["text"]))
    leak_test = len(set(train["text"]) & set(test["text"]))
    if leak_val or leak_test:
        logger.error("דליפה! train∩val=%d, train∩test=%d", leak_val, leak_test)
    else:
        logger.info("אימות: אין חפיפה בין סטי האימון, הוולידציה והבדיקה ✓")

    logger.info("Saved: train=%d | val=%d | test=%d", len(train), len(val), len(test))
    logger.info("Output: %s", args.output_dir)
    logger.info("Next step: python ML/train.py --data_dir %s --output_dir ML/checkpoints",
                args.output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", default="ML/data")
    parser.add_argument("--output_dir", default="ML/data/processed")
    parser.add_argument(
        "--hebrew_factor", type=int, default=5,
        help="פי כמה להכפיל את הדוגמאות בעברית בסט האימון (1 = ללא הכפלה)",
    )
    parser.add_argument(
        "--max-single-class-frac", dest="max_single_class_frac",
        type=float, default=0.15,
        help="חלקם המרבי של מקורות חד-מחלקתיים (Enron, PhishTank) במאגר. "
             "ערך נמוך מקטין את התגמול על לימוד המאגר במקום לימוד פישינג. "
             "1.0 מבטל את האיזון.",
    )
    prepare(parser.parse_args())