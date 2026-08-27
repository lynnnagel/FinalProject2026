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
    Clean the text before training.

    Links used to be replaced with the word "URL", which erased one of
    the strongest signals there is: paypal-verify.tk and netflix.com
    became the same string. The link is kept now, cut to 80 characters
    so long paths do not eat the token budget.
    """
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"(https?://\S{1,80})\S*", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:1000]


# ---------------------------------------------------------------------------
# Spam is not phishing.
#
# The public corpora label them together, so the model was never asked
# to tell them apart - and it showed: an advertisement scored 99.99,
# the same as a request for card details. LURA detects phishing, and
# marking an advertisement as danger costs trust in every other alert.
#
# SPAM_LABEL decides what happens to those rows:
#   0     - spam is not phishing. The default, and what the product does.
#   1     - the old behaviour, for comparison.
#   None  - drop them entirely.
#
# Note for measurement: 0 lowers the reported accuracy on a corpus that
# labels spam as phishing. That is expected - it measures a different,
# narrower task.
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
            logger.info("Kaggle: %d spam rows labelled %s",
                        spam_rows, "dropped" if SPAM_LABEL is None else SPAM_LABEL)
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

    # In SpamAssassin 1 means spam, not phishing - it is a ham/spam
    # collection from the 2000s with no phishing in it.
    spam_rows = int((df["label"] == 1).sum())
    if spam_rows:
        if SPAM_LABEL is None:
            df = df[df["label"] == 0]
            logger.info("SpamAssassin: %d spam rows dropped", spam_rows)
        else:
            df.loc[df["label"] == 1, "label"] = SPAM_LABEL
            logger.info("SpamAssassin: %d spam rows labelled %d",
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
    # Oversampling happens after the split, on train only. When it ran
    # here, the copies of each message scattered across train/val/test
    # and nearly every Hebrew test message had been seen in training.
    logger.info("Hebrew: %d samples", len(df))
    return df


HEBREW_CHARS = r"[֐-׿]"


def balance_sources(df: pd.DataFrame, max_single_frac: float) -> pd.DataFrame:
    """
    Cap how much of the corpus comes from single-class sources.

    Enron is 100% legitimate and PhishTank 100% phishing. When they
    dominate, the model can score well by recognising the corpus rather
    than the phishing - leave-one-source-out showed exactly that, with
    accuracy falling from 99.6% to 65.9% on an unseen source.

    This does not solve it; it reduces the reward for the shortcut and
    pushes the model toward sources that carry both classes.
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
        logger.warning("every source is single-class - nothing to balance")
        return df

    # The budget for single-class sources, split evenly between them
    budget_total = int(mixed_rows * max_single_frac / (1 - max_single_frac))
    per_source = max(budget_total // len(single_sources), 100)

    kept = []
    for src, g in df.groupby("source"):
        if is_single.get(src) and len(g) > per_source:
            logger.info("source balance: %s  %d -> %d rows", src, len(g), per_source)
            g = g.sample(per_source, random_state=42)
        kept.append(g)

    out = pd.concat(kept, ignore_index=True)
    out = out.sample(frac=1, random_state=42).reset_index(drop=True)

    single_after = int(out["source"].isin(single_sources).sum())
    logger.info(
        "single-class sources: %.1f%% of the corpus (was %.1f%%)",
        single_after / len(out) * 100,
        int(df["source"].isin(single_sources).sum()) / len(df) * 100,
    )
    return out


def oversample_hebrew(df: pd.DataFrame, factor: int = 5) -> pd.DataFrame:
    """
    Repeat the Hebrew examples *factor* times, on train only.

    Hebrew is small next to English, and without this the model barely
    sees the language. It is safe here because it happens after the
    split - every copy stays in train.
    """
    if factor <= 1:
        return df

    is_hebrew = df["text"].str.contains(HEBREW_CHARS, na=False, regex=True)
    hebrew = df[is_hebrew]
    if hebrew.empty:
        logger.warning("no Hebrew examples in the training split")
        return df

    extra = pd.concat([hebrew] * (factor - 1), ignore_index=True)
    out = pd.concat([df, extra], ignore_index=True)
    out = out.sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info(
        "Hebrew oversample x%d on train only: %d -> %d rows (%d Hebrew originals)",
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

    # Extra Hebrew sources, both optional:
    #   hebrew_generated.csv  - ML/generate_hebrew.py (combinatorial)
    #   hebrew_translated.csv - ML/augment_hebrew.py (machine translation)
    for fname, source in (("hebrew_generated.csv", "generated"),
                          ("hebrew_translated.csv", "translated")):
        path = os.path.join(args.data_dir, fname)
        if not os.path.exists(path):
            continue
        df = pd.read_csv(path).dropna(subset=["text", "label"])
        df["label"] = df["label"].astype(int).clip(0, 1)
        # sender and subject are kept when present. Three of the rules
        # read the sender, and without it the ensemble cannot be
        # calibrated - it would measure a crippled engine.
        df["source"] = f"hebrew_{source}"
        keep = [c for c in ("sender", "subject", "text", "label", "source")
                if c in df.columns]
        frames.append(df[keep])
        logger.info("Hebrew (%s): %d samples (legitimate=%d, phishing=%d)%s",
                    source, len(df), int((df["label"] == 0).sum()), int(df["label"].sum()),
                    "  [with sender and subject]" if "sender" in df.columns else "")

    # -- legitimate operational mail --------------------------------
    # The category missing from the corpora entirely: order
    # confirmations, renewals, receipts, sign-in alerts, requested
    # password resets. The model scored them 99.99 simply because it had
    # never seen one - they look like phishing in every shallow way.
    #     ML/generate_legitimate.py --n 2000
    legit_path = os.path.join(args.data_dir, "legitimate_generated.csv")
    if os.path.exists(legit_path):
        df = pd.read_csv(legit_path).dropna(subset=["text", "label"])
        df["label"] = df["label"].astype(int).clip(0, 1)
        df["source"] = "legitimate_generated"
        keep = [c for c in ("sender", "subject", "text", "label", "source")
                if c in df.columns]
        frames.append(df[keep])
        logger.info("legitimate operational mail: %d examples", len(df))
    else:
        logger.warning(
            "No legitimate operational mail. The model will score order "
            "confirmations and password resets high. To generate some:  "
            "python ML/generate_legitimate.py --n 2000"
        )

    if not any(os.path.exists(os.path.join(args.data_dir, f))
               for f in ("hebrew_generated.csv", "hebrew_translated.csv")):
        logger.warning(
            "No extended Hebrew source. The corpus will hold only ~300 Hebrew "
            "messages (0.2%%). To extend:  python ML/generate_hebrew.py --n 3000"
        )

    if not frames:
        raise FileNotFoundError(f"No CSV files found in {args.data_dir}")

    combined = pd.concat(frames, ignore_index=True)
    combined["text"] = combined["text"].apply(clean_text)
    combined = combined[combined["text"].str.len() > 10].reset_index(drop=True)

    # Most sources give a body only. These columns are filled so the
    # three sender-reading rules do not fail on a missing column.
    for col in ("sender", "subject"):
        if col not in combined.columns:
            combined[col] = ""
        combined[col] = combined[col].fillna("").astype(str)

    # The source is kept so we can test whether the classes are
    # separable by corpus - the case where the model learns "which
    # dataset is this" instead of "is this phishing". See source_check.py.
    if "source" not in combined.columns:
        combined["source"] = "unknown"
    combined["source"] = combined["source"].fillna("unknown").astype(str)

    with_sender = int((combined["sender"] != "").sum())
    logger.info(
        "rows with a sender and subject: %d of %d (%.1f%%) - only these "
        "allow the rule engine to be evaluated in full",
        with_sender, len(combined), with_sender / len(combined) * 100,
    )

    # -- dedup, which has to happen before the split ------------------
    # A message that appears twice and lands in both train and test
    # means the model is tested on text it memorised.
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

    # -- Hebrew oversampling: after the split, train only -------------
    train = oversample_hebrew(train, factor=args.hebrew_factor)

    os.makedirs(args.output_dir, exist_ok=True)
    train.to_csv(os.path.join(args.output_dir, "train.csv"), index=False)
    val.to_csv(os.path.join(args.output_dir, "val.csv"), index=False)
    test.to_csv(os.path.join(args.output_dir, "test.csv"), index=False)

    # There must be no overlap left
    leak_val = len(set(train["text"]) & set(val["text"]))
    leak_test = len(set(train["text"]) & set(test["text"]))
    if leak_val or leak_test:
        logger.error("LEAK! train/val=%d, train/test=%d", leak_val, leak_test)
    else:
        logger.info("verified: no overlap between train, val and test")

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
        help="how many times to repeat the Hebrew examples in train (1 = none)",
    )
    parser.add_argument(
        "--max-single-class-frac", dest="max_single_class_frac",
        type=float, default=0.15,
        help="maximum share of single-class sources (Enron, PhishTank). "
             "A lower value reduces the reward for learning the corpus "
             "instead of the phishing. 1.0 disables the balancing.",
    )
    prepare(parser.parse_args())