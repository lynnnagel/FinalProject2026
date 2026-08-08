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
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:1000]


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
        df["label"] = df["label"].map(
            {"spam": 1, "phishing": 1, "ham": 0, "legitimate": 0}
        )
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
    # Oversample Hebrew x5 so the model actually learns the language
    df = pd.concat([df] * 5, ignore_index=True)
    logger.info("Hebrew: %d samples after 5x oversample", len(df))
    return df


def prepare(args: argparse.Namespace):
    frames = []

    kaggle_path = os.path.join(args.data_dir, "emails.csv")
    if os.path.exists(kaggle_path):
        df = load_kaggle(kaggle_path)
        frames.append(df)
        logger.info("Kaggle: %d samples (phishing=%d)", len(df), df["label"].sum())

    enron_path = os.path.join(args.data_dir, "enron_legitimate.csv")
    if os.path.exists(enron_path):
        df = load_enron(enron_path)
        frames.append(df)
        logger.info("Enron: %d legitimate samples", len(df))

    phishtank_path = os.path.join(args.data_dir, "phishtank.csv")
    if os.path.exists(phishtank_path):
        df = load_phishtank(phishtank_path)
        frames.append(df)
        logger.info("PhishTank: %d phishing samples", len(df))

    spamassassin_path = os.path.join(args.data_dir, "spamassassin.csv")
    if os.path.exists(spamassassin_path):
        df = load_spamassassin(spamassassin_path)
        frames.append(df)
        logger.info("SpamAssassin: %d samples (ham=%d, spam=%d)",
                    len(df), int((df["label"] == 0).sum()), int((df["label"] == 1).sum()))
    else:
        logger.warning("SpamAssassin not found - run: python ML/download_spamassassin.py")

    hebrew_path = os.path.join(args.data_dir, "hebrew_emails.csv")
    if os.path.exists(hebrew_path):
        df = load_hebrew(hebrew_path)
        frames.append(df)
        logger.info("Hebrew: %d samples (legitimate=%d, phishing=%d)",
                    len(df), int((df["label"] == 0).sum()), int((df["label"] == 1).sum()))
    else:
        logger.warning("Hebrew dataset not found - run: python ML/create_hebrew_dataset.py")

    if not frames:
        raise FileNotFoundError(f"No CSV files found in {args.data_dir}")

    combined = pd.concat(frames, ignore_index=True)
    combined["text"] = combined["text"].apply(clean_text)
    combined = combined[combined["text"].str.len() > 10].reset_index(drop=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    phishing_pct = combined["label"].mean() * 100
    logger.info(
        "Combined: %d total | Phishing: %.1f%% | Legitimate: %.1f%%",
        len(combined), phishing_pct, 100 - phishing_pct,
    )

    train, tmp = train_test_split(combined, test_size=0.30, stratify=combined["label"], random_state=42)
    val, test = train_test_split(tmp, test_size=0.50, stratify=tmp["label"], random_state=42)

    os.makedirs(args.output_dir, exist_ok=True)
    train.to_csv(os.path.join(args.output_dir, "train.csv"), index=False)
    val.to_csv(os.path.join(args.output_dir, "val.csv"), index=False)
    test.to_csv(os.path.join(args.output_dir, "test.csv"), index=False)

    logger.info("Saved: train=%d | val=%d | test=%d", len(train), len(val), len(test))
    logger.info("Output: %s", args.output_dir)
    logger.info("Next step: python ML/train.py --data_dir %s --output_dir ML/checkpoints",
                args.output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", default="ML/data")
    parser.add_argument("--output_dir", default="ML/data/processed")
    prepare(parser.parse_args())