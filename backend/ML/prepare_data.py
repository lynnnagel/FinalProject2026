"""
Prepare phishing datasets for BERT training.

Usage:
    python ML/prepare_data.py --data_dir ML/data --output_dir ML/data/processed

Expected input files in data_dir:
    emails.csv          – columns: text, label (0=legit, 1=phishing)
    phishtank.csv       – columns: text, label
    enron_legitimate.csv – columns: text, label
"""
import os
import argparse
import pandas as pd
from sklearn.model_selection import train_test_split


def load_and_merge(data_dir: str) -> pd.DataFrame:
    dfs = []
    for filename in ["emails.csv", "phishtank.csv", "enron_legitimate.csv"]:
        path = os.path.join(data_dir, filename)
        if os.path.exists(path):
            df = pd.read_csv(path, usecols=["text", "label"])
            df = df.dropna(subset=["text", "label"])
            df["label"] = df["label"].astype(int)
            dfs.append(df)
            print(f"Loaded {len(df)} rows from {filename}")
        else:
            print(f"Warning: {filename} not found, skipping.")

    if not dfs:
        raise FileNotFoundError("No data files found in " + data_dir)

    merged = pd.concat(dfs, ignore_index=True)
    merged = merged.drop_duplicates(subset=["text"])
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

    total = len(merged)
    phishing = merged["label"].sum()
    print(f"\nTotal samples: {total}")
    print(f"Phishing: {phishing} ({100*phishing/total:.1f}%)")
    print(f"Legitimate: {total - phishing} ({100*(total-phishing)/total:.1f}%)")

    return merged


def save_splits(df: pd.DataFrame, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    train_df, temp_df = train_test_split(df, test_size=0.3, stratify=df["label"], random_state=42)
    val_df, test_df = train_test_split(temp_df, test_size=0.5, stratify=temp_df["label"], random_state=42)

    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    val_df.to_csv(os.path.join(output_dir, "val.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir, "test.csv"), index=False)

    print(f"\nSaved to {output_dir}:")
    print(f"  train.csv  – {len(train_df)} rows")
    print(f"  val.csv    – {len(val_df)} rows")
    print(f"  test.csv   – {len(test_df)} rows")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", required=True)
    parser.add_argument("--output_dir", required=True)
    args = parser.parse_args()

    df = load_and_merge(args.data_dir)
    save_splits(df, args.output_dir)
    print("\nData preparation complete.")
