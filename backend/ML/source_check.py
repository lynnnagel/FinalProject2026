"""
Source separability check.

The question: is the model learning to spot phishing, or learning which
corpus a text came from?

The corpora come from very different places - Enron is business mail
from 2001, PhishTank is current phishing, SpamAssassin is from the
2000s. If each leans to one class, a model can score very well without
learning anything about phishing: recognising the corpus is enough.

This is a known problem in the literature and the usual explanation for
unusually high accuracy.

Three checks, all on TF-IDF and logistic regression - seconds, not hours:

  1. Label distribution per source. If a source is one class, predicting
     the source is the same as predicting the label.
  2. How easily the source can be guessed from the text. High accuracy
     means the corpora differ in style, not only content.
  3. Train without one source and test on it. The decisive one: if
     accuracy collapses, the model leans on corpus traits.
    python ML/source_check.py
    python ML/source_check.py --limit 20000    # faster
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
        sys.exit(f"{path} not found\nrun first:  python ML/prepare_data.py")

    df = pd.read_csv(path).dropna(subset=["text", "label"])
    if "source" not in df.columns:
        sys.exit(
            "no 'source' column in the data.\n"
            "re-run:  python ML/prepare_data.py\n"
            "(the current version tags every row with its source)"
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
    ap = argparse.ArgumentParser(description="source separability check")
    ap.add_argument("--data_dir", default="ML/data")
    ap.add_argument("--limit", type=int, default=40_000,
                    help="sample to shorten the run (0 = all)")
    args = ap.parse_args()

    df = load(args.data_dir, args.limit)
    print(f"\n{len(df):,} rows | {df['source'].nunique()} sources\n")

    # -- 1. label distribution per source -----------------------------
    print("=" * 68)
    print("  1. Label distribution per source")
    print("=" * 68)
    print(f"  {'source':<18} {'rows':>8} {'phishing':>9} {'legit':>9}   note")
    print("  " + "-" * 64)

    confounded = []
    for src, g in df.groupby("source"):
        pct = g["label"].mean() * 100
        note = ""
        if pct >= 97 or pct <= 3:
            note = "!  one class only"
            confounded.append(src)
        print(f"  {src:<18} {len(g):>8,} {pct:>8.1f}% {100-pct:>8.1f}%   {note}")

    if confounded:
        print(f"\n  {len(confounded)} source(s) are almost entirely one class.")
        print("  For those, predicting the source predicts the label.")

    # -- 2. how easily the source can be guessed ----------------------
    print("\n" + "=" * 68)
    print("  2. How much the text gives away its corpus")
    print("=" * 68)

    vec = TfidfVectorizer(max_features=30_000, ngram_range=(1, 2), min_df=2)
    X = vec.fit_transform(df["text"].astype(str))
    src_acc = cross_val_score(
        LogisticRegression(max_iter=1000),
        X, df["source"], cv=3, scoring="accuracy",
    ).mean()

    print(f"  accuracy predicting the source: {src_acc*100:.1f}%")
    if src_acc > 0.95:
        print("  !  the corpora are clearly distinguishable - style, vocabulary")
        print("     or format. With finding 1, high accuracy is reachable")
        print("     without learning any phishing.")
    else:
        print("  the corpora are fairly mixed - lower risk of source separation.")

    # -- 3. train without one source, test on it ----------------------
    print("\n" + "=" * 68)
    print("  3. The decisive check: train without a source, test on it")
    print("=" * 68)
    print("  If accuracy collapses, the model leans on corpus traits.\n")
    print(f"  {'held-out source':<20} {'n':>7} {'acc':>8} {'F1':>8}   note")
    print("  " + "-" * 64)

    results = []
    for src in sorted(df["source"].unique()):
        held = df[df["source"] == src]
        rest = df[df["source"] != src]

        if len(held) < 50 or rest["label"].nunique() < 2:
            print(f"  {src:<20} {len(held):>7,} {'-':>8} {'-':>8}   sample too small")
            continue

        pred = fit_predict(rest["text"].astype(str), rest["label"], held["text"].astype(str))
        acc = accuracy_score(held["label"], pred)

        # Single-class source: F1 is meaningless, but the accuracy is
        # informative - it asks whether an unseen corpus is still
        # classified correctly. These are the riskiest, so keep them.
        single = held["label"].nunique() < 2
        f1 = float("nan") if single else f1_score(held["label"], pred, zero_division=0)
        f1_txt = "-" if single else f"{f1:.3f}"

        note = "!  sharp drop" if acc < 0.75 else ""
        if single and not note:
            note = "one class"

        results.append((src, acc, f1))
        print(f"  {src:<20} {len(held):>7,} {acc*100:>7.1f}% {f1_txt:>8}   {note}")

    # -- conclusion ---------------------------------------------------
    print("\n" + "=" * 68)
    print("  Conclusion")
    print("=" * 68)

    if not results:
        print("  no source carried both classes - nothing can be concluded.")
    else:
        mean_acc = float(np.mean([a for _, a, _ in results]))
        print(f"  mean accuracy on an unseen source: {mean_acc*100:.1f}%")
        if mean_acc < 0.75:
            print("\n  Performance collapses on a new source. A large part of the")
            print("  reported accuracy comes from recognising the corpus, not")
            print("  the phishing. Report this alongside the headline number.")
        elif mean_acc < 0.88:
            print("\n  A moderate drop. The model generalises partly, but corpus")
            print("  traits contribute. Worth noting as a limitation.")
        else:
            print("\n  Performance holds on an unseen source - the model generalises.")
            print("  The reported accuracy is not corpus recognition.")

    print()


if __name__ == "__main__":
    main()
