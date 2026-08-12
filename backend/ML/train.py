"""
LURA BERT Training Pipeline
===================================
Fine-tunes bert-base-multilingual-cased on a combined phishing dataset.

Data sources expected in --data_dir:
    emails.csv          – Kaggle phishing dataset (columns: text, label)
    phishtank.csv       – PhishTank community feed  (columns: text, label)
    enron_legitimate.csv – Enron emails as negatives (columns: text, label)

Labels: 0 = legitimate, 1 = phishing

Usage
-----
    # Install deps: pip install -r requirements.txt
    # Prepare data directory with CSV files (see §4.1 of the report)
    python ML/train.py --data_dir ML/data --output_dir ML/checkpoints --epochs 3

Hardware
--------
    Recommended: Google Colab A100 (~2 h) or NVIDIA RTX 3080 (~6 h).
    CPU-only training is possible but very slow.

Expected output metrics (§6 of the report):
    Val F1  ≥ 0.88
    FNR     < 5 %
    AUC-ROC ≥ 0.92
"""

import argparse
import json
import logging
import os
from typing import List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from transformers import get_linear_schedule_with_warmup

# ---- local imports (run from backend/) -----------------------------------
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ML.bert_model import (
    MODEL_NAME,
    DEVICE,
    MAX_LENGTH,
    PhishingBertClassifier,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
class EmailDataset(Dataset):
    def __init__(
        self,
        texts: List[str],
        labels: List[int],
        tokenizer,
        max_length: int = MAX_LENGTH,
    ):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        enc = self.tokenizer(
            self.texts[idx],
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_dataset(data_dir: str) -> Tuple[List[str], List[int]]:
    """
    Load and merge all CSV data sources.
    Each CSV must have columns 'text' (str) and 'label' (int 0/1).
    """
    texts, labels = [], []
    for fname in ["emails.csv", "phishtank.csv", "enron_legitimate.csv"]:
        fpath = os.path.join(data_dir, fname)
        if not os.path.exists(fpath):
            logger.warning("Data file not found, skipping: %s", fpath)
            continue
        df = pd.read_csv(fpath)
        if not {"text", "label"}.issubset(df.columns):
            logger.warning("Unexpected columns in %s: %s – skipping", fname, list(df.columns))
            continue
        df = df.dropna(subset=["text", "label"])
        texts.extend(df["text"].astype(str).tolist())
        labels.extend(df["label"].astype(int).tolist())
        logger.info("Loaded %d samples from %s", len(df), fname)

    if not texts:
        raise FileNotFoundError(
            f"No usable CSV files found in '{data_dir}'. "
            "Download the datasets first – see §4 of the project report."
        )

    phishing_count = sum(labels)
    logger.info(
        "Total: %d samples | Phishing: %d (%.1f%%) | Legitimate: %d (%.1f%%)",
        len(texts),
        phishing_count,
        100 * phishing_count / len(texts),
        len(texts) - phishing_count,
        100 * (len(texts) - phishing_count) / len(texts),
    )
    return texts, labels


# ---------------------------------------------------------------------------
# Split loading – prefers prepare_data.py output (train/val/test.csv),
# falls back to combining + splitting the raw source CSVs.
# ---------------------------------------------------------------------------
def load_split_dataset(data_dir: str):
    processed = ["train.csv", "val.csv", "test.csv"]
    if all(os.path.exists(os.path.join(data_dir, f)) for f in processed):
        splits = {}
        for fname in processed:
            df = pd.read_csv(os.path.join(data_dir, fname))
            df = df.dropna(subset=["text", "label"])
            splits[fname] = (df["text"].astype(str).tolist(), df["label"].astype(int).tolist())
            logger.info("Loaded %d samples from %s", len(df), fname)

        train_texts, train_labels = splits["train.csv"]
        val_texts, val_labels = splits["val.csv"]
        test_texts, test_labels = splits["test.csv"]
        return train_texts, train_labels, val_texts, val_labels, test_texts, test_labels

    texts, labels = load_dataset(data_dir)
    train_texts, tmp_texts, train_labels, tmp_labels = train_test_split(
        texts, labels, test_size=0.30, stratify=labels, random_state=42
    )
    val_texts, test_texts, val_labels, test_labels = train_test_split(
        tmp_texts, tmp_labels, test_size=0.50, stratify=tmp_labels, random_state=42
    )
    return train_texts, train_labels, val_texts, val_labels, test_texts, test_labels


# ---------------------------------------------------------------------------
# Class-weight helper (handles 71 % / 29 % imbalance)
# ---------------------------------------------------------------------------
def compute_class_weights(labels: List[int]) -> torch.Tensor:
    counts = np.bincount(labels)          # [n_legit, n_phishing]
    weights = 1.0 / counts
    weights = weights / weights.sum() * len(counts)
    return torch.tensor(weights, dtype=torch.float).to(DEVICE)


# ---------------------------------------------------------------------------
# Evaluation helper
# ---------------------------------------------------------------------------
def evaluate(model, loader, criterion) -> Tuple[float, float, float]:
    model.eval()
    all_preds, all_labels, total_loss = [], [], 0.0
    with torch.no_grad():
        for batch in loader:
            ids = batch["input_ids"].to(DEVICE)
            mask = batch["attention_mask"].to(DEVICE)
            lbls = batch["labels"].to(DEVICE)
            out = model(input_ids=ids, attention_mask=mask)
            loss = criterion(out.logits, lbls)
            total_loss += loss.item()
            preds = out.logits.argmax(dim=-1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(lbls.cpu().numpy())

    f1 = f1_score(all_labels, all_preds, pos_label=1, zero_division=0)
    acc = float(np.mean(np.array(all_preds) == np.array(all_labels)))
    return total_loss / len(loader), f1, acc


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train(args: argparse.Namespace):
    # 1. Load train/val/test splits (prefers prepare_data.py output)
    train_texts, train_labels, val_texts, val_labels, test_texts, test_labels = load_split_dataset(args.data_dir)
    logger.info(
        "Split – Train: %d | Val: %d | Test: %d",
        len(train_texts), len(val_texts), len(test_texts),
    )

    # 2. Model & tokeniser
    model = PhishingBertClassifier()
    model = model.to(DEVICE)
    tokenizer = model.tokenizer

    # 3. Datasets & loaders
    # דגימת תת-קבוצה מסט האימון. שומרת על יחס המחלקות כדי שהאימון
    # לא יוטה, ומאפשרת אימון על CPU בזמן סביר.
    if args.limit and args.limit < len(train_texts):
        from sklearn.model_selection import train_test_split as _tts
        train_texts, _, train_labels, _ = _tts(
            train_texts, train_labels,
            train_size=args.limit, stratify=train_labels, random_state=42,
        )
        logger.info("Subsampled training set to %d rows (--limit)", len(train_texts))

    train_ds = EmailDataset(train_texts, train_labels, tokenizer, max_length=args.max_length)
    val_ds = EmailDataset(val_texts, val_labels, tokenizer, max_length=args.max_length)
    test_ds = EmailDataset(test_texts, test_labels, tokenizer, max_length=args.max_length)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    # 4. Loss with class weights
    class_weights = compute_class_weights(train_labels)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    # 5. Optimiser (AdamW with weight decay, exclude bias / LayerNorm)
    no_decay = ["bias", "LayerNorm.weight"]
    param_groups = [
        {
            "params": [
                p for n, p in model.named_parameters()
                if not any(nd in n for nd in no_decay)
            ],
            "weight_decay": 0.01,
        },
        {
            "params": [
                p for n, p in model.named_parameters()
                if any(nd in n for nd in no_decay)
            ],
            "weight_decay": 0.0,
        },
    ]
    optimizer = torch.optim.AdamW(param_groups, lr=args.learning_rate)

    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(0.1 * total_steps),
        num_training_steps=total_steps,
    )

    os.makedirs(args.output_dir, exist_ok=True)
    best_val_f1 = 0.0

    # 6. Training loop
    for epoch in range(1, args.epochs + 1):
        model.train()
        epoch_loss = 0.0
        for step, batch in enumerate(train_loader, 1):
            ids = batch["input_ids"].to(DEVICE)
            mask = batch["attention_mask"].to(DEVICE)
            lbls = batch["labels"].to(DEVICE)

            out = model(input_ids=ids, attention_mask=mask, labels=lbls)
            loss = criterion(out.logits, lbls)

            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()
            epoch_loss += loss.item()

            if step % 100 == 0:
                logger.info(
                    "Epoch %d/%d | Step %d/%d | Loss %.4f",
                    epoch, args.epochs, step, len(train_loader), loss.item(),
                )

        val_loss, val_f1, val_acc = evaluate(model, val_loader, criterion)
        logger.info(
            "Epoch %d ✓ | train_loss=%.4f | val_loss=%.4f | val_F1=%.4f | val_acc=%.4f",
            epoch, epoch_loss / len(train_loader), val_loss, val_f1, val_acc,
        )

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_path = os.path.join(args.output_dir, "best_model.pt")
            torch.save(model.bert.state_dict(), best_path)

            # נשמר לצד ה-checkpoint כדי שההרצה תשתמש בדיוק באותו מודל
            # ובאותו אורך רצף. בעבר האימון רץ ב-256 וההרצה ב-512, ואיש
            # לא ידע. bert_model.py קורא את הקובץ הזה בטעינה.
            meta_path = os.path.join(args.output_dir, "best_model.meta.json")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({
                    "model_name": MODEL_NAME,
                    "max_length": args.max_length,
                    "epochs": args.epochs,
                    "train_rows": len(train_texts),
                    "val_f1": round(val_f1, 4),
                }, f, ensure_ascii=False, indent=2)

            logger.info("New best model saved → %s (F1=%.4f)", best_path, val_f1)

    # 7. Final evaluation on held-out test set
    logger.info("=" * 60)
    logger.info("Final evaluation on test set")
    best_path = os.path.join(args.output_dir, "best_model.pt")
    if os.path.exists(best_path):
        model.bert.load_state_dict(torch.load(best_path, map_location=DEVICE))

    test_loss, test_f1, test_acc = evaluate(model, test_loader, criterion)
    logger.info(
        "Test | loss=%.4f | F1=%.4f | acc=%.4f", test_loss, test_f1, test_acc
    )

    # Full classification report + AUC-ROC
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for batch in test_loader:
            out = model(
                input_ids=batch["input_ids"].to(DEVICE),
                attention_mask=batch["attention_mask"].to(DEVICE),
            )
            all_preds.extend(out.logits.argmax(dim=-1).cpu().numpy())
            all_labels.extend(batch["labels"].numpy())

    print("\n" + classification_report(
        all_labels, all_preds, target_names=["Legitimate", "Phishing"]
    ))
    auc = roc_auc_score(all_labels, all_preds)
    logger.info("AUC-ROC: %.4f", auc)

    # Report whether targets are met
    fn_rate = sum(
        1 for p, l in zip(all_preds, all_labels) if p == 0 and l == 1
    ) / max(sum(all_labels), 1)
    logger.info("FNR: %.2f%%", fn_rate * 100)
    logger.info("Targets met: F1≥0.88=%s  FNR<5%%=%s  AUC≥0.92=%s",
                test_f1 >= 0.88, fn_rate < 0.05, auc >= 0.92)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LURA BERT Training Pipeline"
    )
    parser.add_argument(
        "--data_dir", default="ML/data/processed",
        help=(
            "Directory containing train.csv/val.csv/test.csv (output of "
            "prepare_data.py). Falls back to combining + splitting "
            "emails.csv/phishtank.csv/enron_legitimate.csv if those are "
            "not found."
        ),
    )
    parser.add_argument(
        "--output_dir", default="ML/checkpoints",
        help="Where to write best_model.pt",
    )
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch_size", type=int, default=16)
    parser.add_argument("--learning_rate", type=float, default=2e-5)
    parser.add_argument("--max_length", type=int, default=256)
    parser.add_argument(
        "--limit", type=int, default=0,
        help="דגימת תת-קבוצה מסט האימון (0 = הכל). מקצר אימון על CPU.",
    )

    args = parser.parse_args()
    logger.info("Training on device: %s", DEVICE)
    train(args)