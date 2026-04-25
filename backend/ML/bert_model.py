"""
PhishGuard BERT Classifier
==========================
Fine-tuned bert-base-multilingual-cased for binary phishing classification.
Supports Hebrew + English via mBERT's multilingual tokeniser.

Architecture decision (from report §5.4):
  BERT-Base chosen over BERT-Large (too slow) and DistilBERT (less accurate)
  to meet the < 2 s latency target even without GPU caching.

Usage
-----
Inference (after checkpoint is available):
    from ML.bert_model import bert_model
    prob = bert_model.predict("sender subject body")

Training:
    python ML/train.py --data_dir ML/data --output_dir ML/checkpoints

Checkpoint path: ML/checkpoints/best_model.pt
"""

import os
import logging
from typing import Optional

import torch
import torch.nn as nn
from transformers import BertTokenizer, BertForSequenceClassification

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODEL_NAME = "bert-base-multilingual-cased"
MAX_LENGTH = 512          # mBERT context window
NUM_LABELS = 2            # 0 = legitimate, 1 = phishing
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CHECKPOINT = os.path.join(_THIS_DIR, "checkpoints", "best_model.pt")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class PhishingBertClassifier(nn.Module):
    """
    Thin wrapper around BertForSequenceClassification.

    Fine-tuning target metrics (from report §3.2):
        F1 (phishing) ≥ 0.88
        FNR          < 5 %
        Latency p95  < 2 s
    """

    def __init__(
        self,
        model_name: str = MODEL_NAME,
        num_labels: int = NUM_LABELS,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.bert = BertForSequenceClassification.from_pretrained(
            model_name,
            num_labels=num_labels,
            hidden_dropout_prob=dropout,
            attention_probs_dropout_prob=dropout,
        )
        self.tokenizer = BertTokenizer.from_pretrained(model_name)

    # ------------------------------------------------------------------ #
    def forward(self, input_ids, attention_mask, token_type_ids=None, labels=None):
        return self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            labels=labels,
        )

    # ------------------------------------------------------------------ #
    def predict(self, text: str) -> float:
        """
        Return phishing probability in [0.0, 1.0] for the given text.
        Expects pre-concatenated 'sender subject body' string.
        """
        self.eval()
        encoding = self.tokenizer(
            text,
            max_length=MAX_LENGTH,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        with torch.no_grad():
            outputs = self(
                input_ids=encoding["input_ids"].to(DEVICE),
                attention_mask=encoding["attention_mask"].to(DEVICE),
            )
        probs = torch.softmax(outputs.logits, dim=-1)
        return float(probs[0][1])   # P(phishing)

    def predict_score(self, sender: str, subject: str, content: str) -> float:
        """
        Convenience wrapper that mirrors the heuristics detector interface.
        Returns a risk score in [0, 100].
        """
        text = f"{sender} {subject} {content}"
        return round(self.predict(text) * 100, 2)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
def load_model(
    checkpoint_path: str = DEFAULT_CHECKPOINT,
) -> Optional["PhishingBertClassifier"]:
    """
    Load the fine-tuned model from *checkpoint_path*.

    Returns None if the checkpoint does not exist so the application can
    gracefully fall back to the heuristics engine.
    """
    if not os.path.exists(checkpoint_path):
        logger.warning(
            "BERT checkpoint not found at %s. "
            "Heuristics engine will be used until training is complete.",
            checkpoint_path,
        )
        return None

    try:
        model = PhishingBertClassifier()
        state_dict = torch.load(checkpoint_path, map_location=DEVICE, weights_only=True)
        model.bert.load_state_dict(state_dict)
        model = model.to(DEVICE)
        model.eval()
        logger.info("BERT model loaded from %s (device=%s)", checkpoint_path, DEVICE)
        return model
    except Exception as exc:
        logger.error("Failed to load BERT checkpoint: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Module-level singleton
# None → heuristics-only mode (checkpoint not yet available)
# ---------------------------------------------------------------------------
bert_model: Optional[PhishingBertClassifier] = load_model()
