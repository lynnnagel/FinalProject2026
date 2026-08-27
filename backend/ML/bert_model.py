"""
LURA BERT Classifier
==========================
Fine-tuned multilingual transformer for binary phishing classification.
Supports Hebrew + English via the multilingual tokeniser.

Base model (BERT_MODEL_NAME):
  bert-base-multilingual-cased        177M, ~710 MB
  distilbert-base-multilingual-cased  135M, ~540 MB, ~2x faster, 1-2% less accurate

Both cover 104 languages. Over half the weight in each is the embedding
table (92M parameters, 119,547 tokens), so DistilBERT mostly saves
compute rather than file size.

Switching models means retraining - the checkpoints are not compatible.

Usage
-----
Inference (after checkpoint is available):
    from ML.bert_model import bert_model
    prob = bert_model.predict("sender subject body")

Training:
    python ML/train.py --data_dir ML/data --output_dir ML/checkpoints

Checkpoint path: ML/checkpoints/best_model.pt
"""

import json
import os
import logging
import threading
from typing import Optional

import torch
import torch.nn as nn
from transformers import (
    AutoConfig,
    AutoTokenizer,
    AutoModelForSequenceClassification,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# The base model, swappable through an environment variable. Changing
# it means retraining: the checkpoints are not compatible.
MODEL_NAME = os.getenv("BERT_MODEL_NAME", "bert-base-multilingual-cased")

# Dynamic int8 quantisation: less memory and faster on CPU, no
# retraining, under a percent of accuracy. No effect on GPU.
QUANTIZE = os.getenv("BERT_QUANTIZE", "false").lower() in ("1", "true", "yes")

MAX_LENGTH = int(os.getenv("BERT_MAX_LENGTH", "256"))  # same as --max_length in training
NUM_LABELS = 2            # 0 = legitimate, 1 = phishing
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CHECKPOINT = os.path.join(_THIS_DIR, "checkpoints", "best_model.pt")


def _apply_checkpoint_metadata(checkpoint_path: str) -> None:
    """
    Line the runtime settings up with the ones the model was trained
    on.

    train.py writes best_model.meta.json next to the checkpoint with the
    base model name and sequence length. Without it, training ran at 256
    and inference at 512 - a silent mismatch nobody noticed. Environment
    variables still win, so a different setting can be tried on purpose.
    """
    global MODEL_NAME, MAX_LENGTH

    meta_path = os.path.splitext(checkpoint_path)[0] + ".meta.json"
    if not os.path.exists(meta_path):
        return

    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("could not read %s: %s", meta_path, exc)
        return

    trained_on = meta.get("model_name")
    if trained_on and "BERT_MODEL_NAME" in os.environ and trained_on != MODEL_NAME:
        # The variable wins on purpose, but when it contradicts the
        # checkpoint the load fails with an unreadable list of missing
        # keys. Better to say so first.
        logger.error(
            "conflict: BERT_MODEL_NAME is '%s' but the checkpoint was trained "
            "on '%s'.\nThe load will fail. Remove BERT_MODEL_NAME from "
            "backend/.env to use the model it was trained with, or retrain.",
            MODEL_NAME, trained_on,
        )

    if "BERT_MODEL_NAME" not in os.environ and trained_on:
        if trained_on != MODEL_NAME:
            logger.info("base model taken from the checkpoint: %s", trained_on)
        MODEL_NAME = trained_on

    if "BERT_MAX_LENGTH" not in os.environ and meta.get("max_length"):
        if meta["max_length"] != MAX_LENGTH:
            logger.info("sequence length taken from the checkpoint: %s", meta["max_length"])
        MAX_LENGTH = int(meta["max_length"])


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
        model_name: Optional[str] = None,
        num_labels: int = NUM_LABELS,
        dropout: float = 0.1,
        pretrained: bool = True,
    ):
        super().__init__()
        # Resolved here rather than in the signature: a default there
        # is frozen at class-definition time, so a MODEL_NAME updated
        # from the checkpoint metadata would not reach it.
        model_name = model_name or MODEL_NAME

        # Auto* rather than Bert*, so DistilBERT and others also work
        if pretrained:
            # Training: start from the pre-trained weights.
            self.bert = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=num_labels,
            )
        else:
            # Inference: a checkpoint is about to overwrite every weight.
            # from_pretrained would read ~700MB off disk (and fetch it
            # the first time) only to discard it. from_config builds the
            # architecture alone - much faster, and offline.
            config = AutoConfig.from_pretrained(model_name, num_labels=num_labels)
            self.bert = AutoModelForSequenceClassification.from_config(config)
        # Multilingual-MiniLM declares BertTokenizer in its config but
        # was trained with XLM-R's vocabulary. AutoTokenizer honours the
        # declaration and returns the wrong tokeniser, which produces
        # meaningless tokens and training that never converges.
        if "minilm" in model_name.lower() and "multilingual" in model_name.lower():
            from transformers import XLMRobertaTokenizer
            self.tokenizer = XLMRobertaTokenizer.from_pretrained(
                "xlm-roberta-base"
            )
            logger.info("multilingual MiniLM: loaded XLMRobertaTokenizer as required")
        else:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)

        self.model_name = model_name

        # DistilBERT and XLM-R do not take token_type_ids
        lowered = model_name.lower()
        self.accepts_token_type_ids = not any(
            k in lowered for k in ("distil", "minilm", "xlm-roberta")
        )

    # ------------------------------------------------------------------ #
    def forward(self, input_ids, attention_mask, token_type_ids=None, labels=None):
        kwargs = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }
        if self.accepts_token_type_ids and token_type_ids is not None:
            kwargs["token_type_ids"] = token_type_ids
        return self.bert(**kwargs)

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
                token_type_ids=(
                    encoding["token_type_ids"].to(DEVICE)
                    if "token_type_ids" in encoding else None
                ),
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

    # ------------------------------------------------------------------ #
    def predict_batch(self, texts: list[str], batch_size: int = 32) -> list[float]:
        """
        Same result as predict() for each text, but in batches.

        One forward per message is right for a live scan. Over a whole
        evaluation split it wastes fixed overhead on every call; a batch
        of 32 does the same work in one matrix multiply.

        padding="longest" rather than "max_length": if the whole batch
        is short there is no point padding to 256. The result is
        identical, since attention_mask hides the padding either way.
        """
        self.eval()
        out: list[float] = []
        for start in range(0, len(texts), batch_size):
            chunk = texts[start:start + batch_size]
            encoding = self.tokenizer(
                chunk,
                max_length=MAX_LENGTH,
                padding="longest",
                truncation=True,
                return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self(
                    input_ids=encoding["input_ids"].to(DEVICE),
                    attention_mask=encoding["attention_mask"].to(DEVICE),
                    token_type_ids=(
                        encoding["token_type_ids"].to(DEVICE)
                        if "token_type_ids" in encoding else None
                    ),
                )
            probs = torch.softmax(outputs.logits, dim=-1)
            out.extend(float(p) for p in probs[:, 1])
        return out

    def predict_scores(self, rows: list[tuple[str, str, str]],
                       batch_size: int = 32) -> list[float]:
        """predict_score over a list of (sender, subject, content), batched."""
        texts = [f"{s} {sub} {c}" for s, sub, c in rows]
        return [round(p * 100, 2) for p in self.predict_batch(texts, batch_size)]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
def load_model(
    checkpoint_path: str = DEFAULT_CHECKPOINT,
) -> Optional["PhishingBertClassifier"]:
    """
    Load the fine-tuned model from *checkpoint_path*.

    Returns None if the checkpoint does not exist so the application can
    gracefully fall back to the heuristics' engine.
    """
    if not os.path.exists(checkpoint_path):
        logger.warning(
            "BERT checkpoint not found at %s. "
            "Heuristics engine will be used until training is complete.",
            checkpoint_path,
        )
        return None

    _apply_checkpoint_metadata(checkpoint_path)

    try:
        # pretrained=False: the state_dict loaded next holds every
        # weight, so reading the base weights first is wasted work.
        model = PhishingBertClassifier(pretrained=False)
        state_dict = torch.load(checkpoint_path, map_location=DEVICE, weights_only=True)
        model.bert.load_state_dict(state_dict)
        model = model.to(DEVICE)
        model.eval()

        params = sum(p.numel() for p in model.parameters())
        logger.info(
            "BERT loaded: %s | %.0fM parameters | device=%s | max_length=%d",
            MODEL_NAME, params / 1e6, DEVICE, MAX_LENGTH,
        )

        if QUANTIZE:
            if DEVICE.type == "cuda":
                logger.info("BERT: quantisation skipped - not needed on GPU")
            else:
                model = torch.quantization.quantize_dynamic(
                    model, {nn.Linear, nn.Embedding}, dtype=torch.qint8
                )
                model.eval()
                logger.info("BERT: int8 quantisation on (less memory, faster)")

        return model
    except RuntimeError as exc:
        # A checkpoint/base-model mismatch is the common mistake here
        if "size mismatch" in str(exc) or "Missing key" in str(exc) or "Unexpected key" in str(exc):
            logger.error(
                "the checkpoint does not match the model '%s'.\n"
                "If BERT_MODEL_NAME changed, it needs retraining:\n"
                "    python ML/train.py --epochs 6\n"
                "details: %s",
                MODEL_NAME, exc,
            )
        else:
            logger.error("Failed to load BERT checkpoint: %s", exc)
        return None
    except Exception as exc:
        logger.error("Failed to load BERT checkpoint: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Lazy loading
#
# Loading reads a ~700MB checkpoint and takes tens of seconds. Run at
# import time it blocks uvicorn and the site never comes up, so it runs
# on a background thread: the server answers immediately, and scans that
# arrive before the model is ready run on the rules alone.
# ---------------------------------------------------------------------------
_model: Optional[PhishingBertClassifier] = None
_load_thread: Optional[threading.Thread] = None
_load_lock = threading.Lock()
_load_failed = False


def get_model() -> Optional[PhishingBertClassifier]:
    """
    The model once loading has finished, otherwise None.

    None is not an error - it is the signal to fall back to the rules.
    """
    return _model


def is_ready() -> bool:
    return _model is not None


def load_state() -> str:
    """Loading state, for /health and the logs."""
    if _model is not None:
        return "ready"
    if _load_failed:
        return "failed"
    if _load_thread is not None and _load_thread.is_alive():
        return "loading"
    return "not_started"


def _load_into_cache(checkpoint_path: str) -> None:
    global _model, _load_failed
    model = load_model(checkpoint_path)
    if model is None:
        _load_failed = True
    else:
        _model = model


def start_background_load(checkpoint_path: str = DEFAULT_CHECKPOINT) -> None:
    """
    Start loading on a background thread and return immediately.
    Safe to call again - a second load will not start.
    """
    global _load_thread
    with _load_lock:
        if _model is not None or (_load_thread is not None and _load_thread.is_alive()):
            return
        logger.info("BERT: starting background load from %s", checkpoint_path)
        _load_thread = threading.Thread(
            target=_load_into_cache,
            args=(checkpoint_path,),
            name="bert-loader",
            daemon=True,
        )
        _load_thread.start()


def load_now(checkpoint_path: str = DEFAULT_CHECKPOINT) -> Optional[PhishingBertClassifier]:
    """Blocking load - for scripts, not for the server."""
    global _model
    if _model is None:
        _load_into_cache(checkpoint_path)
    return _model


# Backwards compatibility: older code importing `bert_model` gets None
# until loading finishes. Prefer get_model().
bert_model: Optional[PhishingBertClassifier] = None
