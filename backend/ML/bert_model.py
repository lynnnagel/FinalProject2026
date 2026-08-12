"""
LURA BERT Classifier
==========================
Fine-tuned multilingual transformer for binary phishing classification.
Supports Hebrew + English via the multilingual tokeniser.

בחירת מודל הבסיס (BERT_MODEL_NAME):
  bert-base-multilingual-cased        177M · ~710 MB · דיוק בסיס
  distilbert-base-multilingual-cased  135M · ~540 MB · פי ~2 מהיר, 1-2% פחות דיוק

שני המודלים תומכים ב-104 שפות. מעל מחצית מהמשקל בשניהם היא טבלת
האמבדינגס (92M פרמטרים, 119,547 טוקנים) — ולכן DistilBERT חוסך בעיקר
בזמן חישוב ולא בגודל הקובץ.

החלפת מודל מחייבת אימון מחדש — checkpoint של אחד אינו תואם לשני.

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
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# מודל הבסיס. ניתן להחלפה דרך משתנה סביבה, בלי לגעת בקוד:
#
#   bert-base-multilingual-cased        177M פרמטרים · ~710 MB · איטי יותר
#   distilbert-base-multilingual-cased  135M פרמטרים · ~540 MB · פי ~2 מהיר
#
# שני המודלים מכסים 104 שפות כולל עברית. DistilBERT מוותר על מחצית
# משכבות ה-Transformer ולכן מהיר בהרבה, בעלות של אחוז-שניים בדיוק.
# רוב המשקל בשניהם הוא טבלת האמבדינגס (92M פרמטרים) — תוצאה של אוצר
# מילים בן 119,547 טוקנים שנועד ל-104 שפות.
#
# החלפת מודל מחייבת אימון מחדש: checkpoint של אחד לא מתאים לשני.
MODEL_NAME = os.getenv("BERT_MODEL_NAME", "bert-base-multilingual-cased")

# קוונטיזציה דינמית ל-int8: מקטינה זיכרון ומאיצה הרצה על CPU,
# בלי אימון מחדש ובעלות של פחות מאחוז דיוק. אין השפעה על GPU.
QUANTIZE = os.getenv("BERT_QUANTIZE", "false").lower() in ("1", "true", "yes")

MAX_LENGTH = int(os.getenv("BERT_MAX_LENGTH", "256"))  # זהה ל---max_length באימון
NUM_LABELS = 2            # 0 = legitimate, 1 = phishing
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CHECKPOINT = os.path.join(_THIS_DIR, "checkpoints", "best_model.pt")


def _apply_checkpoint_metadata(checkpoint_path: str) -> None:
    """
    מיישר את הגדרות ההרצה לאלה שבהן המודל אומן.

    train.py שומר best_model.meta.json לצד ה-checkpoint עם שם מודל הבסיס
    ואורך הרצף. בלי זה קרה בפרויקט שהאימון רץ ב-256 וההרצה ב-512 —
    אי-התאמה שקטה שאיש לא הבחין בה. משתני הסביבה עדיין גוברים, כדי
    שאפשר יהיה לנסות הגדרה אחרת בכוונה.
    """
    global MODEL_NAME, MAX_LENGTH

    meta_path = os.path.splitext(checkpoint_path)[0] + ".meta.json"
    if not os.path.exists(meta_path):
        return

    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("לא ניתן לקרוא %s: %s", meta_path, exc)
        return

    if "BERT_MODEL_NAME" not in os.environ and meta.get("model_name"):
        if meta["model_name"] != MODEL_NAME:
            logger.info("מודל הבסיס נלקח מה-checkpoint: %s", meta["model_name"])
        MODEL_NAME = meta["model_name"]

    if "BERT_MAX_LENGTH" not in os.environ and meta.get("max_length"):
        if meta["max_length"] != MAX_LENGTH:
            logger.info("אורך הרצף נלקח מה-checkpoint: %s", meta["max_length"])
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
    ):
        super().__init__()
        # ברירת מחדל נפתרת כאן ולא בחתימה: ערך בחתימה מוקפא בזמן הגדרת
        # המחלקה, ואז עדכון MODEL_NAME מהמטא-דאטה של ה-checkpoint לא היה
        # משפיע עליו.
        model_name = model_name or MODEL_NAME

        # Auto* ולא Bert* — כדי ש-DistilBERT ומודלים אחרים יעבדו גם הם
        self.bert = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            num_labels=num_labels,
        )
        # Multilingual-MiniLM מצהיר על BertTokenizer ב-config שלו, אך אומן
        # למעשה עם אוצר המילים של XLM-R. AutoTokenizer מכבד את ההצהרה
        # ומחזיר טוקנייזר שגוי, מה שמייצר טוקנים חסרי משמעות ואימון שלא
        # מתכנס. כרטיס המודל ב-Hugging Face מנחה במפורש להשתמש
        # ב-XLMRobertaTokenizer. הבחירה נעשית כאן ולא מושארת למשתמש.
        if "minilm" in model_name.lower() and "multilingual" in model_name.lower():
            from transformers import XLMRobertaTokenizer
            self.tokenizer = XLMRobertaTokenizer.from_pretrained(
                "xlm-roberta-base"
            )
            logger.info("MiniLM רב-לשוני: נטען XLMRobertaTokenizer כנדרש")
        else:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)

        self.model_name = model_name

        # DistilBERT ו-XLM-R אינם מקבלים token_type_ids
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
        model = PhishingBertClassifier()
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
                logger.info("BERT: קוונטיזציה מדולגת — לא נדרשת על GPU")
            else:
                model = torch.quantization.quantize_dynamic(
                    model, {nn.Linear, nn.Embedding}, dtype=torch.qint8
                )
                model.eval()
                logger.info("BERT: קוונטיזציה ל-int8 הופעלה (זיכרון נמוך, הרצה מהירה)")

        return model
    except RuntimeError as exc:
        # אי-התאמה בין ה-checkpoint למודל הבסיס היא הטעות הנפוצה כאן
        if "size mismatch" in str(exc) or "Missing key" in str(exc) or "Unexpected key" in str(exc):
            logger.error(
                "ה-checkpoint לא תואם למודל '%s'.\n"
                "אם החלפת BERT_MODEL_NAME — צריך לאמן מחדש:\n"
                "    python ML/train.py --epochs 6\n"
                "פירוט: %s",
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
# הטעינה קוראת checkpoint של ~678 MB ולוקחת עשרות שניות. כשהיא רצה
# בזמן ה-import, uvicorn חוסם עד שהיא מסתיימת והאתר לא עולה.
# לכן היא מורצת בשרשור רקע: השרת עונה מיד, וסריקות שמגיעות לפני
# שהמודל מוכן פשוט רצות במצב חוקים בלבד.
# ---------------------------------------------------------------------------
_model: Optional[PhishingBertClassifier] = None
_load_thread: Optional[threading.Thread] = None
_load_lock = threading.Lock()
_load_failed = False


def get_model() -> Optional[PhishingBertClassifier]:
    """
    מחזיר את המודל אם הטעינה הסתיימה, אחרת None.

    None אינו שגיאה — הוא הסימן לעבור ל-fallback של מנוע החוקים.
    """
    return _model


def is_ready() -> bool:
    return _model is not None


def load_state() -> str:
    """מצב הטעינה, לצורך /health ולוגים."""
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
    מתחיל את טעינת המודל בשרשור רקע וחוזר מיד.
    בטוח לקריאה חוזרת — טעינה שנייה לא תתחיל.
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
    """טעינה סינכרונית — לשימוש בסקריפטים (אימון, כיול) ולא בשרת."""
    global _model
    if _model is None:
        _load_into_cache(checkpoint_path)
    return _model


# תאימות לאחור: קוד ישן שכתב `from ML.bert_model import bert_model`
# יקבל None עד שהטעינה תסתיים. עדיף להשתמש ב-get_model().
bert_model: Optional[PhishingBertClassifier] = None
