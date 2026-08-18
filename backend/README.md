<div align="center">

# LURA

### Don't Take the Bait

**Real-time phishing detection for Gmail — Chrome Extension + FastAPI backend**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?logo=pytorch&logoColor=white)
![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-4285F4?logo=googlechrome&logoColor=white)

</div>

---

## Overview

LURA scans every incoming Gmail message in real time and displays a risk score
(0–100) with a human-readable explanation of *why* the message was flagged.

Detection runs through a hybrid engine that combines fast, transparent rules
with a multilingual language model — so the system catches both known patterns
and novel attacks, in Hebrew and English.

## Features

- **Real-time scanning** — every inbox message scored in under 2 seconds
- **Colour-coded badges** — green (safe), orange (suspicious), red (danger) inline in Gmail
- **Explainable results** — each score lists the specific indicators that triggered it
- **Bilingual** — Hebrew and English detection
- **Guardian Mode** — email alerts to a supervisor when a monitored user receives phishing
- **Graceful degradation** — falls back to rules-only mode if the ML model is unavailable
- **Cached verdicts** — a message already scored is not re-run through the model, and
  stored results carry the scoring version so a change to the formula refreshes them

## How Detection Works

Two layers run in parallel and their scores are combined:

```
score = max( bert × damping + 0.5 × rules ,  rules )
```

See [Combining the two engines](#combining-the-two-engines) for why this is a
maximum rather than an average.

### Layer 1 — Heuristic engine (`detector.py`)

Nine weighted checks, capped at 100 points total:

| Check | Max points |
|---|---:|
| Brand impersonation — known company, sender on another domain | 45 |
| &nbsp;&nbsp;↳ brand named only in the body, with a link away from it | 30 |
| Suspicious keywords (50+ bilingual terms) | 40 |
| &nbsp;&nbsp;↳ weaker terms that also occur in legitimate mail | 16 |
| Impersonating an organisation via free email provider | 30 |
| Lookalike / spoofed sender patterns | 25 |
| Raw IP address in URL | 25 |
| Non-standard sending domain | 20 |
| Excessive number of links | 20 |
| Urgency language | 15 |
| URL shorteners | 15 |

Brand impersonation is the strongest single signal and the one the extension
relies on most in a real inbox: it is the only check that cannot be satisfied
by rewording, because it compares what the mail claims to be against the
domain it was actually sent from.

### Layer 2 — Multilingual BERT (`ML/bert_model.py`)

`bert-base-multilingual-cased`, fine-tuned for binary phishing classification.
It detects psychological manipulation from meaning and context rather than
keyword matching — catching messages that contain no individually suspicious words.

### Combining the two engines

Each engine produces an independent 0–100 score. They are combined as

```
score = max( bert × damping + 0.5 × rules ,  rules )
```

so either engine can reach 100 on its own — rules that identify a clear
impersonation do not need the model's agreement, and the reverse holds too.
Agreement between them raises confidence rather than averaging it away.

`damping` (0.25) applies only when the mail was genuinely sent from a known
company's own domain. That is positive evidence of legitimacy, not merely the
absence of suspicion, and it targets a measured weakness of the model: the
training corpora contain almost no legitimate account or security mail, so
BERT scores a subscription renewal notice and a user-requested password reset
at 99.99 — the same as real phishing.

A second damping covers a different failure. The training corpora label spam
and phishing as one class, so the model does not separate them: it scores a
retail advertisement at 99.99, the same as a request for card details. LURA
detects phishing, not spam — an irritating advertisement is not a threat, and
flagging it as danger costs the user's trust in every other alert. Mail is
damped when it carries positive evidence of the marketing category — an
unsubscribe link, an `(AD)` marker, offer vocabulary — and no request for
credentials, so a prize scam dressed as a promotion still scores full.

An earlier version averaged the two scores. It was replaced after measurement;
see [Results](#results).

### Risk thresholds

The classification threshold is the only calibrated value. The remaining bands
are derived from it, so they cannot drift apart when it is retuned.

| Score | Classification |
|---|---|
| ≥ 76 | High risk |
| ≥ 57 | Phishing |
| ≥ 34 | Caution |
| < 34 | Safe |

## Results

Measured on a held-out test set of 16,137 emails, deduplicated before the
train/test split.

| Metric | Result | Target |
|---|---:|---:|
| Overall accuracy | 99.4% | 85% |
| F1-score (phishing) | 0.994 | 0.88 |
| False negative rate | 0.9% | < 5% |
| False positive rate | 0.4% | — |

By language:

| | Samples | Accuracy | F1 | Precision |
|---|---:|---:|---:|---:|
| Hebrew | 638 | 99.2% | 0.990 | 100% |
| English | 15,499 | 99.4% | 0.994 | 99.6% |

31 false alarms across 8,007 legitimate emails, and none at all in Hebrew.

### What the numbers cost to get

The first ensemble scored **52.8% accuracy with F1 0.121** on the same test
set, while BERT alone scored 99.4%. The weighted average was the cause. It
capped the model's contribution at `BERT_WEIGHT × 100 = 40`, below the
threshold of 57, so BERT could never cross on its own however certain it was.
It also treated a rule score of 0 as evidence of legitimacy, when zero only
means the rules have nothing to say — which is also what happens when there is
no sender for three of the nine checks to read. Replacing the average with the
formula above recovered the full 99.4%.

Two limitations are worth stating. 96% of the corpus rows carry no `From`
line, so three rule checks cannot run on them; the extension always has a
sender from Gmail, making the deployed pipeline stronger than this figure
suggests. And leave-one-source-out validation drops to 67.2% accuracy, which
means part of any high score on public corpora reflects recognising the
dataset rather than recognising phishing. The rule engine is corpus-
independent and is what carries the system on mail it has never seen.

Trained on ~119,000 emails from multiple sources, including a Hebrew corpus
built specifically for this project.

## Installation

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure environment variables

`backend/.env` is excluded from the repository because it holds secrets.
Create it from the template:

```bash
cd backend
cp env.example .env      # Windows: copy env.example .env
```

Then set:

| Variable | Description |
|---|---|
| `SMTP_USER` | Gmail address used to send alerts |
| `SMTP_PASSWORD` | Gmail **App Password** — not your regular password |

Generate an App Password at https://myaccount.google.com/apppasswords

### 3. Run the server

```bash
cd backend
uvicorn server:app --reload --port 8000
```

API docs are then available at http://localhost:8000/docs

### 4. Load the extension

Open `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
select the `extension/` directory.

## BERT Model Checkpoint

The trained checkpoint (`backend/ML/checkpoints/best_model.pt`, ~678 MB) is
**not included** in this repository — it exceeds GitHub's 100 MB file size limit.

To regenerate it:

```bash
cd backend
python ML/train.py --data_dir ML/data --output_dir ML/checkpoints
```

Without the checkpoint the system still runs: `load_model()` returns `None` and
the engine automatically falls back to heuristics-only mode.

## Guardian Mode

The monitored user installs the extension and enters a supervisor's email
address in the settings. From that point on, whenever LURA detects phishing in
the monitored inbox, an alert email is sent automatically to the supervisor —
who does not need to install anything.

## Project Structure

```
backend/
├── API/                 Endpoints: auth, scan, stats, guardian, metrics
├── ML/                  BERT model, training, data preparation
│   └── data/            Training datasets (CSV)
├── detector.py          Heuristic engine — 9 weighted checks
├── scoring.py           Combines the two engines into one score
├── risk_levels.py       Score to risk band and user-facing wording
├── url_detector.py      URL analysis
├── email_service.py     Guardian alert emails (SMTP)
├── config.py            Environment configuration
├── database.py          SQLAlchemy setup
├── models.py            ORM models
└── server.py            FastAPI application

extension/               Chrome Extension (content script + popup)
frontend/                Dashboard and authentication pages
presentation/            Project presentation
```

## Testing

```bash
cd backend
pytest
```

## Tech Stack

**Backend** — FastAPI, SQLAlchemy, SQLite, PyTorch, Transformers
**Frontend** — Vanilla JavaScript, HTML, CSS
**Extension** — Chrome Manifest V3