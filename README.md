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

## How Detection Works

Two layers run in parallel and their scores are combined:

```
final_score = 0.7 × heuristic_score + 0.3 × bert_score
```

### Layer 1 — Heuristic engine (`detector.py`)

Eight weighted checks, capped at 100 points total:

| Check | Max points |
|---|---:|
| Suspicious keywords (50+ bilingual terms) | 40 |
| Impersonating an organisation via free email provider | 30 |
| Lookalike / spoofed sender patterns | 25 |
| Raw IP address in URL | 25 |
| Non-standard sending domain | 20 |
| Excessive number of links | 20 |
| Urgency language | 15 |
| URL shorteners | 15 |

### Layer 2 — Multilingual BERT (`ML/bert_model.py`)

`bert-base-multilingual-cased`, fine-tuned for binary phishing classification.
It detects psychological manipulation from meaning and context rather than
keyword matching — catching messages that contain no individually suspicious words.

### Risk thresholds

| Score | Classification |
|---|---|
| ≥ 80 | High risk |
| ≥ 70 | Phishing |
| ≥ 50 | Suspicious |
| ≥ 30 | Caution |
| < 30 | Safe |

## Results

| Metric | Result | Target |
|---|---:|---:|
| Overall accuracy | 95.1% | 85% |
| F1-Score (phishing) | 0.94 | 0.88 |
| False negative rate | 3.2% | < 5% |
| AUC-ROC | 0.96 | — |

Trained on ~130,000 emails from multiple sources, including a Hebrew corpus
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
├── detector.py          Heuristic engine — 8 weighted checks
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