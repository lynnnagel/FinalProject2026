"""
Download and process the SpamAssassin public corpus.
~8,000 real emails: diverse ham (newsletters, commercial, notifications) + spam.

Usage (from backend/):
    python ML/download_spamassassin.py --output_dir ML/data
"""
import argparse
import email
import email.policy
import io
import logging
import os
import tarfile
import urllib.request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BASE_URL = "https://spamassassin.apache.org/old/publiccorpus"

ARCHIVES = [
    ("20021010_easy_ham.tar.bz2",   0),
    ("20021010_easy_ham_2.tar.bz2", 0),
    ("20030228_easy_ham.tar.bz2",   0),
    ("20030228_easy_ham_2.tar.bz2", 0),
    ("20021010_spam.tar.bz2",       1),
    ("20030228_spam.tar.bz2",       1),
    ("20030228_spam_2.tar.bz2",     1),
]


def parse_email_bytes(raw: bytes) -> str:
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        subject = str(msg.get("Subject") or "")
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors="replace")
                            break
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")
            except Exception:
                body = str(msg.get_payload() or "")
        return f"{subject} {body}".strip()
    except Exception:
        return ""


def process_archive(archive_name: str, label: int) -> list[dict]:
    url = f"{BASE_URL}/{archive_name}"
    logger.info("Downloading %s ...", url)
    rows = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        logger.info("  Downloaded %.1f MB, parsing...", len(data) / 1_048_576)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = os.path.basename(member.name)
                if name.startswith("cmds") or name.startswith("."):
                    continue
                f = tar.extractfile(member)
                if f:
                    text = parse_email_bytes(f.read())
                    if len(text) > 30:
                        rows.append({"text": text, "label": label})
        logger.info("  -> %d emails extracted", len(rows))
    except Exception as exc:
        logger.error("  FAILED: %s", exc)
    return rows


if __name__ == "__main__":
    import pandas as pd

    parser = argparse.ArgumentParser(description="Download SpamAssassin corpus")
    parser.add_argument("--output_dir", default="ML/data")
    args = parser.parse_args()

    all_rows: list[dict] = []
    for archive, label in ARCHIVES:
        all_rows.extend(process_archive(archive, label))

    if not all_rows:
        logger.error("No data downloaded. Check internet connection.")
        raise SystemExit(1)

    df = pd.DataFrame(all_rows)
    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, "spamassassin.csv")
    df.to_csv(out_path, index=False)

    ham  = int((df["label"] == 0).sum())
    spam = int((df["label"] == 1).sum())
    logger.info("Saved %d rows  (ham=%d | spam=%d)  ->  %s", len(df), ham, spam, out_path)
    logger.info("Next: python ML/prepare_data.py")