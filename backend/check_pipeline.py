"""
A quick check that the pipeline is alive, against the running server.

A clean inbox where everything scores 0% looks exactly like a broken
system that returns zero for everything. This tells the two apart: it
sends one obvious phishing message and one harmless one, and shows what
came back for each.

    python check_pipeline.py
    python check_pipeline.py --url http://localhost:8000
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The real thresholds, not a copy - they went stale here once already.
from config import PHISHING_THRESHOLD, LOW_RISK_THRESHOLD   # noqa: E402

SAMPLES = [
    dict(
        expect="high",
        note="obvious phishing, English",
        sender="security-rn@paypal-verify.xyz",
        subject="URGENT: verify your account",
        content=(
            "Your account has been suspended. Verify your password immediately "
            "or your account will be permanently closed. "
            "Click here: http://paypal-verify.xyz/login"
        ),
    ),
    dict(
        expect="high",
        note="bank impersonation, Hebrew",
        sender="service@bank-leumi-secure.com",
        subject="חשבונך ייחסם",
        content=(
            "לקוח יקר, זוהתה פעילות חריגה בחשבונך. יש לאמת את פרטי הכניסה "
            "תוך 24 שעות אחרת החשבון ייחסם. http://bank-leumi-secure.com/verify"
        ),
    ),
    dict(
        expect="low",
        note="harmless newsletter",
        sender="newsletter@company.com",
        subject="עדכון חודשי",
        content="שלום, הנה הניוזלטר החודשי שלנו עם עדכונים ומידע על מוצרים.",
    ),
]


def post(url: str, path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def get(url: str, path: str) -> dict:
    with urllib.request.urlopen(url.rstrip("/") + path, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="sanity check for the live pipeline")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--email", default="pipeline-check@example.com",
                    help="a separate address, to keep the real account clean")
    args = ap.parse_args()

    try:
        state = get(args.url, "/health/model")
    except urllib.error.URLError as exc:
        raise SystemExit(f"no answer at {args.url}\n{exc}")

    print(f"\nmodel state: {state.get('state', 'unknown')}")
    if state.get("state") != "ready":
        print("  not loaded yet - the scores below come from the rules alone.")
        print("  that is normal; worth running again once it is ready.")
    print()

    print("=" * 72)
    print(f"  {'expect':<8} {'score':>6}  {'level':<14} note")
    print("=" * 72)

    ok = True
    for s in SAMPLES:
        try:
            r = post(args.url, "/scan", {
                "user_email": args.email,
                "sender": s["sender"],
                "subject": s["subject"],
                "content": s["content"],
            })
        except urllib.error.HTTPError as exc:
            print(f"  {s['expect']:<8} {'error':>6}  HTTP {exc.code}   {s['note']}")
            ok = False
            continue

        score = r.get("risk_score", 0)
        good = (score >= PHISHING_THRESHOLD) if s["expect"] == "high" \
            else (score < LOW_RISK_THRESHOLD)
        ok &= good
        mark = "" if good else "   <- not as expected"
        print(f"  {s['expect']:<8} {score:>6.1f}  {r.get('risk_level', ''):<14} "
              f"{s['note']}{mark}")

    print("=" * 72)
    if ok:
        print("\n  The pipeline works. If everything in your inbox still scores")
        print("  low, that is the inbox, not the system.\n")
    else:
        print("\n  Something is off. Check that the model loaded and that the")
        print("  threshold in config.py is what you expect.\n")


if __name__ == "__main__":
    main()
