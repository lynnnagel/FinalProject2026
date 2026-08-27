"""
A sanity check for the decision threshold.

The validation split is built from corpora and a Hebrew generator -
easy, well-separated examples. A threshold that is perfect on them can
be far too low for a real inbox, where legitimate mail looks much more
like phishing: an invoice, a billing notice, a password reset the user
asked for.

This runs the full pipeline over hand-written messages, including ones
the model got wrong before, and sweeps a range of thresholds. A safe
threshold is one that classifies all of them correctly.

    python ML/sanity_check.py
    python ML/sanity_check.py --no-bert          # rules only, fast
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detector          # noqa: E402
from scoring import combine            # noqa: E402
from config import PHISHING_THRESHOLD   # noqa: E402

# ---------------------------------------------------------------------------
# label: 1 = phishing, 0 = legitimate. The note says why each one is
# here - several are real failures found in a live inbox, which makes
# them the ones that matter.
# ---------------------------------------------------------------------------
EMAILS = [
    # -- legitimate -------------------------------------------------
    dict(
        label=0, note="ordinary newsletter",
        sender="newsletter@company.com",
        subject="Monthly update",
        content="Hi, here is our monthly newsletter with product updates and news.",
    ),
    dict(
        label=0, note="a real invoice - BERT got this wrong consistently",
        sender="info@netflix.com",
        subject="Your invoice",
        content=(
            "Hello, your monthly Netflix invoice is attached. "
            "Your subscription will renew on the 15th. "
            "You can view your billing history in your account settings."
        ),
    ),
    dict(
        label=0, note="monthly card charge - a false positive found in a real inbox",
        sender="noreply@cal-online.co.il",
        subject="כאל — חיוב חודשי",
        content=(
            "שלום, החיוב החודשי שלך בכרטיס האשראי בוצע בהצלחה. "
            "לפירוט העסקאות ניתן להיכנס לאזור האישי באתר."
        ),
    ),
    dict(
        label=0, note="Temu - a false positive found in a real inbox",
        sender="transaction@temu.com",
        subject="Your order has shipped",
        content=(
            "Your order has been shipped and is on its way. "
            "Track your package in the Temu app."
        ),
    ),
    dict(
        label=0, note="Malwarebytes - a false positive found in a real inbox",
        sender="noreply@malwarebytes.com",
        subject="Your subscription renews soon",
        content=(
            "Your Malwarebytes Premium subscription renews on August 30. "
            "No action is needed. Manage your subscription in your account."
        ),
    ),
    dict(
        label=0, note="a password reset the user asked for - the hardest case",
        sender="no-reply@accounts.google.com",
        subject="Password reset requested",
        content=(
            "We received a request to reset the password for your account. "
            "Click the link below to choose a new password. "
            "https://accounts.google.com/reset "
            "If you did not request this, you can ignore this email."
        ),
    ),

    # -- phishing ---------------------------------------------------
    dict(
        label=1, note="classic English phishing",
        sender="security-rn@paypal-verify.xyz",
        subject="URGENT: verify your account",
        content=(
            "Your account has been suspended. Verify your password immediately "
            "or your account will be permanently closed. Click here: "
            "http://paypal-verify.xyz/login"
        ),
    ),
    dict(
        label=1, note="Hebrew phishing - bank impersonation",
        sender="service@bank-leumi-secure.com",
        subject="חשבונך ייחסם",
        content=(
            "לקוח יקר, זוהתה פעילות חריגה בחשבונך. "
            "יש לאמת את פרטי הכניסה תוך 24 שעות אחרת החשבון ייחסם. "
            "לאימות מיידי: http://bank-leumi-secure.com/verify"
        ),
    ),
    dict(
        label=1, note="card-issuer impersonation from a foreign domain - what the rules are for",
        sender="cal-service@secure-billing.info",
        subject="כאל: חיוב חריג בכרטיס",
        content=(
            "זוהה חיוב חריג בכרטיס האשראי שלך. "
            "לביטול החיוב יש להזין את פרטי הכרטיס בקישור המצורף. "
            "http://secure-billing.info/cal"
        ),
    ),
    dict(
        label=1, note="Microsoft impersonation",
        sender="ms-support@office365-alert.net",
        subject="Action required: your mailbox is full",
        content=(
            "Your Microsoft 365 mailbox is full and will be deactivated. "
            "Confirm your credentials now to restore access. "
            "http://office365-alert.net/signin"
        ),
    ),
]


def main() -> None:
    ap = argparse.ArgumentParser(description="sanity check for the decision threshold")
    ap.add_argument("--no-bert", action="store_true", help="rules only")
    args = ap.parse_args()

    print("\nscoring with the rules ...")
    rows = []
    for e in EMAILS:
        h = detector.analyze_email(e["sender"], e["subject"], e["content"])["risk_score"]
        rows.append({**e, "h": h, "b": 0.0})

    if not args.no_bert:
        print("loading the model (~700MB, may take a minute) ...", flush=True)
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            sys.exit("No checkpoint found. Run with --no-bert, or fetch the model.")
        print("scoring with BERT ...\n")
        for r in rows:
            r["b"] = model.predict_score(r["sender"], r["subject"], r["content"])


    for r in rows:
        r["trusted"] = bool(r["sender"]) and detector.is_trusted_sender(r["sender"])
        r["final"] = combine(r["b"], r["h"], r["sender"],
                             r["subject"], r["content"])

    # -- the table --------------------------------------------------
    print("=" * 78)
    print("  Scores")
    print("=" * 78)
    print(f"  {'truth':<10} {'rules':>7} {'BERT':>8} {'final':>7}  {'known':<6} note")
    print("  " + "-" * 74)
    for r in rows:
        truth = "phishing" if r["label"] else "legitimate"
        trust = "yes" if r["trusted"] else ""
        print(f"  {truth:<8} {r['h']:>7.1f} {r['b']:>8.2f} {r['final']:>7.1f}  "
              f"{trust:<6} {r['note']}")

    # -- the threshold ----------------------------------------------
    legit = [r for r in rows if r["label"] == 0]
    phish = [r for r in rows if r["label"] == 1]
    worst_legit = max(legit, key=lambda r: r["final"])
    worst_phish = min(phish, key=lambda r: r["final"])
    legit_max, phish_min = worst_legit["final"], worst_phish["final"]

    print("\n" + "=" * 78)
    print("  Decision threshold")
    print("=" * 78)
    print(f"  highest legitimate:  {legit_max:>6.1f}   {worst_legit['note']}")
    print(f"  lowest phishing:     {phish_min:>6.1f}   {worst_phish['note']}")

    if legit_max >= phish_min:
        print("\n  !  overlap - no threshold classifies all of them correctly.")
        print("     A threshold alone will not fix this.\n")
        return

    lo, hi = int(legit_max) + 1, int(phish_min)
    mid = (lo + hi) // 2
    print(f"\n  safe range: {lo}-{hi}   margin: {phish_min - legit_max:.1f} points")

    inside = lo <= PHISHING_THRESHOLD <= hi
    print(f"  threshold in config.py: {PHISHING_THRESHOLD}   "
          f"{'inside the range' if inside else 'OUTSIDE the range'}")

    if not inside:
        # With the model off these are rule scores only, and the real
        # system scores phishing far higher - so the suggestion below
        # would be wrong.
        if args.no_bert:
            print("\n  !  This ran with --no-bert, so these are rule scores")
            print("     only. Do not set a threshold from this run.\n")
            return

        print(f"\n  for config.py:")
        print(f"      PHISHING_THRESHOLD = {mid}")
        print("      # the other bands are derived from this automatically")
        print("\n  The middle of the range, not an edge: the low end flags")
        print("  harmless mail on any small change, the high end misses.")
    print()


if __name__ == "__main__":
    main()
