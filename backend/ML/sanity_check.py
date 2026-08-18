"""
בדיקת שפיות לסף ההחלטה
========================

סט הוולידציה בנוי מקורפוסים ומגנרטור עברי — דוגמאות "קלות", מופרדות
היטב. סף שמושלם עליהן יכול להיות נמוך מדי לתיבת דואר אמיתית, שבה
מיילים לגיטימיים נראים הרבה יותר דומים לפישינג (חשבונית, התראת חיוב,
איפוס סיסמה יזום).

הסקריפט הזה מריץ את הפייפליין המלא — חוקים + BERT — על מיילים
שנכתבו ביד, כולל אלה שהמודל טעה בהם בעבר, וסורק טווח ספים.
סף "בטוח" הוא כזה שמסווג נכון את כולם.

הרצה (מתוך backend/):
    python ML/sanity_check.py
    python ML/sanity_check.py --no-bert          # חוקים בלבד (מהיר)
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
# המיילים. label: 1 = פישינג, 0 = לגיטימי.
# ה-note מסביר למה כל אחד נמצא כאן — כמה מהם הם כשלים אמיתיים
# שהתגלו בתיבה של המשתמשת, ולכן הם המבחן החשוב באמת.
# ---------------------------------------------------------------------------
EMAILS = [
    # ── לגיטימיים ────────────────────────────────────────────────────
    dict(
        label=0, note="ניוזלטר רגיל",
        sender="newsletter@company.com",
        subject="Monthly update",
        content="Hi, here is our monthly newsletter with product updates and news.",
    ),
    dict(
        label=0, note="חשבונית אמיתית — BERT טעה בה בעקביות",
        sender="info@netflix.com",
        subject="Your invoice",
        content=(
            "Hello, your monthly Netflix invoice is attached. "
            "Your subscription will renew on the 15th. "
            "You can view your billing history in your account settings."
        ),
    ),
    dict(
        label=0, note="חיוב חודשי מכאל — false positive שהתגלה בתיבה",
        sender="noreply@cal-online.co.il",
        subject="כאל — חיוב חודשי",
        content=(
            "שלום, החיוב החודשי שלך בכרטיס האשראי בוצע בהצלחה. "
            "לפירוט העסקאות ניתן להיכנס לאזור האישי באתר."
        ),
    ),
    dict(
        label=0, note="Temu — false positive שהתגלה בתיבה",
        sender="transaction@temu.com",
        subject="Your order has shipped",
        content=(
            "Your order has been shipped and is on its way. "
            "Track your package in the Temu app."
        ),
    ),
    dict(
        label=0, note="Malwarebytes — false positive שהתגלה בתיבה",
        sender="noreply@malwarebytes.com",
        subject="Your subscription renews soon",
        content=(
            "Your Malwarebytes Premium subscription renews on August 30. "
            "No action is needed. Manage your subscription in your account."
        ),
    ),
    dict(
        label=0, note="איפוס סיסמה שהמשתמש יזם — הקשה ביותר",
        sender="no-reply@accounts.google.com",
        subject="Password reset requested",
        content=(
            "We received a request to reset the password for your account. "
            "Click the link below to choose a new password. "
            "https://accounts.google.com/reset "
            "If you did not request this, you can ignore this email."
        ),
    ),

    # ── פישינג ───────────────────────────────────────────────────────
    dict(
        label=1, note="פישינג קלאסי באנגלית",
        sender="security-rn@paypal-verify.xyz",
        subject="URGENT: verify your account",
        content=(
            "Your account has been suspended. Verify your password immediately "
            "or your account will be permanently closed. Click here: "
            "http://paypal-verify.xyz/login"
        ),
    ),
    dict(
        label=1, note="פישינג בעברית — התחזות לבנק",
        sender="service@bank-leumi-secure.com",
        subject="חשבונך ייחסם",
        content=(
            "לקוח יקר, זוהתה פעילות חריגה בחשבונך. "
            "יש לאמת את פרטי הכניסה תוך 24 שעות אחרת החשבון ייחסם. "
            "לאימות מיידי: http://bank-leumi-secure.com/verify"
        ),
    ),
    dict(
        label=1, note="התחזות לכאל מדומיין זר — המקרה שהחוקים נבנו בשבילו",
        sender="cal-service@secure-billing.info",
        subject="כאל: חיוב חריג בכרטיס",
        content=(
            "זוהה חיוב חריג בכרטיס האשראי שלך. "
            "לביטול החיוב יש להזין את פרטי הכרטיס בקישור המצורף. "
            "http://secure-billing.info/cal"
        ),
    ),
    dict(
        label=1, note="התחזות למיקרוסופט",
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
    ap = argparse.ArgumentParser(description="בדיקת שפיות לסף ההחלטה")
    ap.add_argument("--no-bert", action="store_true", help="חוקים בלבד")
    args = ap.parse_args()

    print("\nמחשב ציוני חוקים ...")
    rows = []
    for e in EMAILS:
        h = detector.analyze_email(e["sender"], e["subject"], e["content"])["risk_score"]
        rows.append({**e, "h": h, "b": 0.0})

    if not args.no_bert:
        print("טוען את המודל (חד-פעמי, ~700MB — עשוי לקחת דקה) ...", flush=True)
        from ML.bert_model import load_now
        model = load_now()
        if model is None:
            sys.exit("לא נמצא checkpoint. הריצי עם --no-bert או הורידי את המודל.")
        print("מחשב ציוני BERT ...\n")
        for r in rows:
            r["b"] = model.predict_score(r["sender"], r["subject"], r["content"])


    for r in rows:
        r["trusted"] = bool(r["sender"]) and detector.is_trusted_sender(r["sender"])
        r["final"] = combine(r["b"], r["h"], r["sender"],
                             r["subject"], r["content"])

    # ── טבלה ─────────────────────────────────────────────────────────
    print("═" * 78)
    print("  ציונים")
    print("═" * 78)
    print(f"  {'אמת':<8} {'חוקים':>7} {'BERT':>8} {'סופי':>7}  {'שולח':<6} הערה")
    print("  " + "─" * 74)
    for r in rows:
        truth = "פישינג" if r["label"] else "לגיטימי"
        trust = "מוכר" if r["trusted"] else ""
        print(f"  {truth:<8} {r['h']:>7.1f} {r['b']:>8.2f} {r['final']:>7.1f}  "
              f"{trust:<6} {r['note']}")

    # ── סף ההחלטה ────────────────────────────────────────────────────
    legit = [r for r in rows if r["label"] == 0]
    phish = [r for r in rows if r["label"] == 1]
    worst_legit = max(legit, key=lambda r: r["final"])
    worst_phish = min(phish, key=lambda r: r["final"])
    legit_max, phish_min = worst_legit["final"], worst_phish["final"]

    print("\n" + "═" * 78)
    print("  סף ההחלטה")
    print("═" * 78)
    print(f"  הלגיטימי הגבוה ביותר:  {legit_max:>6.1f}   {worst_legit['note']}")
    print(f"  הפישינג הנמוך ביותר:   {phish_min:>6.1f}   {worst_phish['note']}")

    if legit_max >= phish_min:
        print("\n  ⚠  חפיפה — אין סף שמסווג נכון את כל הדוגמאות.")
        print("     סף לבדו לא יפתור; יש לחזק מנוע או לאמן מחדש.\n")
        return

    lo, hi = int(legit_max) + 1, int(phish_min)
    mid = (lo + hi) // 2
    print(f"\n  טווח בטוח: {lo}–{hi}   שוליים: {phish_min - legit_max:.1f} נקודות")

    inside = lo <= PHISHING_THRESHOLD <= hi
    print(f"  הסף ב-config.py: {PHISHING_THRESHOLD}   "
          f"{'✓ בתוך הטווח' if inside else '✗ מחוץ לטווח'}")

    if not inside:
        print(f"\n  ל-config.py:")
        print(f"      PHISHING_THRESHOLD = {mid}")
        print("      # שאר רמות הסיכון נגזרות מהערך הזה אוטומטית")
        print("\n  בחרנו את אמצע הטווח ולא את הקצה: קצה תחתון מתריע על")
        print("  מייל תמים בשינוי קטן, קצה עליון מפספס פישינג.")
    print()


if __name__ == "__main__":
    main()
