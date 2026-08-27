"""
שליחת מיילי בדיקה לתיבה שלך, כדי לראות את התוסף עובד.

הבדיקה היחידה שבאמת משכנעת היא לראות את התג נדלק על מייל אמיתי בתיבה
אמיתית. הסקריפט שולח אליך סדרה מדורגת — מפישינג בוטה, דרך מקרים
עדינים, ועד מיילים תמימים שאסור שיסומנו — כדי שתראי גם מה נתפס וגם
מה לא, וגם שהמערכת יודעת להבדיל.

כל ההודעות נשלחות אליך ואליך בלבד, ונושאות כותרת X-LURA-Test כדי שיהיה
אפשר לזהות ולסנן אותן. הן טקסט בלבד: אין בהן קבצים מצורפים, והקישורים
מצביעים על דומיינים שאינם קיימים.

הרצה (מתוך backend/):
    python send_test_emails.py                 # שולח לכתובת שב-SMTP_USER
    python send_test_emails.py --to me@gmail.com
    python send_test_emails.py --list          # מציג בלי לשלוח
"""
from __future__ import annotations

import argparse
import smtplib
import sys
import time
from email.mime.text import MIMEText
from email.utils import formataddr

from config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_ENABLED,
)

# ---------------------------------------------------------------------------
# expect: what the system should return.
#   "high"    - must be caught
#   "medium"  - a borderline case; any result is worth discussing
#   "low"     - must pass quietly
#
# from_name is a display name only. The real sender address will be
# yours, since that is the mailbox this sends from, so the sender-domain
# rules cannot score fully here. That is a limit of testing against your
# own inbox, not of the system - check_pipeline.py posts straight to the
# API with a real sender domain.
# ---------------------------------------------------------------------------
SAMPLES = [
    dict(
        expect="גבוה", from_name="PayPal Security",
        subject="URGENT: verify your account within 24 hours",
        body=(
            "Dear customer,\n\n"
            "Your account has been suspended due to unusual activity. "
            "Verify your password immediately or your account will be "
            "permanently closed.\n\n"
            "Click here: http://paypal-verify-secure.xyz/login\n\n"
            "PayPal Security Team"
        ),
    ),
    dict(
        expect="גבוה", from_name="בנק לאומי - אבטחה",
        subject="חשבונך ייחסם תוך 24 שעות",
        body=(
            "לקוח יקר,\n\n"
            "זוהתה פעילות חריגה בחשבונך בבנק לאומי. "
            "יש לאמת את פרטי הכניסה תוך 24 שעות, אחרת החשבון ייחסם.\n\n"
            "לאימות מיידי: http://bank-leumi-secure.xyz/verify\n\n"
            "מחלקת האבטחה"
        ),
    ),
    dict(
        expect="גבוה", from_name="כאל שירות לקוחות",
        subject="כאל: חיוב חריג בכרטיס האשראי שלך",
        body=(
            "שלום,\n\n"
            "זוהה חיוב חריג בסך 2,340 ש\"ח בכרטיס האשראי שלך.\n"
            "לביטול החיוב יש להזין את פרטי הכרטיס בקישור המצורף "
            "תוך 12 שעות.\n\n"
            "http://cal-secure-billing.info/cancel\n\n"
            "שירות לקוחות כאל"
        ),
    ),
    dict(
        expect="גבוה", from_name="Microsoft 365",
        subject="Action required: your mailbox will be deactivated",
        body=(
            "Your Microsoft 365 mailbox has exceeded its storage quota "
            "and will be deactivated within 48 hours.\n\n"
            "Confirm your credentials now to restore access:\n"
            "http://office365-alert-support.net/signin\n\n"
            "Microsoft 365 Support"
        ),
    ),
    dict(
        expect="גבוה", from_name="דואר ישראל",
        subject="החבילה שלך ממתינה - נדרש תשלום מכס",
        body=(
            "שלום,\n\n"
            "חבילה על שמך ממתינה במחסני דואר ישראל. "
            "לשחרורה נדרש תשלום מכס בסך 12 ש\"ח.\n"
            "החבילה תוחזר לשולח אם התשלום לא יבוצע היום.\n\n"
            "לתשלום: http://israelpost-delivery.info/pay\n"
        ),
    ),
    dict(
        expect="גבוה", from_name="Prize Department",
        subject="Congratulations! You have won an iPhone 17",
        body=(
            "Congratulations!\n\n"
            "You have won an iPhone 17 in our monthly draw. "
            "Claim your prize within 24 hours - limited time offer.\n\n"
            "Claim here: http://bit.ly/claim-prize-now\n"
        ),
    ),
    dict(
        expect="בינוני", from_name="IT Helpdesk",
        subject="Scheduled password rotation",
        body=(
            "Hello,\n\n"
            "As part of our quarterly security policy, all staff are "
            "required to rotate their password before Friday.\n"
            "Please use the internal portal to complete this.\n\n"
            "http://192.168.44.19/portal/reset\n\n"
            "IT Helpdesk"
        ),
    ),
    dict(
        expect="בינוני", from_name="מזכירות המחלקה",
        subject="עדכון פרטים אישיים לקראת סוף השנה",
        body=(
            "שלום רב,\n\n"
            "לקראת סוף שנת הלימודים נדרש עדכון פרטים אישיים במערכת.\n"
            "נא למלא את הטופס עד יום חמישי.\n\n"
            "http://tinyurl.com/student-update\n\n"
            "בברכה, המזכירות"
        ),
    ),
    dict(
        expect="נמוך", from_name="ניוזלטר חודשי",
        subject="עדכוני מוצר - אוגוסט",
        body=(
            "שלום,\n\n"
            "הנה סיכום העדכונים החודשי שלנו: שיפורי ביצועים, "
            "ממשק חדש לניהול משימות, ותיקוני תקלות.\n\n"
            "קריאה נעימה,\n"
            "הצוות\n\n"
            "להסרה מרשימת התפוצה לחצו כאן."
        ),
    ),
    dict(
        expect="נמוך", from_name="אישור הזמנה",
        subject="ההזמנה שלך יצאה למשלוח",
        body=(
            "שלום,\n\n"
            "ההזמנה שלך נארזה ויצאה למשלוח. "
            "צפי הגעה: יומיים עסקים.\n"
            "לפרטים נוספים ניתן להיכנס לאזור האישי באתר.\n\n"
            "תודה שקנית אצלנו."
        ),
    ),
]


def build(sample: dict, to_addr: str, index: int) -> MIMEText:
    msg = MIMEText(sample["body"], "plain", "utf-8")
    msg["Subject"] = sample["subject"]
    msg["From"] = formataddr((sample["from_name"], SMTP_USER))
    msg["To"] = to_addr
    # This header is not scanned (the pipeline reads sender, subject and
    # body only), so it marks the test messages without changing a score.
    msg["X-LURA-Test"] = f"sample-{index}-{sample['expect']}"
    return msg


def main() -> None:
    ap = argparse.ArgumentParser(description="שליחת מיילי בדיקה לתיבה שלך")
    ap.add_argument("--to", default=None, help="כתובת היעד (ברירת מחדל: SMTP_USER)")
    ap.add_argument("--list", action="store_true", help="להציג בלי לשלוח")
    ap.add_argument("--delay", type=float, default=1.5,
                    help="השהיה בין הודעות, בשניות")
    args = ap.parse_args()

    print(f"\n{len(SAMPLES)} הודעות בדיקה:\n")
    print(f"  {'צפוי':<8} {'שם השולח':<26} נושא")
    print("  " + "─" * 74)
    for s in SAMPLES:
        print(f"  {s['expect']:<8} {s['from_name']:<26} {s['subject'][:44]}")

    if args.list:
        print("\nלשליחה בפועל: python send_test_emails.py\n")
        return

    if not EMAIL_ENABLED:
        sys.exit("\nEMAIL_ENABLED=false ב-.env. יש להדליק כדי לשלוח.\n")
    if not SMTP_USER or not SMTP_PASSWORD:
        sys.exit("\nחסרים SMTP_USER או SMTP_PASSWORD ב-.env.\n")

    to_addr = args.to or SMTP_USER
    print(f"\nשולח אל {to_addr} ...\n")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        for i, sample in enumerate(SAMPLES, 1):
            smtp.send_message(build(sample, to_addr, i))
            print(f"  {i:>2}/{len(SAMPLES)}  {sample['subject'][:56]}")
            time.sleep(args.delay)

    print("\nנשלחו. פתחי את Gmail, המתיני שהתוסף יסרוק, והשווי לעמודת 'צפוי'.")
    print("להסרה אחר כך, חפשי בתיבה:  X-LURA-Test\n")


if __name__ == "__main__":
    main()
