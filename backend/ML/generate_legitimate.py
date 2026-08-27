"""
מחולל דואר תפעולי לגיטימי — הקטגוריה שחסרה בקורפוסים
======================================================

הבעיה שהוא בא לפתור: המודל נותן 99.99 להודעת חידוש מנוי מ-Malwarebytes
ולאיפוס סיסמה שהמשתמש עצמו ביקש מגוגל. שני מיילים תקינים לחלוטין.

הסיבה אינה חולשה של הארכיטקטורה אלא חור בנתונים. הקורפוסים מכילים
דואר עסקי משנת 2001 (Enron), ספאם משנות ה-2000 (SpamAssassin) ופישינג
עכשווי (PhishTank) — ואין בהם כמעט דבר מהקטגוריה שממלאת תיבת דואר
מודרנית: אישור הזמנה, הודעת משלוח, חידוש מנוי, קבלה, התראת כניסה,
ואיפוס סיסמה שהמשתמש יזם.

המודל לא "טועה" בהם. הוא מעולם לא ראה אותם, והם דומים לפישינג בכל
מאפיין שטחי: הם מדברים על חשבון, מכילים קישורים, ולעיתים גם על סיסמה.
ההבדל היחיד הוא שהם אמיתיים.

הקובץ מייצר את הקטגוריה הזאת קומבינטורית, באותה גישה שבה נבנה
generate_hebrew.py — עברית ואנגלית, עם שולח, נושא וגוף מלא, מתויגים 0.

הרצה (מתוך backend/):
    python ML/generate_legitimate.py --n 2000
    python ML/generate_legitimate.py --n 500 --preview 3

הפלט: ML/data/legitimate_generated.csv
prepare_data.py קורא אותו אוטומטית אם הוא קיים.
"""
from __future__ import annotations

import argparse
import csv
import os
import random

# ---------------------------------------------------------------------------
# Companies and the domains they really send from. These are exactly
# the addresses the rule engine recognises as a known sender, so these
# examples teach the model the combination it never saw: a legitimate
# sender with operational content.
# ---------------------------------------------------------------------------
BRANDS_EN = [
    ("Netflix", "netflix.com"), ("Spotify", "spotify.com"),
    ("Amazon", "amazon.com"), ("eBay", "ebay.com"),
    ("iHerb", "iherb.com"), ("ASOS", "asos.com"),
    ("Booking.com", "booking.com"), ("Airbnb", "airbnb.com"),
    ("Malwarebytes", "malwarebytes.com"), ("Norton", "norton.com"),
    ("Adobe", "adobe.com"), ("GitHub", "github.com"),
    ("Dropbox", "dropbox.com"), ("Zoom", "zoom.us"),
    ("Temu", "temu.com"), ("AliExpress", "aliexpress.com"),
]

BRANDS_HE = [
    ("כאל", "cal-online.co.il"), ("ישראכרט", "isracard.co.il"),
    ("בנק לאומי", "leumi.co.il"), ("בנק הפועלים", "bankhapoalim.co.il"),
    ("KSP", "ksp.co.il"), ("שופרסל", "shufersal.co.il"),
    ("רמי לוי", "rami-levy.co.il"), ("איקאה", "ikea.co.il"),
    ("סלקום", "cellcom.co.il"), ("פרטנר", "partner.co.il"),
    ("בזק", "bezeq.co.il"), ("דואר ישראל", "israelpost.co.il"),
    ("אל על", "elal.co.il"), ("תן ביס", "10bis.co.il"),
]

MAILBOXES = ["noreply", "no-reply", "orders", "service", "info",
             "support", "billing", "notifications", "account"]

SUBDOMAINS = ["", "", "", "mail.", "e.", "email.", "news."]

# ---------------------------------------------------------------------------
# Templates. {brand} {order} {amount} {date} {link} are substituted.
#
# Some deliberately carry the words the model trips on - password,
# account, verify - because that is exactly where it errs. An
# operational example without them teaches it nothing.
# ---------------------------------------------------------------------------
TEMPLATES_EN = [
    ("Your {brand} order #{order} has shipped",
     "Hi,\n\nYour order #{order} is on its way and should arrive within "
     "3-5 business days.\n\nTrack your package: {link}\n\nThanks for "
     "shopping with {brand}."),
    ("Your {brand} receipt",
     "Thank you for your purchase.\n\nOrder #{order}\nTotal: {amount}\n"
     "Date: {date}\n\nYou can view this receipt in your account: {link}"),
    ("Your {brand} subscription renews on {date}",
     "Hello,\n\nYour {brand} subscription will renew automatically on "
     "{date} for {amount}. No action is needed.\n\nTo manage your "
     "subscription or change your plan, visit your account: {link}"),
    ("Password changed successfully",
     "Hi,\n\nThe password for your {brand} account was changed on {date}.\n\n"
     "If you made this change, no further action is needed. If you did "
     "not, please contact our support team.\n\n{link}"),
    ("New sign-in to your {brand} account",
     "Hello,\n\nWe noticed a new sign-in to your {brand} account on {date}.\n\n"
     "If this was you, you can ignore this message. You can review your "
     "recent activity here: {link}"),
    ("Your {brand} invoice for {date}",
     "Hello,\n\nYour invoice for {date} is ready. Amount due: {amount}.\n\n"
     "View invoice: {link}\n\nThis amount will be charged to your saved "
     "payment method."),
    ("Your {brand} order #{order} has been delivered",
     "Your package was delivered on {date}.\n\nIf anything is missing or "
     "damaged, you can start a return from your orders page: {link}"),
    ("Welcome to {brand}",
     "Thanks for creating an account.\n\nYou can update your details and "
     "preferences any time from your account settings: {link}\n\n"
     "We're glad to have you."),
    ("Your {brand} plan is now active",
     "Your plan is active as of {date}.\n\nNext billing date: {date}\n"
     "Amount: {amount}\n\nManage your plan: {link}"),
    ("Your monthly {brand} statement is ready",
     "Hello,\n\nYour statement for {date} is now available.\n\n"
     "Total this period: {amount}\n\nView statement: {link}"),
]

TEMPLATES_HE = [
    ("ההזמנה שלך מ{brand} נשלחה",
     "שלום,\n\nההזמנה שלך מספר {order} יצאה למשלוח ותגיע תוך 3 ימי עסקים.\n\n"
     "למעקב אחר המשלוח: {link}\n\nתודה שקנית ב{brand}."),
    ("{brand} — חיוב חודשי",
     "שלום,\n\nהחיוב החודשי בכרטיס האשראי שלך בוצע בהצלחה.\n\n"
     "סכום: {amount}\nתאריך: {date}\n\n"
     "לפירוט העסקאות ניתן להיכנס לאזור האישי: {link}"),
    ("אישור הזמנה מספר {order}",
     "תודה על הזמנתך.\n\nמספר הזמנה: {order}\nסכום: {amount}\n"
     "תאריך: {date}\n\nלצפייה בפרטי ההזמנה: {link}"),
    ("הסיסמה שלך ב{brand} שונתה",
     "שלום,\n\nהסיסמה לחשבונך ב{brand} שונתה בתאריך {date}.\n\n"
     "אם ביצעת את השינוי, אין צורך בפעולה נוספת. אם לא — צור קשר עם "
     "שירות הלקוחות.\n\n{link}"),
    ("כניסה חדשה לחשבון שלך ב{brand}",
     "שלום,\n\nזוהתה כניסה חדשה לחשבונך בתאריך {date}.\n\n"
     "אם זה היית את או אתה, אפשר להתעלם מההודעה. לצפייה בפעילות "
     "האחרונה בחשבון: {link}"),
    ("החשבונית שלך מ{brand} מוכנה",
     "שלום,\n\nהחשבונית לתקופה {date} מוכנה. סכום לתשלום: {amount}.\n\n"
     "לצפייה בחשבונית: {link}\n\nהסכום יחויב באמצעי התשלום השמור."),
    ("החבילה שלך הגיעה",
     "המשלוח שלך נמסר בתאריך {date}.\n\n"
     "אם חסר משהו או שמשהו הגיע פגום, אפשר לפתוח פנייה מהאזור האישי: {link}"),
    ("ברוכה הבאה ל{brand}",
     "תודה שנרשמת.\n\nאפשר לעדכן את הפרטים וההעדפות בכל רגע דרך "
     "האזור האישי: {link}\n\nנשמח לראותך."),
    ("המנוי שלך ב{brand} מתחדש בתאריך {date}",
     "שלום,\n\nהמנוי שלך יתחדש אוטומטית בתאריך {date} בסכום {amount}. "
     "אין צורך בפעולה כלשהי.\n\nלניהול המנוי: {link}"),
    ("סיכום חודשי — {brand}",
     "שלום,\n\nריכוז הפעילות שלך לחודש {date} מוכן.\n\n"
     "סך הכול: {amount}\n\nלצפייה: {link}"),
]

PATHS = ["account", "orders", "my", "billing", "statements", "profile",
         "orders/track", "account/settings", "invoices"]

MONTHS_HE = ["ינואר", "פברואר", "מרץ", "אפריל", "מאי", "יוני",
             "יולי", "אוגוסט", "ספטמבר", "אוקטובר", "נובמבר", "דצמבר"]
MONTHS_EN = ["January", "February", "March", "April", "May", "June",
             "July", "August", "September", "October", "November", "December"]


def make_row(rng: random.Random, hebrew: bool) -> dict:
    brand, domain = rng.choice(BRANDS_HE if hebrew else BRANDS_EN)
    subject_t, body_t = rng.choice(TEMPLATES_HE if hebrew else TEMPLATES_EN)

    sender = f"{rng.choice(MAILBOXES)}@{rng.choice(SUBDOMAINS)}{domain}"
    link = f"https://www.{domain}/{rng.choice(PATHS)}"
    order = str(rng.randint(1000000, 9999999))
    amount = (f"{rng.randint(20, 900)} ש\"ח" if hebrew
              else f"${rng.randint(5, 250)}.{rng.randint(0, 99):02d}")
    date = (f"{rng.randint(1, 28)} ב{rng.choice(MONTHS_HE)}" if hebrew
            else f"{rng.choice(MONTHS_EN)} {rng.randint(1, 28)}")

    fields = dict(brand=brand, order=order, amount=amount, date=date, link=link)
    subject = subject_t.format(**fields)
    content = body_t.format(**fields)

    return {
        "sender": sender,
        "subject": subject,
        "content": content,
        "text": f"{sender} {subject} {content}",
        "label": 0,
        "lang": "he" if hebrew else "en",
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="generator for legitimate operational mail")
    ap.add_argument("--n", type=int, default=2000, help="how many examples")
    ap.add_argument("--hebrew-share", type=float, default=0.4,
                    help="Hebrew share of the total")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--preview", type=int, default=0,
                    help="print a few examples and exit")
    ap.add_argument("--out", default="ML/data/legitimate_generated.csv")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    if args.preview:
        for i in range(args.preview):
            row = make_row(rng, hebrew=i % 2 == 0)
            print(f"\n{'-' * 66}")
            print(f"from:     {row['sender']}")
            print(f"subject:  {row['subject']}")
            print(f"\n{row['content']}")
        print()
        return

    # Unique by (subject, body): the templates repeat, and duplicates
    # inflate the corpus without adding information.
    seen, rows = set(), []
    attempts = 0
    while len(rows) < args.n and attempts < args.n * 50:
        attempts += 1
        row = make_row(rng, hebrew=rng.random() < args.hebrew_share)
        key = (row["subject"], row["content"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["sender", "subject", "content", "text", "label", "lang"])
        writer.writeheader()
        writer.writerows(rows)

    heb = sum(1 for r in rows if r["lang"] == "he")
    print(f"\nwrote {len(rows):,} examples to {args.out}")
    print(f"  Hebrew: {heb:,}  |  English: {len(rows) - heb:,}")
    print(f"  all labelled 0 - legitimate operational mail\n")
    if len(rows) < args.n:
        print(f"  !  {args.n:,} requested, {len(rows):,} unique produced.")
        print("     The templates ran out; add brands or templates.\n")


if __name__ == "__main__":
    main()
