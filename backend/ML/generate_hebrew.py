"""
מחולל מיילים בעברית לאימון LURA
================================

הבעיה: המאגר מכיל ~300 מיילים בעברית מתוך ~132,000. המודל כמעט לא
רואה עברית, ולכן הטענה על תמיכה בעברית אינה מדידה.

תרגום מכונה נוסה ונפסל — התוצאה לא נשמעת כמו מייל עברי אמיתי.
המחולל הזה כותב בעברית מלכתחילה, בשיטה קומבינטורית:

    מותג × עילה × ניסוח × סכום × אסמכתא × קישור  →  אלפי צירופים

הרצה (מתוך backend/):
    python ML/generate_hebrew.py --n 3000
    python ML/generate_hebrew.py --n 20 --preview   # לראות דוגמאות

הפלט: ML/data/hebrew_generated.csv — נאסף אוטומטית על ידי prepare_data.py

מגבלה: דאטה סינתטי. הווריאציה כאן רחבה, אבל היא לא מחליפה מיילים
אותנטיים. ראה --noise שמוסיף שגיאות כתיב וניסוח לא אחיד כדי לצמצם
את הפער.
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import re
import sys

# ---------------------------------------------------------------------------
# מותגים ישראליים — שם, דומיין אמיתי, דומיין מזויף
# ---------------------------------------------------------------------------
BRANDS = {
    "bank": [
        ("בנק הפועלים", "bankhapoalim.co.il", ["bankhapoalim-secure.net", "hapoalim-verify.com", "bank-hapoalim.info"]),
        ("בנק לאומי", "leumi.co.il", ["leumi-online.net", "leumi-secure.info", "bankleumi-il.com"]),
        ("בנק דיסקונט", "discountbank.co.il", ["discount-bank.net", "discountbank-verify.com"]),
        ("בנק מזרחי טפחות", "mizrahi-tefahot.co.il", ["mizrahi-secure.net", "mizrahi-online.info"]),
        ("ישראכרט", "isracard.co.il", ["isracard-verify.net", "isracard-secure.com"]),
        ("כאל", "cal-online.co.il", ["cal-secure.net", "calonline-verify.com"]),
        ("מקס", "max.co.il", ["max-secure.net", "max-card.info"]),
    ],
    "telecom": [
        ("פרטנר", "partner.co.il", ["partner-bill.net", "partner-pay.info"]),
        ("סלקום", "cellcom.co.il", ["cellcom-pay.net", "cellcom-bill.com"]),
        ("HOT", "hot.net.il", ["hot-billing.net", "hot-pay.info"]),
        ("בזק", "bezeq.co.il", ["bezeq-pay.net", "bezeq-billing.com"]),
        ("גולן טלקום", "golantelecom.co.il", ["golan-pay.net"]),
    ],
    "delivery": [
        ("דואר ישראל", "israelpost.co.il", ["israelpost-delivery.net", "israel-post.info", "postil-track.com"]),
        ("DHL", "dhl.co.il", ["dhl-delivery.net", "dhl-track.info"]),
        ("FedEx", "fedex.com", ["fedex-il.net", "fedex-delivery.info"]),
        ("UPS", "ups.com", ["ups-israel.net", "ups-track.info"]),
        ("צ'יטה משלוחים", "cheetah.co.il", ["cheetah-track.net"]),
    ],
    "retail": [
        ("KSP", "ksp.co.il", ["ksp-sale.net", "ksp-order.info"]),
        ("Terminal X", "terminalx.com", ["terminalx-sale.net"]),
        ("איקאה", "ikea.co.il", ["ikea-il.net", "ikea-sale.info"]),
        ("רמי לוי", "rami-levy.co.il", ["ramilevy-club.net"]),
        ("שופרסל", "shufersal.co.il", ["shufersal-club.net", "shufersal-sale.info"]),
        ("Zap", "zap.co.il", ["zap-deals.net"]),
    ],
    "gov": [
        ("רשות המסים", "gov.il", ["taxes-refund.net", "misim-gov.info", "gov-il-refund.com"]),
        ("ביטוח לאומי", "btl.gov.il", ["btl-refund.net", "bituah-leumi.info"]),
        ("משרד התחבורה", "gov.il", ["mot-fines.net", "transport-gov.info"]),
        ("חברת החשמל", "iec.co.il", ["iec-pay.net", "electric-bill.info"]),
    ],
    "streaming": [
        ("Netflix", "netflix.com", ["netflix-billing.net", "netflix-il.info"]),
        ("Spotify", "spotify.com", ["spotify-premium.net"]),
        ("yes", "yes.co.il", ["yes-tv.net"]),
    ],
}

FIRST_NAMES = ["נועה", "יובל", "איתי", "שירה", "דניאל", "מאיה", "עומר", "תמר",
               "אורי", "ליאור", "רותם", "אסף", "הילה", "גיא", "עדי", "רון",
               "יעל", "אלון", "מיכל", "נדב", "שני", "עמית", "טל", "ניר"]

# ---------------------------------------------------------------------------
# מיילים לגיטימיים
# ---------------------------------------------------------------------------
LEGIT = {
    "bank": [
        "דוח חשבון חודשי | {brand}\nשלום {name},\nדוח החשבון שלך לחודש {month} מוכן לצפייה באזור האישי.\nיתרה נוכחית: {amount} ₪ | תנועות בחודש: {count}\nלצפייה: {real}\n\nלשאלות ניתן לפנות למוקד בשעות הפעילות.",
        "הודעת חיוב | {brand}\nשלום {name},\nבוצע חיוב בסך {amount} ₪ בכרטיס שמסתיים ב-{last4}, בבית העסק {merchant}.\nתאריך: {date}\nאם אינך מזהה את החיוב, ניתן לפנות אלינו דרך האזור האישי באתר.",
        "סיכום חודשי | {brand}\n{name} שלום,\nסיכום הפעילות בחשבונך לחודש {month}:\nהכנסות {amount} ₪ | הוצאות {amount2} ₪\nהפירוט המלא זמין באפליקציה ובאתר {real}.",
        "אישור העברה | {brand}\nשלום {name},\nההעברה על סך {amount} ₪ בוצעה בהצלחה.\nאסמכתא: {ref}\nמועד ביצוע: {date}\nההעברה תיקלט אצל המוטב תוך יום עסקים אחד.",
    ],
    "telecom": [
        "חשבון חודשי | {brand}\nשלום {name},\nהחשבון שלך לחודש {month} עומד על {amount} ₪.\nמועד חיוב: {date}\nהחבילה שלך: שיחות ללא הגבלה, {count} GB גלישה.\nלפירוט מלא: {real}",
        "עדכון חבילה | {brand}\n{name} שלום,\nהחבילה שלך עודכנה בהצלחה. החיוב החודשי החדש: {amount} ₪.\nהשינוי ייכנס לתוקף במחזור החיוב הבא.\nלפרטים: {real}",
        "קבלה על תשלום | {brand}\nשלום {name},\nהתקבל תשלום בסך {amount} ₪ עבור חשבון {month}.\nאסמכתא: {ref}. תודה!",
    ],
    "delivery": [
        "עדכון משלוח | {brand}\nשלום {name},\nהחבילה שלך {track} יצאה מהמיון ובדרך אליך.\nצפי הגעה: {date}\nמעקב: {real}",
        "החבילה הגיעה | {brand}\n{name} שלום,\nהחבילה {track} ממתינה לאיסוף בנקודת החלוקה.\nכתובת: {street} {count}\nשעות פעילות: א'-ה' 08:00-18:00",
        "המשלוח בדרך | {brand}\nשלום {name},\nהשליח יגיע היום בין השעות {hour}:00-{hour2}:00.\nמספר מעקב: {track}\nלשינוי מועד: {real}",
    ],
    "retail": [
        "אישור הזמנה | {brand}\nשלום {name},\nהזמנה מספר {ref} התקבלה בהצלחה.\nסה\"כ לתשלום: {amount} ₪\nהמוצרים יישלחו תוך {count} ימי עסקים.\nתודה שקנית אצלנו!",
        "ההזמנה שלך בהכנה | {brand}\n{name} שלום,\nההזמנה {ref} בהכנה במחסן. תקבל/י הודעה כשהחבילה תצא.\nסכום: {amount} ₪\nלצפייה בהזמנה: {real}",
        "קבלה | {brand}\nשלום {name},\nרכישתך בסך {amount} ₪ אושרה. אסמכתא: {ref}.\nניתן להחזיר תוך 14 יום עם הקבלה.",
    ],
    "gov": [
        "אישור קבלת מסמכים | {brand}\nשלום {name},\nהמסמכים שהגשת התקבלו במערכת. מספר פנייה: {ref}.\nזמן טיפול משוער: עד {count} ימי עבודה.\nניתן לעקוב באזור האישי באתר {real}.",
        "עדכון סטטוס | {brand}\n{name} שלום,\nהבקשה מספר {ref} עברה לטיפול.\nלא נדרשת פעולה מצדך בשלב זה.",
    ],
    "streaming": [
        "החשבונית שלך מוכנה | {brand}\nשלום {name},\nהחיוב החודשי בסך {amount} ₪ בוצע בהצלחה.\nהמנוי שלך פעיל עד {date}.",
        "תודה על המנוי | {brand}\n{name} שלום,\nהמנוי שלך חודש אוטומטית. סכום: {amount} ₪.\nלניהול המנוי: {real}",
    ],
}

# ---------------------------------------------------------------------------
# מיילי פישינג — עילות נפוצות
# ---------------------------------------------------------------------------
PHISH = {
    "bank": [
        "אזהרה: פעילות חריגה בחשבונך | {brand}\nשלום,\nזיהינו ניסיון גישה לא מורשה לחשבונך מהתקן לא מוכר.\n{urgency}\nלאימות זהותך ושחרור החשבון: {fake}\nאם לא תאמת תוך {hours} שעות, החשבון ייחסם באופן זמני.",
        "החשבון שלך הוגבל | {brand}\nלקוח יקר,\nבשל אי-עדכון פרטים, חשבונך הוגבל לפעולות יוצאות.\n{urgency}\nלהסרת ההגבלה יש להזין את פרטי הכרטיס והסיסמה: {fake}",
        "כרטיס האשראי שלך נחסם | {brand}\nשלום,\nהכרטיס שמסתיים ב-{last4} נחסם בעקבות חיוב חשוד בסך {amount} ₪.\n{urgency}\nלביטול החיוב ושחרור הכרטיס לחץ כאן: {fake}",
        "נדרש עדכון אמצעי אבטחה | {brand}\nלקוח נכבד,\nהמערכת מחייבת עדכון סיסמה ואמצעי זיהוי עד {date}.\nחשבונות שלא יעודכנו ייסגרו.\nלעדכון מיידי: {fake}",
        "זיכוי ממתין באישורך | {brand}\nשלום,\nזוהה חיוב כפול בסך {amount} ₪. הזיכוי ממתין לאישורך.\nלקבלת הכסף יש לאמת את פרטי החשבון: {fake}\n{urgency}",
    ],
    "telecom": [
        "חשבונך בפיגור | {brand}\nלקוח יקר,\nלא נקלט תשלום בסך {amount} ₪ עבור חודש {month}.\n{urgency}\nלתשלום מיידי ומניעת ניתוק הקו: {fake}",
        "הקו שלך יינתק היום | {brand}\nשלום,\nעקב חוב של {amount} ₪ הקו יינתק בתוך {hours} שעות.\nלהסדרת התשלום: {fake}",
        "זיכוי בסך {amount} ₪ ממתין | {brand}\nשלום,\nמצאנו חיוב יתר בחשבונך. הזיכוי ממתין להעברה.\nלקבלתו יש להזין פרטי כרטיס אשראי: {fake}\n{urgency}",
    ],
    "delivery": [
        "החבילה שלך ממתינה — נדרש תשלום | {brand}\nשלום,\nהחבילה {track} מעוכבת במכס.\nנדרש תשלום אגרה בסך {small} ₪ לשחרורה.\n{urgency}\nלתשלום: {fake}",
        "כתובת שגויה — עדכן פרטים | {brand}\nשלום,\nלא הצלחנו למסור את החבילה {track} עקב כתובת חסרה.\nלעדכון הכתובת תוך {hours} שעות: {fake}\nלאחר מכן החבילה תוחזר לשולח.",
        "משלוח אחרון לפני החזרה | {brand}\nהחבילה {track} ממתינה במחסן.\n{urgency}\nלתיאום מסירה ותשלום דמי אחסון {small} ₪: {fake}",
    ],
    "retail": [
        "זכית בפרס! | {brand}\nמזל טוב,\nנבחרת באקראי לזכות בשובר בסך {amount} ₪.\n{urgency}\nלמימוש הפרס יש למלא פרטים תוך {hours} שעות: {fake}",
        "ההזמנה שלך בוטלה | {brand}\nשלום,\nהזמנה {ref} בוטלה עקב בעיה באמצעי התשלום.\nלחידוש ההזמנה ועדכון פרטי אשראי: {fake}",
        "חיוב לא מזוהה בחשבונך | {brand}\nזוהה חיוב בסך {amount} ₪ שלא בוצע על ידך.\n{urgency}\nלביטול מיידי: {fake}",
    ],
    "gov": [
        "החזר מס ממתין לך | {brand}\nשלום,\nזוהה תשלום יתר בסך {amount} ₪ לשנת המס.\nלקבלת ההחזר יש להזין פרטי חשבון בנק: {fake}\n{urgency}",
        "דוח תנועה לתשלום | {brand}\nנרשם לחובתך דוח בסך {amount} ₪.\nתשלום עד {date} יזכה בהנחה של 50%.\nלתשלום: {fake}",
        "עדכון פרטים נדרש | {brand}\nלא ניתן להעביר את הקצבה החודשית בשל פרטים חסרים.\n{urgency}\nלעדכון: {fake}",
    ],
    "streaming": [
        "המנוי שלך יבוטל | {brand}\nשלום,\nלא הצלחנו לחייב את אמצעי התשלום שלך.\n{urgency}\nלעדכון פרטי תשלום ומניעת ביטול: {fake}",
        "חשבונך הושעה | {brand}\nזוהתה כניסה מהתקן לא מוכר.\nלשחזור הגישה יש לאמת את הסיסמה: {fake}",
    ],
}

URGENCY = [
    "יש לפעול באופן מיידי.",
    "הפעולה דחופה ואינה ניתנת לדחייה.",
    "אנא טפל בכך בהקדם האפשרי.",
    "אי-טיפול יוביל לחסימה קבועה.",
    "זוהי התראה אחרונה.",
    "הזמן קצוב ואינו ניתן להארכה.",
    "לתשומת לבך — הטיפול דחוף.",
    "נא לא להתעלם מהודעה זו.",
]

MONTHS = ["ינואר", "פברואר", "מרץ", "אפריל", "מאי", "יוני",
          "יולי", "אוגוסט", "ספטמבר", "אוקטובר", "נובמבר", "דצמבר"]
MERCHANTS = ["שופרסל דיל", "KSP", "פז", "רמי לוי", "מקדונלד'ס", "סופר פארם",
             "Terminal X", "דלק", "ארומה", "איקאה", "castro", "H&M"]
STREETS = ["הרצל", "ויצמן", "בן גוריון", "אלנבי", "דיזנגוף", "רוטשילד",
           "ז'בוטינסקי", "הנשיא", "השלום", "בגין"]

# שגיאות כתיב נפוצות, לצמצום המראה הרובוטי
TYPOS = [("שלום", "שלון"), ("החשבון", "החשבן"), ("לחץ", "לחץ  "),
         ("אנא", "אנה"), ("פרטים", "פרטים "), ("תשלום", "תשלון")]


# ארגונים אמיתיים מפנים לאזור אישי בהצפנה. מיילי פישינג נוטים
# לנתיבי הזדהות ולעיתים ל-http לא מוצפן — ההפרדה כאן שומרת על
# ההבדל הזה גם בדאטה הסינתטי.
REAL_PATHS = ["", "personal", "account/statements", "my", "orders",
              "billing/history", "he/personal", "info", "support"]
FAKE_PATHS = ["login", "verify", "secure-login", "account/verify",
              "confirm-identity", "update-payment", "auth", "il/login",
              "unlock", "validate"]


# כתובות שולח. מיילי פישינג משתמשים בדומיין דומה, ולעיתים בספק חינמי
# בשם ארגון רשמי — דפוס שמנוע החוקים מזהה במפורש.
REAL_MAILBOXES = ["noreply", "no-reply", "service", "info", "billing",
                  "support", "updates", "notifications"]
FAKE_MAILBOXES = ["no-reply", "security", "alert", "verify", "service-il",
                  "account-security", "support"]
FREE_PROVIDERS = ["gmail.com", "outlook.com", "hotmail.com", "walla.co.il"]


def rnd_sender(brand: tuple, legit: bool, rng: random.Random) -> str:
    name, real_domain, fake_domains = brand
    if legit:
        return f"{rng.choice(REAL_MAILBOXES)}@{real_domain}"
    if rng.random() < 0.22:
        # התחזות דרך ספק דואר חינמי
        slug = re.sub(r"[^a-z]", "", name.lower()) or "service"
        return f"{slug}.{rng.choice(['security', 'support', 'alert'])}{rng.randint(1, 99)}@{rng.choice(FREE_PROVIDERS)}"
    return f"{rng.choice(FAKE_MAILBOXES)}@{rng.choice(fake_domains)}"


def rnd_link(domain: str, legit: bool, rng: random.Random) -> str:
    if legit:
        path = rng.choice(REAL_PATHS)
        base = f"https://www.{domain}" if rng.random() < 0.5 else f"https://{domain}"
        return f"{base}/{path}".rstrip("/")
    path = rng.choice(FAKE_PATHS)
    scheme = rng.choice(["http://", "https://", "http://www."])
    return f"{scheme}{domain}/{path}"


def fill(template: str, brand: tuple, rng: random.Random) -> str:
    name, real_domain, fake_domains = brand
    values = {
        "brand":    name,
        "name":     rng.choice(FIRST_NAMES),
        "real":     rnd_link(real_domain, legit=True, rng=rng),
        "fake":     rnd_link(rng.choice(fake_domains), legit=False, rng=rng),
        "amount":   f"{rng.randint(50, 9500):,}",
        "amount2":  f"{rng.randint(50, 9500):,}",
        "small":    rng.randint(9, 89),
        "count":    rng.randint(2, 30),
        "last4":    rng.randint(1000, 9999),
        "ref":      f"{rng.choice(['IL', 'REF', 'ORD', ''])}{rng.randint(100000, 999999)}",
        "track":    f"{rng.choice(['IL', 'RR', 'JD'])}{rng.randint(100000000, 999999999)}",
        "date":     f"{rng.randint(1, 28)}/{rng.randint(1, 12)}/2026",
        "month":    rng.choice(MONTHS),
        "merchant": rng.choice(MERCHANTS),
        "street":   rng.choice(STREETS),
        "hour":     rng.randint(8, 15),
        "hour2":    rng.randint(16, 20),
        "hours":    rng.choice([2, 6, 12, 24, 48, 72]),
        "urgency":  rng.choice(URGENCY),
    }
    return template.format(**values)


def add_noise(text: str, rng: random.Random) -> str:
    """שגיאות כתיב וניסוח לא אחיד — מיילים אמיתיים אינם מושלמים."""
    if rng.random() < 0.15:
        src, dst = rng.choice(TYPOS)
        text = text.replace(src, dst, 1)
    if rng.random() < 0.10:
        text = text.replace("!", "!!", 1)
    if rng.random() < 0.08:
        text = text + "\n\nהודעה זו נשלחה אוטומטית, נא לא להשיב."
    return text


def generate(n: int, seed: int, noise: bool) -> list[dict]:
    """
    מפיק שורות עם sender, subject ו-content בנפרד.

    הפרדת השדות חיונית: מנוע החוקים מריץ שלוש מתוך שמונה בדיקותיו על
    כתובת השולח בלבד. דאטה שמכיל רק גוף מייל אחיד לא מאפשר להעריך את
    האנסמבל כפי שהוא רץ בפועל, אלא רק את BERT.
    """
    rng = random.Random(seed)
    rows, seen = [], set()
    categories = list(BRANDS.keys())
    attempts = 0

    while len(rows) < n and attempts < n * 40:
        attempts += 1
        category = rng.choice(categories)
        brand = rng.choice(BRANDS[category])
        is_phish = rng.random() < 0.42          # יחס דומה לשאר המאגר

        pool = PHISH[category] if is_phish else LEGIT[category]
        text = fill(rng.choice(pool), brand, rng)
        if noise:
            text = add_noise(text, rng)

        # התבניות בנויות כ-"נושא | מותג\nגוף ההודעה"
        subject, _, body = text.partition("\n")
        sender = rnd_sender(brand, legit=not is_phish, rng=rng)

        key = text[:150]
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "sender":  sender,
            "subject": subject.strip(),
            "content": body.strip(),
            "text":    f"{sender} {subject.strip()} {body.strip()}",
            "label":   int(is_phish),
        })

    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="מחולל מיילים בעברית")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", default="ML/data/hebrew_generated.csv")
    ap.add_argument("--no-noise", action="store_true", help="בלי שגיאות כתיב")
    ap.add_argument("--preview", action="store_true", help="הדפסה במקום שמירה")
    args = ap.parse_args()

    rows = generate(args.n, args.seed, noise=not args.no_noise)

    if args.preview:
        for r in rows[:8]:
            tag = "פישינג" if r["label"] else "לגיטימי"
            print(f"\n{'─' * 64}\n[{tag}]  מאת: {r['sender']}")
            print(f"נושא: {r['subject']}\n\n{r['content']}")
        print(f"\n{'─' * 64}\nסה\"כ נוצרו {len(rows)} (מוצגות 8)")
        return

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sender", "subject", "content", "text", "label"])
        w.writeheader()
        w.writerows(rows)

    phish = sum(r["label"] for r in rows)
    print(f"נשמרו {len(rows)} מיילים בעברית → {args.output}")
    print(f"  פישינג: {phish} ({phish/len(rows)*100:.0f}%)  |  "
          f"לגיטימי: {len(rows)-phish} ({(len(rows)-phish)/len(rows)*100:.0f}%)")
    if len(rows) < args.n:
        print(f"  שים לב: התבקשו {args.n} אך מרחב הצירופים הגיע לרוויה.")
    print("\n  הצעד הבא:  python ML/prepare_data.py")


if __name__ == "__main__":
    main()
