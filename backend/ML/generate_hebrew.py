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
# Israeli brands: name, real domain, forged domain
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
# Legitimate messages
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
# Phishing, on the common pretexts
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

# ---------------------------------------------------------------------------
# Borderline cases
#
# The first version separated the classes perfectly: legitimate always
# https to an official domain with no urgency, phishing always http to a
# hyphenated domain with urgency. A model learning from that learns one
# rule - "hyphen in the domain means phishing" - not how to spot
# phishing. Calibrating on it gave a perfect F1 and a threshold low
# enough to flag a real invoice.
#
# These two groups break that separation: legitimate mail that looks
# suspicious, and phishing that looks innocent.
# ---------------------------------------------------------------------------

# Legitimate, with signs that look suspicious: real urgency, genuine
# verification requests, subdomains, and financial language that also
# appears in fraud.
HARD_LEGIT = {
    "retail": [
        "המבצע מסתיים היום | {brand}\nשלום {name},\nנותרו {hours} שעות לסיום המבצע. הנחה של 30% על כל האתר.\nלצפייה: {real}\nמוזמנ/ת להצטרף למועדון הלקוחות.",
        "אימות כתובת מייל | {brand}\nשלום {name},\nכדי להשלים את ההרשמה נדרש לאמת את כתובת המייל.\nלאימות: {real}\nאם לא נרשמת אצלנו, אפשר להתעלם מהודעה זו.",
        "עגלת הקניות ממתינה | {brand}\n{name} שלום,\nהשארת פריטים בסך {amount} ₪ בעגלה. המלאי מוגבל.\nלהשלמת ההזמנה: {real}",
    ],
    "bank": [
        "נדרשת פעולה בחשבונך | {brand}\nשלום {name},\nלצורך עמידה בדרישות רגולציה נדרש לעדכן את פרטי הזיהוי עד {date}.\nניתן לבצע זאת באזור האישי או בסניף.\n{real}\nלא נבקש ממך פרטים בטלפון או במייל.",
        "כרטיסך עומד לפוג | {brand}\n{name} שלום,\nהכרטיס שמסתיים ב-{last4} יפוג בחודש {month}.\nכרטיס חדש יישלח לכתובתך אוטומטית. לעדכון כתובת: {real}",
        "התראת חיוב חריג | {brand}\nשלום {name},\nזוהה חיוב בסך {amount} ₪ החורג מדפוס ההוצאות הרגיל שלך.\nאם ביצעת את החיוב, אין צורך בפעולה. לצפייה: {real}",
    ],
    "streaming": [
        "אמצעי התשלום שלך יפוג | {brand}\nשלום {name},\nהכרטיס הרשום אצלנו יפוג בסוף {month}.\nלעדכון פרטי תשלום ומניעת הפסקת השירות: {real}",
        "כניסה מהתקן חדש | {brand}\n{name} שלום,\nזוהתה כניסה לחשבונך מהתקן חדש ב-{date}.\nאם זה היית את/ה — אין צורך בפעולה.\nלניהול התקנים: {real}",
    ],
    "telecom": [
        "החשבון שלך גבוה מהרגיל | {brand}\nשלום {name},\nהחשבון לחודש {month} עומד על {amount} ₪, גבוה מהממוצע שלך.\nלפירוט השיחות והגלישה: {real}",
        "איפוס סיסמה | {brand}\n{name} שלום,\nהתקבלה בקשה לאיפוס הסיסמה לאזור האישי.\nלאיפוס: {real}\nהקישור תקף לשעה. אם לא ביקשת — התעלם/י.",
    ],
    "delivery": [
        "החבילה מוחזרת לשולח | {brand}\nשלום {name},\nהחבילה {track} ממתינה {count} ימים ולא נאספה.\nהיא תוחזר לשולח בעוד {hours} שעות. לתיאום: {real}",
    ],
    "gov": [
        "מסמך ממתין לחתימתך | {brand}\nשלום {name},\nבתיק {ref} ממתין מסמך לחתימה דיגיטלית עד {date}.\nלכניסה עם כרטיס חכם או אימות דו-שלבי: {real}",
    ],
}

# Phishing written calmly and professionally, with no urgency, and
# sometimes from a domain that looks entirely reasonable.
HARD_PHISH = {
    "bank": [
        "עדכון תנאי שימוש | {brand}\nשלום,\nתנאי השימוש בחשבונך עודכנו. כדי להמשיך לקבל שירות מלא, נא לאשר את התנאים החדשים בקישור הבא.\n{fake}\nתודה על שיתוף הפעולה.",
        "אישור פרטי חשבון | {brand}\nשלום,\nכחלק מתהליך שגרתי לשמירה על אבטחת המידע, נבקש לאמת את פרטי החשבון.\nלאישור: {fake}\nההליך אורך פחות מדקה.",
    ],
    "streaming": [
        "עדכון אמצעי תשלום | {brand}\nשלום,\nלא הצלחנו לעבד את החיוב האחרון. ניתן לעדכן את פרטי התשלום בקישור:\n{fake}\nהמנוי שלך ימשיך לפעול כרגיל.",
    ],
    "retail": [
        "קבלה על הזמנתך | {brand}\nשלום,\nמצורפת קבלה על הזמנה מספר {ref} בסך {amount} ₪.\nלצפייה בפרטי ההזמנה: {fake}\nתודה על הרכישה.",
    ],
    "gov": [
        "עדכון פרטי קשר | {brand}\nשלום,\nהפרטים הרשומים במערכת אינם מעודכנים. לעדכון ניתן להיכנס לקישור:\n{fake}\nהעדכון אינו כרוך בתשלום.",
    ],
    "telecom": [
        "סיכום חשבון | {brand}\nשלום,\nסיכום החשבון לחודש {month} זמין לצפייה.\nלצפייה בפירוט המלא: {fake}",
    ],
    "delivery": [
        "עדכון סטטוס משלוח | {brand}\nשלום,\nהמשלוח {track} עודכן. ניתן לעקוב אחר הסטטוס בקישור:\n{fake}",
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

# Common typos, to reduce the robotic look
TYPOS = [("שלום", "שלון"), ("החשבון", "החשבן"), ("לחץ", "לחץ  "),
         ("אנא", "אנה"), ("פרטים", "פרטים "), ("תשלום", "תשלון")]


# Real organisations link to an encrypted account area. Phishing tends
# toward sign-in paths and sometimes plain http - this keeps that
# difference in the synthetic data too.
REAL_PATHS = ["", "personal", "account/statements", "my", "orders",
              "billing/history", "he/personal", "info", "support"]
FAKE_PATHS = ["login", "verify", "secure-login", "account/verify",
              "confirm-identity", "update-payment", "auth", "il/login",
              "unlock", "validate"]


# Sender addresses. Phishing uses a lookalike domain, and sometimes a
# free provider under an official-sounding name - a pattern the rule
# engine flags explicitly.
REAL_MAILBOXES = ["noreply", "no-reply", "service", "info", "billing",
                  "support", "updates", "notifications"]
FAKE_MAILBOXES = ["no-reply", "security", "alert", "verify", "service-il",
                  "account-security", "support"]

# Mailboxes that sound alarming but that real organisations genuinely
# use: a bank's fraud alert really does come from security@ or alerts@.
#
# Before this existed, "security", "verify" and "alert" appeared only in
# phishing rows, so the word before the @ predicted the label on its own.
# Overlapping the domains was not enough - a classifier reading the whole
# address still scored 0.985, because the mailbox vocabularies were
# disjoint. Both classes now draw from this list.
ALERTING_MAILBOXES = ["security", "alerts", "fraud-alert", "account-notice",
                      "verification", "secure-messages"]
FREE_PROVIDERS = ["gmail.com", "outlook.com", "hotmail.com", "walla.co.il"]

# Legitimate subdomains. A real organisation also sends from
# mail.brand.co.il, and the impersonation check has to accept those.
LEGIT_SUBDOMAINS = ["mail", "news", "info", "no-reply", "service", "notify"]

# Shapes that look plausible at a glance: the official name as the
# prefix of a foreign domain, which reads as correct when skimmed.
def deceptive_domain(real_domain: str, rng: random.Random) -> str:
    style = rng.randint(0, 2)
    if style == 0:
        return f"{real_domain}.{rng.choice(['secure-verify', 'account-il', 'login-portal'])}.com"
    if style == 1:
        base = real_domain.split(".")[0]
        return f"{base}-{rng.choice(['notifications', 'support', 'billing', 'account'])}.com"
    base = real_domain.split(".")[0]
    return f"{base}{rng.choice(['-il', 'online', 'service'])}.com"


def rnd_sender(brand: tuple, legit: bool, rng: random.Random,
               hard: bool = False) -> str:
    """
    A sender for one generated message.

    The classes overlap on purpose. An earlier version gave every
    legitimate row the brand's real domain and every phishing row a
    lookalike or a free provider, with no exceptions either way, so the
    address determined the label: a classifier reading nothing but the
    sender scored AUC 1.000 on these rows (ML/senders.py --audit).

    That is not what real mail looks like, and because these rows are in
    the training data it is not only a measurement problem - it taught
    the model that an official domain is proof of safety. Real senders
    overlap: small businesses and sole traders write from Gmail, and
    attackers send from compromised accounts on ordinary domains.

    The overlap is deliberately modest. Impersonation from a lookalike
    domain is still most of what phishing draws, because that is what
    the impersonation rule exists to catch.
    """
    name, real_domain, fake_domains = brand

    # The mailbox is drawn from the same two lists for both classes. What
    # separates a phishing row is the domain it is paired with, which is
    # the thing the impersonation rule actually reads.
    def mailbox() -> str:
        return (rng.choice(ALERTING_MAILBOXES) if rng.random() < 0.22
                else rng.choice(REAL_MAILBOXES))

    if legit:
        roll = rng.random()
        # There is deliberately no free-provider branch here.
        #
        # An earlier version gave 18% of legitimate rows a Gmail or Walla
        # address, to stop the sender predicting the label. Measured, it
        # was a mistake: every template in this file presents the message
        # as the brand ("הודעת חיוב | בנק הפועלים"), so a brand-claiming
        # message from gmail.com labelled legitimate is a mislabelled
        # impersonation. The rule engine flagged 34 of them and was right
        # to - they turned into Hebrew false alarms at every threshold,
        # where there had been none.
        #
        # The wider lesson: for brand transactional mail the sender is
        # genuinely what makes it legitimate, so a sender that predicts
        # the label here is the subject matter, not leakage. Overlapping
        # the classes is the right move only where the message makes no
        # claim about who sent it - which is what ML/senders.py does for
        # the rows that have no sender at all.
        if hard and roll < 0.60:
            # An official subdomain - looks unusual, entirely valid
            sub = rng.choice(LEGIT_SUBDOMAINS)
            return f"{mailbox()}@{sub}.{real_domain}"
        return f"{mailbox()}@{real_domain}"

    roll = rng.random()
    # A compromised account on the brand's own domain. Rare, and the
    # hardest case there is - the sender is genuinely theirs, so only the
    # message body gives it away.
    if roll < 0.06:
        return f"{mailbox()}@{real_domain}"
    if hard:
        # A plausible domain and a plain mailbox - no "security" or "alert"
        return f"{rng.choice(REAL_MAILBOXES)}@{deceptive_domain(real_domain, rng)}"
    if roll < 0.28:
        # Impersonation through a free mail provider. The brand slug is
        # kept for a minority of these - it is a real phishing habit, but
        # as the default it made the local part a giveaway on its own.
        if rng.random() < 0.35:
            slug = re.sub(r"[^a-z]", "", name.lower()) or "service"
            return (f"{slug}.{rng.choice(['security', 'support', 'alert'])}"
                    f"{rng.randint(1, 99)}@{rng.choice(FREE_PROVIDERS)}")
        return f"{mailbox()}{rng.randint(1, 99)}@{rng.choice(FREE_PROVIDERS)}"
    return f"{mailbox()}@{rng.choice(fake_domains)}"


def rnd_link(domain: str, legit: bool, rng: random.Random) -> str:
    if legit:
        path = rng.choice(REAL_PATHS)
        base = f"https://www.{domain}" if rng.random() < 0.5 else f"https://{domain}"
        return f"{base}/{path}".rstrip("/")
    path = rng.choice(FAKE_PATHS)
    scheme = rng.choice(["http://", "https://", "http://www."])
    return f"{scheme}{domain}/{path}"


def fill(template: str, brand: tuple, rng: random.Random, hard: bool = False) -> str:
    name, real_domain, fake_domains = brand
    values = {
        "brand":    name,
        "name":     rng.choice(FIRST_NAMES),
        "real":     rnd_link(real_domain, legit=True, rng=rng),
        # Calm phishing links to a misleading domain over https - no
        # plain http and no /verify
        "fake":     (rnd_link(deceptive_domain(real_domain, rng), legit=True, rng=rng)
                     if hard else
                     rnd_link(rng.choice(fake_domains), legit=False, rng=rng)),
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


def generate(n: int, seed: int, noise: bool, hard_ratio: float = 0.30) -> list[dict]:
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

        # Borderline cases. Without them the classes separate perfectly
        # and the model learns one shallow rule instead of the task.
        hard_pool = HARD_PHISH if is_phish else HARD_LEGIT
        hard = rng.random() < hard_ratio and category in hard_pool

        if hard:
            pool = hard_pool[category]
        else:
            pool = PHISH[category] if is_phish else LEGIT[category]

        text = fill(rng.choice(pool), brand, rng, hard=hard)
        if noise and not hard:
            # Borderline cases stay clean: typos would make them easy to
            # spot and defeat their whole purpose.
            text = add_noise(text, rng)

        # Templates are shaped as "subject | brand\nbody"
        subject, _, body = text.partition("\n")
        sender = rnd_sender(brand, legit=not is_phish, rng=rng, hard=hard)

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
            "hard":    int(hard),
        })

    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Hebrew email generator")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", default="ML/data/hebrew_generated.csv")
    ap.add_argument("--no-noise", action="store_true", help="no typos")
    ap.add_argument(
        "--hard-ratio", type=float, default=0.30,
        help="share of borderline cases - legitimate that looks suspicious "
             "and phishing that looks innocent",
    )
    ap.add_argument("--preview", action="store_true", help="print instead of saving")
    args = ap.parse_args()

    rows = generate(args.n, args.seed, noise=not args.no_noise,
                    hard_ratio=args.hard_ratio)

    if args.preview:
        for r in rows[:8]:
            tag = "phishing" if r["label"] else "legitimate"
            print(f"\n{'-' * 64}\n[{tag}]  from: {r['sender']}")
            print(f"subject: {r['subject']}\n\n{r['content']}")
        print(f"\n{'-' * 64}\n{len(rows)} generated (8 shown)")
        return

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sender", "subject", "content", "text", "label", "hard"])
        w.writeheader()
        w.writerows(rows)

    phish = sum(r["label"] for r in rows)
    print(f"wrote {len(rows)} Hebrew messages -> {args.output}")
    print(f"  phishing: {phish} ({phish/len(rows)*100:.0f}%)  |  "
          f"legitimate: {len(rows)-phish} ({(len(rows)-phish)/len(rows)*100:.0f}%)")
    if len(rows) < args.n:
        print(f"  note: {args.n} requested, but the combinations ran out.")
    print("\n  next:  python ML/prepare_data.py")


if __name__ == "__main__":
    main()
