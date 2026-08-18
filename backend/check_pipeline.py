"""
בדיקה מהירה שהצינור חי — מול השרת שרץ.

תיבה נקייה שכל המיילים בה מקבלים 0% נראית בדיוק כמו מערכת מקולקלת
שמחזירה אפס לכל דבר. הסקריפט הזה מפריד בין השניים: הוא שולח לשרת מייל
פישינג מובהק ומייל תמים, ומראה מה חזר על כל אחד מהם.

הרצה (מתוך backend/, כשהשרת פועל):
    python check_pipeline.py
    python check_pipeline.py --url http://localhost:8000
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request

SAMPLES = [
    dict(
        expect="גבוה",
        note="פישינג מובהק באנגלית",
        sender="security-rn@paypal-verify.xyz",
        subject="URGENT: verify your account",
        content=(
            "Your account has been suspended. Verify your password immediately "
            "or your account will be permanently closed. "
            "Click here: http://paypal-verify.xyz/login"
        ),
    ),
    dict(
        expect="גבוה",
        note="התחזות לבנק בעברית",
        sender="service@bank-leumi-secure.com",
        subject="חשבונך ייחסם",
        content=(
            "לקוח יקר, זוהתה פעילות חריגה בחשבונך. יש לאמת את פרטי הכניסה "
            "תוך 24 שעות אחרת החשבון ייחסם. http://bank-leumi-secure.com/verify"
        ),
    ),
    dict(
        expect="נמוך",
        note="ניוזלטר תמים",
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
    ap = argparse.ArgumentParser(description="בדיקת שפיות לצינור החי")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--email", default="pipeline-check@example.com",
                    help="כתובת נפרדת, כדי לא ללכלך את החשבון האמיתי")
    args = ap.parse_args()

    try:
        state = get(args.url, "/health/model")
    except urllib.error.URLError as exc:
        raise SystemExit(f"השרת אינו מגיב ב-{args.url}\n{exc}")

    print(f"\nמצב המודל: {state.get('state', 'לא ידוע')}")
    if state.get("state") != "ready":
        print("  המודל טרם נטען — הציונים למטה מגיעים ממנוע החוקים בלבד.")
        print("  זו התנהגות תקינה, אבל כדאי לחזור לבדיקה אחרי שהוא מוכן.")
    print()

    print("═" * 72)
    print(f"  {'צפוי':<6} {'ציון':>6}  {'רמה':<12} הערה")
    print("═" * 72)

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
            print(f"  {s['expect']:<6} {'שגיאה':>6}  HTTP {exc.code}   {s['note']}")
            ok = False
            continue

        score = r.get("risk_score", 0)
        good = (score >= 57) if s["expect"] == "גבוה" else (score < 34)
        ok &= good
        mark = "" if good else "   ← לא כצפוי"
        print(f"  {s['expect']:<6} {score:>6.1f}  {r.get('risk_level', ''):<12} "
              f"{s['note']}{mark}")

    print("═" * 72)
    if ok:
        print("\n  הצינור עובד. אם כל המיילים בתיבה מקבלים ציון נמוך —")
        print("  זו התיבה, לא המערכת.\n")
    else:
        print("\n  משהו לא מסתדר. שווה לבדוק שהמודל נטען ושהסף ב-config.py")
        print("  הוא זה שכוילנו אליו.\n")


if __name__ == "__main__":
    main()
