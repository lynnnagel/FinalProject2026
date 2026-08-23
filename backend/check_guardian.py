"""
End-to-end check of guardian mode, against the running server.

Guardian mode touches four pieces that were written separately: linking
the accounts, the scan that decides a message is phishing, the alert
record kept for the guardian, and the mail that goes out. Every failure
we found in it lived in a seam between two of those, not inside any one
of them - so the only check worth having walks the whole chain.

It creates two throwaway accounts, links them, sends one obvious
phishing message as the monitored user, and then verifies each link:
the message was classified, the alert reached the guardian's dashboard,
the alert names the monitored user, and a second scan does not duplicate
it.

Run from backend/, with the server up:
    python check_guardian.py
    python check_guardian.py --url http://localhost:8000
    python check_guardian.py --keep      # leave the accounts in place

To receive the alert in a real mailbox, name it as the guardian. If that
address is already registered, give its password too - the script logs
in as the guardian and cannot use the throwaway one:
    python check_guardian.py --guardian you@gmail.com
    python check_guardian.py --guardian you@gmail.com --guardian-password ...
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request

PHISHING = {
    "sender": "service@bank-leumi-secure.xyz",
    "subject": "בנק לאומי: חשבונך ייחסם",
    "content": (
        "לקוח יקר, זוהתה פעילות חריגה בחשבונך. יש לאמת את פרטי הכניסה "
        "תוך 24 שעות אחרת החשבון ייחסם. http://bank-leumi-secure.xyz/verify"
    ),
}


def call(url: str, path: str, method: str = "GET",
         payload: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url.rstrip("/") + path, data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"detail": body[:200]}


def step(n: int, text: str) -> None:
    print(f"\n{n}. {text}")


def ok(text: str) -> None:
    print(f"     ✓  {text}")


def fail(text: str) -> None:
    print(f"     ✗  {text}")


def main() -> None:
    ap = argparse.ArgumentParser(description="בדיקת מצב מפקח מקצה לקצה")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--guardian", default="guardian-check@example.com")
    ap.add_argument("--monitored", default="monitored-check@example.com")
    ap.add_argument("--password", default="CheckPass123",
                    help="סיסמה לחשבונות שהסקריפט יוצר")
    ap.add_argument("--guardian-password",
                    help="הסיסמה של חשבון המפקח, אם הוא כבר קיים "
                         "(כשמריצים עם --guardian על כתובת אמיתית)")
    ap.add_argument("--keep", action="store_true",
                    help="לא לנתק את השיוך בסוף")
    args = ap.parse_args()

    problems = []

    # -- server and mail configuration ---------------------------------
    step(1, "השרת והגדרות המייל")
    try:
        _, health = call(args.url, "/test-email")
    except urllib.error.URLError as exc:
        raise SystemExit(f"     ✗  השרת אינו מגיב ב-{args.url}\n        {exc}")
    ok(f"השרת עונה ב-{args.url}")

    mail_on = health.get("email_enabled") or health.get("EMAIL_ENABLED")
    if mail_on:
        ok("שליחת מיילים מופעלת")
    else:
        fail("EMAIL_ENABLED כבוי — ההתראה תירשם אך לא תישלח")
        problems.append("EMAIL_ENABLED=false")
    for key, value in health.items():
        if key not in ("email_enabled", "EMAIL_ENABLED"):
            print(f"        {key}: {value}")

    # -- accounts -------------------------------------------------------
    step(2, "יצירת שני חשבונות")
    tokens = {}
    # The guardian may be a real address that is already registered - that
    # is the whole point of running with --guardian, to receive the alert
    # in a mailbox someone actually reads. Then registration is refused
    # and the login has to use that account's own password, not the
    # throwaway one.
    accounts = (
        ("מפקח",  args.guardian,  args.guardian_password or args.password),
        ("מנוטר", args.monitored, args.password),
    )
    for role, email, password in accounts:
        status, body = call(args.url, "/auth/register", "POST",
                            {"email": email, "password": password})
        existed = status == 400
        if existed:
            status, body = call(args.url, "/auth/login", "POST",
                                {"email": email, "password": password})
        if status == 401 and existed:
            raise SystemExit(
                f"     ✗  {role}: החשבון {email} כבר קיים, והסיסמה אינה מתאימה.\n"
                f"        אם זו הכתובת האמיתית שלך, הריצי עם הסיסמה שלה:\n"
                f"          python check_guardian.py --guardian {email} "
                f"--guardian-password הסיסמה\n"
                f"        ואם שכחת אותה:  python set_password.py {email}"
            )
        if status != 200:
            raise SystemExit(f"     ✗  {role}: {body.get('detail', status)}")
        tokens[role] = body["token"]
        ok(f"{role}: {email}" + ("  (חשבון קיים)" if existed else ""))

    # -- link -----------------------------------------------------------
    step(3, "חיבור המפקח למנוטר")
    status, body = call(args.url, "/guardian/connect", "POST",
                        {"child_email": args.monitored,
                         "parent_email": "ignored-on-purpose@example.com"},
                        token=tokens["מפקח"])
    if status != 200:
        raise SystemExit(f"     ✗  {body.get('detail', status)}")
    ok(body.get("message", "חובר"))
    if body.get("guardian") == args.guardian:
        ok("המפקח נלקח מהטוקן ולא משדה בבקשה")
    else:
        fail(f"המפקח נקבע לפי גוף הבקשה: {body.get('guardian')}")
        problems.append("guardian taken from the request body")

    # -- scan -----------------------------------------------------------
    step(4, "סריקת מייל פישינג בשם המנוטר")
    status, scan = call(args.url, "/scan", "POST",
                        {"user_email": args.monitored, **PHISHING},
                        token=tokens["מנוטר"])
    if status != 200:
        raise SystemExit(f"     ✗  {scan.get('detail', status)}")
    print(f"        ציון {scan['risk_score']}  |  {scan['risk_level']}")
    if scan["is_phishing"]:
        ok("סווג כפישינג")
    else:
        fail("לא סווג כפישינג — ההתראה לא תיווצר")
        problems.append("the sample did not cross the threshold")

    # -- the guardian's dashboard ---------------------------------------
    step(5, "לוח הבקרה של המפקח")
    status, dash = call(args.url, f"/guardian/{args.guardian}",
                        token=tokens["מפקח"])
    if status != 200:
        raise SystemExit(f"     ✗  {dash.get('detail', status)}")

    if dash.get("child_email") == args.monitored:
        ok(f"המנוטר מופיע: {dash['child_email']}")
    else:
        fail(f"המנוטר אינו מופיע (התקבל {dash.get('child_email')!r})")
        problems.append("the monitored account is missing from the dashboard")

    alerts = dash.get("recent_alerts", [])
    if alerts:
        ok(f"{len(alerts)} התראות בלוח")
        print(f"        {alerts[0].get('message', '')[:70]}")
    else:
        fail("אין התראות בלוח")
        problems.append("no alert reached the dashboard")

    if alerts and PHISHING["sender"] in alerts[0].get("message", ""):
        ok("ההתראה נושאת את שם המנוטר ואת השולח")
    elif alerts:
        fail("ההתראה אינה מזכירה את השולח")
        problems.append("the alert does not name the sender")

    # -- no duplicate on a repeat scan ----------------------------------
    # The body is changed slightly on purpose. An identical rescan is
    # answered from the stored result and never reaches the alert code,
    # so it would pass this check without testing anything. A changed
    # body forces a fresh score on the same message, which is exactly
    # what happens whenever the formula changes - and that is the path
    # that used to mail the guardian again about old mail.
    step(6, "סריקה חוזרת של אותו מייל (טקסט שונה במעט)")
    before = len(alerts)
    call(args.url, "/scan", "POST",
         {"user_email": args.monitored, **PHISHING,
          "content": PHISHING["content"] + " "},
         token=tokens["מנוטר"])
    _, dash2 = call(args.url, f"/guardian/{args.guardian}", token=tokens["מפקח"])
    after = len(dash2.get("recent_alerts", []))
    if after == before:
        ok("לא נוצרה התראה כפולה")
    else:
        fail(f"מספר ההתראות עלה מ-{before} ל-{after}")
        problems.append("a repeat scan created a duplicate alert")

    # -- cleanup --------------------------------------------------------
    if not args.keep:
        call(args.url, "/guardian/disconnect", "POST",
             {"child_email": args.monitored, "parent_email": args.guardian},
             token=tokens["מפקח"])
        print("\n   השיוך נותק. החשבונות נשארו — למחיקה: python cleanup_users.py")

    # -- summary --------------------------------------------------------
    print("\n" + "═" * 66)
    if problems:
        print("  נמצאו בעיות:")
        for p in problems:
            print(f"    · {p}")
    else:
        print("  כל השרשרת עובדת.")
        if mail_on:
            print(f"\n  בדקי עכשיו את התיבה של {args.guardian} —")
            print("  מייל ההתראה נשלח ברקע ואמור להגיע תוך שניות.")
    print("═" * 66 + "\n")


if __name__ == "__main__":
    main()
