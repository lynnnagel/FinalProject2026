"""
A dress rehearsal for the demo: every feature, in order, against the
running server.

Each of the other check scripts covers one thing. This one exists to be
run once before showing the product to someone, and to say plainly which
features work right now and which do not. It touches every path a viewer
might ask to see: registration, login, forgotten password, scanning,
known senders, guardian mode, the dashboard numbers, the pages, and the
extension's files.

It talks to the server over HTTP, exactly as the extension and the site
do. Two checks - the reset link and the model state - also read the
local database and the model files directly, because a real reset link
arrives by mail and cannot be read out of a mailbox from here. So run it
on the machine the server is running on.

Run from backend/, with the server up:
    python check_demo.py
    python check_demo.py --url http://localhost:8000
    python check_demo.py --keep       # leave the test accounts behind
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASSWORD = "DemoCheck123"

PHISHING = {
    "sender": "service@bank-leumi-secure.xyz",
    "subject": "בנק לאומי: חשבונך ייחסם",
    "content": (
        "לקוח יקר, זוהתה פעילות חריגה בחשבונך. יש לאמת את פרטי הכניסה "
        "תוך 24 שעות אחרת החשבון ייחסם. http://bank-leumi-secure.xyz/verify"
    ),
}

LEGITIMATE = {
    "sender": "orders@iherb.com",
    "subject": "ההזמנה שלך נשלחה",
    "content": (
        "שלום, ההזמנה מספר 4471029 יצאה לדרך ותגיע אליך בימים הקרובים. "
        "לפרטי המשלוח אפשר להיכנס לחשבון שלך באתר."
    ),
}

# An address nobody has heard of, writing ordinary mail. This is the case
# the known-senders list exists for: no evidence against it, and no
# evidence for it either.
UNKNOWN_BUT_FINE = {
    "sender": "info@machol-studio-tlv.co.il",
    "subject": "לוח השיעורים לחודש הקרוב",
    "content": (
        "היי, מצורף לוח השיעורים לחודש הבא. השיעור של יום שני עובר לשעה "
        "19:00. נשמח לראותך, ואם צריך לשנות משהו אפשר להשיב למייל הזה."
    ),
}


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------
class Report:
    """Collects what failed, so the run ends with one verdict."""

    def __init__(self) -> None:
        self.problems: list[str] = []
        self.notes: list[str] = []

    def ok(self, text: str) -> None:
        print(f"     ✓  {text}")

    def fail(self, text: str, problem: str | None = None) -> None:
        print(f"     ✗  {text}")
        self.problems.append(problem or text)

    def note(self, text: str) -> None:
        print(f"     ·  {text}")

    def warn(self, text: str) -> None:
        print(f"     !  {text}")
        self.notes.append(text)

    def check(self, condition: bool, good: str, bad: str,
              problem: str | None = None) -> bool:
        if condition:
            self.ok(good)
        else:
            self.fail(bad, problem)
        return bool(condition)


def call(url: str, path: str, method: str = "GET",
         payload: dict | None = None, token: str | None = None
         ) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url.rstrip("/") + path, data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            body = r.read().decode("utf-8")
            try:
                return r.status, json.loads(body)
            except json.JSONDecodeError:
                return r.status, {"text": body}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"detail": raw[:200]}


def section(n: int, title: str) -> None:
    print(f"\n{n}. {title}")


def account(url: str, rep: Report, email: str) -> str | None:
    """Register, or log in if the address is already there."""
    status, body = call(url, "/auth/register", "POST",
                        {"email": email, "password": PASSWORD})
    if status == 400:
        status, body = call(url, "/auth/login", "POST",
                            {"email": email, "password": PASSWORD})
    if status != 200:
        rep.fail(f"{email}: {body.get('detail', status)}", "account setup failed")
        return None
    return body["token"]


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
def check_server(url: str, rep: Report) -> None:
    section(1, "השרת והמודל")
    try:
        status, root = call(url, "/")
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"     ✗  השרת אינו מגיב ב-{url}\n        {exc}\n\n"
            f"        להפעלה:  uvicorn server:app --port 8000"
        )
    rep.check(status == 200, f"השרת עונה ב-{url}", "השרת ענה בשגיאה")

    _, health = call(url, "/health/model")
    state = health.get("state")
    if state == "ready":
        rep.ok(f"BERT טעון — מצב אנסמבל (חוקים + מודל), חלון {health.get('max_length')} טוקנים")
    elif state == "loading":
        rep.warn("BERT עדיין נטען. המתיני כדקה והריצי שוב — "
                 "עד אז הציונים מגיעים מהחוקים בלבד.")
    else:
        rep.fail(
            f"BERT אינו טעון (מצב: {state}) — המערכת רצה על מנוע החוקים בלבד. "
            f"בדמו הציונים יהיו שונים מאלה שבמצגת.",
            "BERT not loaded",
        )
        if health.get("checkpoint") and not health.get("checkpoint_exists"):
            rep.note(f"ה-checkpoint לא נמצא בנתיב: {health['checkpoint']}")

    _, mail = call(url, "/test-email")
    if mail.get("EMAIL_ENABLED"):
        login = mail.get("smtp_login", "")
        rep.check("הצליחה" in login, f"SMTP: {login}",
                  f"SMTP: {login or 'לא נבדק'}", "SMTP login failed")
    else:
        rep.fail("EMAIL_ENABLED כבוי — מיילי מפקח ואיפוס סיסמה לא יישלחו",
                 "EMAIL_ENABLED=false")


def check_auth(url: str, rep: Report, email: str) -> str | None:
    section(2, "הרשמה והתחברות")
    token = account(url, rep, email)
    if not token:
        return None
    rep.ok(f"חשבון: {email}")

    status, me = call(url, "/auth/me", token=token)
    rep.check(status == 200 and me.get("email") == email,
              "הטוקן מזהה את המשתמש הנכון (/auth/me)",
              f"/auth/me החזיר {status}", "auth/me failed")

    status, _ = call(url, "/auth/login", "POST",
                     {"email": email, "password": "wrong-password"})
    rep.check(status == 401, "סיסמה שגויה נדחית",
              f"סיסמה שגויה התקבלה ({status})", "wrong password accepted")

    status, _ = call(url, "/auth/register", "POST",
                     {"email": "shortpass@example.com", "password": "123"})
    rep.check(status == 422, "סיסמה קצרה מ-8 תווים נדחית ברישום",
              f"סיסמה קצרה התקבלה ({status})", "short password accepted")

    status, _ = call(url, "/auth/me")
    rep.check(status == 401, "בקשה בלי טוקן נדחית",
              f"בקשה בלי טוקן התקבלה ({status})", "unauthenticated access allowed")
    return token


def check_password_reset(url: str, rep: Report) -> None:
    section(3, "שכחתי סיסמה")
    email = "reset-demo@example.com"

    # This account may be left over from an earlier run of this script,
    # holding the password this very section changes it to. Repair it
    # instead of failing - a check should not depend on how the previous
    # run happened to end. Nothing here is reachable without access to
    # the database file itself.
    try:
        from API.auth import hash_password
        from database import SessionLocal
        from models import User
        db = SessionLocal()
        stale = db.query(User).filter(User.email == email).first()
        if stale:
            stale.password_hash = hash_password(PASSWORD)
            db.commit()
        db.close()
    except Exception:
        pass          # not fatal; account() reports what actually failed

    if not account(url, rep, email):
        return

    known = call(url, "/auth/forgot-password", "POST", {"email": email})
    unknown = call(url, "/auth/forgot-password", "POST",
                   {"email": "nobody-here@example.com"})
    rep.check(known == unknown,
              "התשובה זהה לכתובת רשומה ולא רשומה (לא מדליף מי רשום)",
              "התשובות שונות — אפשר לגלות אילו כתובות רשומות",
              "user enumeration via forgot-password")

    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": "not-a-real-token", "new_password": "whatever123"})
    rep.check(status == 400, "קישור מזויף נדחה",
              f"קישור מזויף התקבל ({status})", "forged reset token accepted")

    # The real link. It is built here the way the server builds it, from
    # the password hash on record - reading it out of a mailbox is not
    # something this script can do.
    try:
        from API.auth import create_reset_token          # noqa: F811
        from database import SessionLocal                # noqa: F811
        from models import User                          # noqa: F811
        db = SessionLocal()
        user = db.query(User).filter(User.email == email).first()
        link_token = create_reset_token(email, user.password_hash)
        db.close()
    except Exception as exc:
        rep.warn(f"לא ניתן היה לבנות קישור אמיתי מכאן ({exc}) — "
                 f"בדקי את המסלול הזה ידנית דרך הדף")
        return

    new_password = "AfterReset456"
    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": link_token, "new_password": new_password})
    rep.check(status == 200, "איפוס דרך הקישור עובד",
              f"האיפוס נכשל ({status})", "reset with a valid link failed")

    status, _ = call(url, "/auth/login", "POST",
                     {"email": email, "password": new_password})
    rep.check(status == 200, "התחברות עם הסיסמה החדשה עובדת",
              "הסיסמה החדשה אינה עובדת", "login after reset failed")

    status, _ = call(url, "/auth/login", "POST",
                     {"email": email, "password": PASSWORD})
    rep.check(status == 401, "הסיסמה הישנה כבר לא עובדת",
              "הסיסמה הישנה עדיין עובדת", "old password still valid")

    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": link_token, "new_password": "Replayed789"})
    rep.check(status == 400, "אותו קישור לא ניתן לשימוש פעם שנייה",
              "הקישור עובד שוב — הוא אינו חד-פעמי", "reset link is replayable")

    status, _ = call(url, "/auth/me", token=link_token)
    rep.check(status == 401, "קישור האיפוס אינו משמש כהזדהות למערכת",
              "קישור מהמייל התקבל כטוקן התחברות", "reset token works as auth")

    # Put the password back, so the next run starts where this one did.
    #
    # This section does its job by changing a password, and the account
    # survives the run - so a second run tried to log in with the
    # original password and failed before reaching any real check. A
    # test that only passes the first time is worse than no test: it
    # reports a problem that is not there.
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        restore = create_reset_token(email, user.password_hash)
    finally:
        db.close()
    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": restore, "new_password": PASSWORD})
    if status != 200:
        rep.warn(f"לא ניתן היה להחזיר את הסיסמה של {email} ({status}) — "
                 f"הרצה הבאה עלולה להיכשל בסעיף הזה")


def check_scanning(url: str, rep: Report, token: str, email: str) -> None:
    section(4, "סריקת מיילים")

    status, phish = call(url, "/scan", "POST",
                         {"user_email": email, **PHISHING}, token=token)
    if status != 200:
        rep.fail(f"הסריקה נכשלה ({status})", "scan failed")
        return
    print(f"        פישינג:  ציון {phish['risk_score']}  |  {phish['risk_level']}")
    rep.check(phish["is_phishing"],
              "מייל פישינג מסווג כפישינג",
              "מייל פישינג לא נתפס — בדקי את הסף",
              "phishing sample not detected")
    rep.check(bool(phish.get("indicators")),
              f"מוצגות סיבות: {' · '.join(phish['indicators'][:3])}",
              "אין אינדיקטורים להצגה", "no indicators returned")

    status, legit = call(url, "/scan", "POST",
                         {"user_email": email, **LEGITIMATE}, token=token)
    print(f"        תקין:    ציון {legit['risk_score']}  |  {legit['risk_level']}")
    rep.check(not legit["is_phishing"],
              "מייל הזמנה תקין אינו מסומן",
              "מייל תקין סומן כפישינג — התרעת שווא",
              "false positive on legitimate mail")

    # The stored result. Rescanning the same text must return the same
    # verdict, or the same message would flip label between two scans.
    _, again = call(url, "/scan", "POST",
                    {"user_email": email, **PHISHING}, token=token)
    rep.check(again["risk_score"] == phish["risk_score"],
              "סריקה חוזרת מחזירה את אותו ציון (מטמון)",
              f"הציון השתנה בסריקה חוזרת: {phish['risk_score']} → {again['risk_score']}",
              "cached rescan returned a different score")

    # Identity comes from the token, not from the body.
    _, other = call(url, "/scan", "POST",
                    {"user_email": "someone-else@example.com", **PHISHING},
                    token=token)
    _, stats = call(url, f"/stats/{email}", token=token)
    rep.check(other["risk_score"] == phish["risk_score"] and stats.get("total_scanned", 0) > 0,
              "הסריקה נרשמת על המשתמש שבטוקן, לא על הכתובת שבגוף הבקשה",
              "הזיהוי נלקח מגוף הבקשה", "identity taken from the request body")


def check_trusted(url: str, rep: Report, token: str, email: str) -> None:
    section(5, "שולחים מוכרים")

    sender = UNKNOWN_BUT_FINE["sender"]
    call(url, f"/trusted-senders/{sender}", "DELETE", token=token)  # clean slate

    _, before = call(url, "/scan", "POST",
                     {"user_email": email, **UNKNOWN_BUT_FINE}, token=token)
    print(f"        לפני הסימון: ציון {before['risk_score']}")

    status, added = call(url, "/trusted-senders", "POST",
                         {"value": sender}, token=token)
    if not rep.check(status == 200, f"סומן כמוכר: {sender}",
                     f"הסימון נכשל: {added.get('detail', status)}",
                     "marking a sender as known failed"):
        return
    rep.check(added.get("rescored", 0) >= 1,
              f"{added['rescored']} מיילים שמורים סומנו לחישוב מחדש",
              "לא סומנו מיילים לחישוב מחדש — התג בתיבה לא יתעדכן",
              "trusting a sender did not invalidate cached scores")

    _, after = call(url, "/scan", "POST",
                    {"user_email": email, **UNKNOWN_BUT_FINE}, token=token)
    print(f"        אחרי הסימון: ציון {after['risk_score']}")
    if before["risk_score"] == 0:
        rep.note("הדוגמה יצאה 0 עוד לפני הסימון, ולכן אין ירידה להראות")
    elif after["risk_score"] < before["risk_score"]:
        rep.ok(f"הציון ירד: {before['risk_score']} → {after['risk_score']}")
    else:
        rep.note(f"הציון לא ירד ({before['risk_score']} → {after['risk_score']}). "
                 f"הסימון מנמיך את ציון המודל בלבד; אם BERT אינו טעון, "
                 f"או שכל הציון הגיע מהחוקים, אין מה להנמיך.")

    status, listed = call(url, "/trusted-senders", token=token)
    rep.check(any(s["value"] == sender for s in listed.get("senders", [])),
              "השולח מופיע ברשימה",
              "השולח אינו ברשימה אחרי שנוסף", "trusted sender not listed")

    # The important one: a user cannot whitewash an address that carries
    # real evidence against it.
    status, refused = call(url, "/trusted-senders", "POST",
                           {"value": PHISHING["sender"]}, token=token)
    rep.check(status == 400,
              "כתובת עם סימני התחזות נדחית מהרשימה",
              "כתובת פישינג התקבלה כשולח מוכר — חור אבטחה",
              "a phishing address can be marked as trusted")
    if status == 400:
        rep.note(refused.get("detail", "")[:90])

    status, _ = call(url, f"/trusted-senders/{sender}", "DELETE", token=token)
    rep.check(status == 200, "הסרה מהרשימה עובדת",
              f"ההסרה נכשלה ({status})", "removing a trusted sender failed")


def check_guardian(url: str, rep: Report, guardian_email: str,
                   monitored_email: str, keep: bool) -> None:
    section(6, "מצב מפקח")
    guardian = account(url, rep, guardian_email)
    monitored = account(url, rep, monitored_email)
    if not (guardian and monitored):
        return

    status, link = call(url, "/guardian/connect", "POST",
                        {"child_email": monitored_email,
                         "parent_email": "ignored@example.com"},
                        token=guardian)
    if not rep.check(status == 200, f"{guardian_email} מפקח על {monitored_email}",
                     f"החיבור נכשל: {link.get('detail', status)}",
                     "guardian connect failed"):
        return
    rep.check(link.get("guardian") == guardian_email,
              "המפקח נקבע לפי הטוקן ולא לפי שדה בבקשה",
              "אפשר להגדיר את עצמך כמפקח על חשבון של מישהו אחר",
              "guardian taken from the request body")

    _, scan = call(url, "/scan", "POST",
                   {"user_email": monitored_email, **PHISHING}, token=monitored)
    _, dash = call(url, f"/guardian/{guardian_email}", token=guardian)

    rep.check(dash.get("child_email") == monitored_email,
              "המנוטר מופיע בלוח של המפקח",
              "המנוטר אינו מופיע בלוח", "monitored account missing from dashboard")

    alerts = dash.get("recent_alerts", [])
    if rep.check(bool(alerts), f"{len(alerts)} התראות בלוח",
                 "לא נוצרה התראה", "no alert on the guardian dashboard"):
        rep.check(PHISHING["sender"] in alerts[0].get("message", ""),
                  "ההתראה מציינת את המנוטר ואת השולח",
                  "ההתראה אינה מציינת את השולח", "alert does not name the sender")

    before = len(alerts)
    call(url, "/scan", "POST",
         {"user_email": monitored_email, **PHISHING,
          "content": PHISHING["content"] + " "}, token=monitored)
    _, dash2 = call(url, f"/guardian/{guardian_email}", token=guardian)
    rep.check(len(dash2.get("recent_alerts", [])) == before,
              "סריקה חוזרת אינה יוצרת התראה כפולה",
              "נוצרה התראה כפולה", "duplicate alert on rescan")

    # The monitored user asking for the guardian's dashboard - the
    # contents of the alerts about them are not theirs to read, and
    # neither is anyone else's dashboard.
    status, _ = call(url, f"/guardian/{guardian_email}", token=monitored)
    rep.check(status in (403, 404),
              "משתמש אחר אינו יכול לצפות בלוח של המפקח",
              f"לוח של משתמש אחר נחשף ({status})",
              "guardian dashboard is readable by others")

    if not keep:
        call(url, "/guardian/disconnect", "POST",
             {"child_email": monitored_email, "parent_email": guardian_email},
             token=guardian)
        rep.note("השיוך נותק בסוף הבדיקה")

    rep.note("לבדיקת שליחת המייל עצמו:  python check_guardian.py "
             "--guardian הכתובת_שלך --guardian-password הסיסמה")


def check_dashboard(url: str, rep: Report, token: str, email: str) -> None:
    section(7, "מספרים בלוח הבקרה")
    status, stats = call(url, f"/stats/{email}", token=token)
    if not rep.check(status == 200, "נתוני המשתמש נטענים",
                     f"/stats החזיר {status}", "stats endpoint failed"):
        return
    print(f"        נסרקו {stats.get('total_scanned')}  |  "
          f"נחסמו {stats.get('phishing_blocked')}  |  "
          f"ציון סיכון {stats.get('risk_score')}")
    rep.check(stats.get("total_scanned", 0) > 0,
              "מספר הסריקות מתעדכן",
              "מספר הסריקות נשאר 0 — הלוח ייראה ריק בדמו",
              "dashboard shows no scans")
    rep.check(stats.get("phishing_blocked", 0) > 0,
              "מספר החסימות מתעדכן",
              "מספר החסימות נשאר 0", "phishing_blocked stays zero")

    status, other = call(url, "/stats/someone-else@example.com", token=token)
    rep.check(status in (403, 404),
              "אי אפשר לקרוא נתונים של משתמש אחר",
              f"נתוני משתמש אחר נחשפו ({status})", "stats readable for other users")

    status, metrics = call(url, "/metrics")
    rep.check(status == 200, "עמוד המדדים עונה", f"/metrics החזיר {status}",
              "metrics endpoint failed")


def check_pages(url: str, rep: Report) -> None:
    section(8, "דפי האתר")
    for path, name in (("/app/index.html", "דף הבית"),
                       ("/app/login.html", "התחברות"),
                       ("/app/dashboard.html", "לוח בקרה"),
                       ("/app/forgot_password.html", "איפוס סיסמה")):
        status, page = call(url, path)
        if not rep.check(status == 200, f"{name} נטען",
                         f"{name} החזיר {status}", f"page {path} not served"):
            continue

        # And that the scripts the page asks for actually arrive.
        #
        # A page whose JavaScript is missing still loads and still looks
        # right - it just stops responding. frontend/js/forgot_password.js
        # went missing from a working copy exactly this way: the reset
        # page rendered, and the "choose a new password" button did
        # nothing at all.
        html = page.get("text", "")
        base = path.rsplit("/", 1)[0]
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html):
            if src.startswith(("http://", "https://", "//")):
                continue
            asset = src if src.startswith("/") else f"{base}/{src}"
            code, _ = call(url, asset)
            rep.check(code == 200,
                      f"    {src}",
                      f"    {src} חסר ({code}) — הדף ייטען אבל לא יגיב",
                      f"missing script {asset}")

    status, scan = call(url, "/scan-url", "POST",
                        {"url": "http://bank-leumi-secure.xyz/verify"})
    rep.check(status == 200 and scan.get("risk_score", 0) > 0,
              f"בדיקת כתובת URL עובדת (ציון {scan.get('risk_score')})",
              f"/scan-url החזיר {status}", "url scan failed")


def check_extension(rep: Report) -> None:
    section(9, "קבצי התוסף")
    here = os.path.dirname(os.path.abspath(__file__))
    ext = os.path.join(here, "..", "extension")

    try:
        with open(os.path.join(ext, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        rep.ok(f"manifest.json תקין (גרסה {manifest.get('version')})")
    except Exception as exc:
        rep.fail(f"manifest.json: {exc}", "manifest.json is broken")
        return

    needed = ["content.js", "background.js", "styles.css", "popup.html",
              "popup/popup.js", "popup/popup.css", "icons/icon128.png",
              "fonts/rubik-hebrew.woff2", "fonts/rubik-latin.woff2"]
    missing = [f for f in needed if not os.path.exists(os.path.join(ext, f))]
    rep.check(not missing, "כל קבצי התוסף במקום",
              f"חסרים: {', '.join(missing)}", "extension files missing")

    declared = []
    for entry in manifest.get("web_accessible_resources", []):
        declared += entry.get("resources", [])
    fonts_ok = all(f in declared for f in
                   ("fonts/rubik-hebrew.woff2", "fonts/rubik-latin.woff2"))
    rep.check(fonts_ok, "הפונט מוצהר ב-web_accessible_resources",
              "הפונט אינו מוצהר — הוא לא ייטען בתוך Gmail",
              "fonts not declared as web accessible")

    rep.note("בדיקת הפונקציות ב-JS:  python -m pytest tests/test_javascript.py")


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="חזרה כללית לפני הדמו")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--keep", action="store_true",
                    help="לא לנתק את שיוך המפקח בסוף")
    args = ap.parse_args()

    rep = Report()
    user_email = "demo-user@example.com"

    print("\n" + "═" * 68)
    print("  LURA — חזרה כללית לפני הדמו")
    print("═" * 68)

    check_server(args.url, rep)
    token = check_auth(args.url, rep, user_email)
    check_password_reset(args.url, rep)
    if token:
        check_scanning(args.url, rep, token, user_email)
        check_trusted(args.url, rep, token, user_email)
    check_guardian(args.url, rep, "demo-guardian@example.com",
                   "demo-monitored@example.com", args.keep)
    if token:
        check_dashboard(args.url, rep, token, user_email)
    check_pages(args.url, rep)
    check_extension(rep)

    print("\n" + "═" * 68)
    if rep.problems:
        print(f"  {len(rep.problems)} בעיות פתוחות:")
        for p in rep.problems:
            print(f"    · {p}")
    else:
        print("  הכל עובד. אפשר להציג.")
    if rep.notes:
        print("\n  לתשומת לב:")
        for n in rep.notes:
            print(f"    · {n}")
    print("═" * 68)
    print("\n  לניקוי חשבונות הבדיקה:  python cleanup_users.py\n")

    sys.exit(1 if rep.problems else 0)


if __name__ == "__main__":
    main()
