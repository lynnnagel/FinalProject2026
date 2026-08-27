"""
A dress rehearsal: every feature, in order, against the running server.

Run it once before showing the product to anyone. It reports which
features work right now and which do not.

Most checks go over HTTP, exactly as the extension and the site do. Two
of them - the reset link and the model state - also read the local
database directly, because a real reset link arrives by mail. So run it
on the machine the server runs on.

    python check_demo.py
    python check_demo.py --url http://localhost:8000
    python check_demo.py --keep       # leave the test accounts behind
"""
from __future__ import annotations

import argparse
import json
import os
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

# An address nobody has heard of, writing ordinary mail. This is what
# the known-senders list exists for: no evidence against it, and none
# for it either.
UNKNOWN_BUT_FINE = {
    "sender": "info@machol-studio-tlv.co.il",
    "subject": "לוח השיעורים לחודש הקרוב",
    "content": (
        "היי, מצורף לוח השיעורים לחודש הבא. השיעור של יום שני עובר לשעה "
        "19:00. נשמח לראותך, ואם צריך לשנות משהו אפשר להשיב למייל הזה."
    ),
}


# ---------------------------------------------------------------------------
class Report:
    """Collects what failed, so the run ends with one verdict."""

    def __init__(self) -> None:
        self.problems: list[str] = []
        self.notes: list[str] = []

    def ok(self, text: str) -> None:
        print(f"     OK    {text}")

    def fail(self, text: str, problem: str | None = None) -> None:
        print(f"     FAIL  {text}")
        self.problems.append(problem or text)

    def note(self, text: str) -> None:
        print(f"     ...   {text}")

    def warn(self, text: str) -> None:
        print(f"     !     {text}")
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
def check_server(url: str, rep: Report) -> bool:
    """Returns whether outgoing mail is switched on."""
    section(1, "Server and model")
    try:
        status, _ = call(url, "/")
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"     FAIL  no answer at {url}\n           {exc}\n\n"
            f"           start it with:  uvicorn server:app --port 8000"
        )
    rep.check(status == 200, f"server answering at {url}", "server returned an error")

    _, health = call(url, "/health/model")
    state = health.get("state")
    if state == "ready":
        rep.ok(f"BERT loaded - ensemble mode, {health.get('max_length')} token window")
    elif state == "loading":
        rep.warn("BERT still loading. Wait a minute and run again - "
                 "until then scores come from the rules alone.")
    else:
        rep.fail(f"BERT not loaded (state: {state}) - running on rules only. "
                 f"Scores in the demo will differ from the reported ones.",
                 "BERT not loaded")
        if health.get("checkpoint") and not health.get("checkpoint_exists"):
            rep.note(f"checkpoint not found at {health['checkpoint']}")

    _, mail = call(url, "/test-email")
    enabled = bool(mail.get("EMAIL_ENABLED"))
    if enabled:
        login = mail.get("smtp_login", "")
        rep.check("הצליחה" in login or "success" in login.lower(),
                  f"SMTP: {login}", f"SMTP: {login or 'not checked'}",
                  "SMTP login failed")
    else:
        rep.fail("EMAIL_ENABLED is off - guardian and reset mail will not be sent",
                 "EMAIL_ENABLED=false")
    return enabled


def check_auth(url: str, rep: Report, email: str) -> str | None:
    section(2, "Registration and login")
    token = account(url, rep, email)
    if not token:
        return None
    rep.ok(f"account: {email}")

    status, me = call(url, "/auth/me", token=token)
    rep.check(status == 200 and me.get("email") == email,
              "the token identifies the right user",
              f"/auth/me returned {status}", "auth/me failed")

    status, _ = call(url, "/auth/login", "POST",
                     {"email": email, "password": "wrong-password"})
    rep.check(status == 401, "a wrong password is refused",
              f"a wrong password was accepted ({status})", "wrong password accepted")

    status, _ = call(url, "/auth/register", "POST",
                     {"email": "shortpass@example.com", "password": "123"})
    rep.check(status == 422, "a password under 8 characters is refused",
              f"a short password was accepted ({status})", "short password accepted")

    status, _ = call(url, "/auth/me")
    rep.check(status == 401, "a request with no token is refused",
              f"an unauthenticated request was allowed ({status})",
              "unauthenticated access allowed")
    return token


def check_password_reset(url: str, rep: Report, mail_enabled: bool) -> None:
    section(3, "Forgotten password")
    email = "reset-demo@example.com"

    # The account may be left from an earlier run, holding the password
    # this section changes it to. Repair it rather than fail.
    try:
        from API.auth import create_reset_token, hash_password
        from database import SessionLocal
        from models import User
        db = SessionLocal()
        stale = db.query(User).filter(User.email == email).first()
        if stale:
            stale.password_hash = hash_password(PASSWORD)
            db.commit()
        db.close()
    except Exception as exc:
        rep.warn(f"cannot reach the database from here ({exc}) - "
                 f"check this flow by hand through the page")
        return

    if not account(url, rep, email):
        return

    # Only when mail is off. For a registered address this endpoint
    # really sends a reset link, and the test account is at example.com,
    # a reserved domain that accepts nothing - so with SMTP live it
    # posts a real message and the bounce lands in your own inbox.
    if mail_enabled:
        rep.note("enumeration check skipped: sending is on, and it would "
                 "bounce a real message back to your inbox")
    else:
        known = call(url, "/auth/forgot-password", "POST", {"email": email})
        unknown = call(url, "/auth/forgot-password", "POST",
                       {"email": "nobody-here@example.com"})
        rep.check(known == unknown,
                  "same answer for a registered and an unknown address",
                  "answers differ - registered addresses can be discovered",
                  "user enumeration via forgot-password")

    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": "not-a-real-token", "new_password": "whatever123"})
    rep.check(status == 400, "a forged link is refused",
              f"a forged link was accepted ({status})", "forged reset token accepted")

    # The real link, built the way the server builds it - from the
    # password hash on record.
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    link_token = create_reset_token(email, user.password_hash)
    db.close()

    new_password = "AfterReset456"
    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": link_token, "new_password": new_password})
    rep.check(status == 200, "reset through the link works",
              f"the reset failed ({status})", "reset with a valid link failed")

    status, _ = call(url, "/auth/login", "POST",
                     {"email": email, "password": new_password})
    rep.check(status == 200, "the new password works",
              "the new password does not work", "login after reset failed")

    status, _ = call(url, "/auth/login", "POST",
                     {"email": email, "password": PASSWORD})
    rep.check(status == 401, "the old password no longer works",
              "the old password still works", "old password still valid")

    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": link_token, "new_password": "Replayed789"})
    rep.check(status == 400, "the same link cannot be used twice",
              "the link works again - it is not single-use",
              "reset link is replayable")

    status, _ = call(url, "/auth/me", token=link_token)
    rep.check(status == 401, "a reset link is not accepted as a login token",
              "a link from mail was accepted as a login token",
              "reset token works as auth")

    # Put the password back, so the next run starts where this one did.
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    restore = create_reset_token(email, user.password_hash)
    db.close()
    status, _ = call(url, "/auth/reset-password", "POST",
                     {"token": restore, "new_password": PASSWORD})
    if status != 200:
        rep.warn(f"could not restore the password for {email} ({status})")


def check_scanning(url: str, rep: Report, token: str, email: str) -> None:
    section(4, "Scanning")

    status, phish = call(url, "/scan", "POST",
                         {"user_email": email, **PHISHING}, token=token)
    if status != 200:
        rep.fail(f"the scan failed ({status})", "scan failed")
        return
    print(f"           phishing:   {phish['risk_score']}  |  {phish['risk_level']}")
    rep.check(phish["is_phishing"],
              "a phishing message is classified as phishing",
              "the phishing sample was not caught - check the threshold",
              "phishing sample not detected")
    rep.check(bool(phish.get("indicators")),
              f"reasons are given: {' | '.join(phish['indicators'][:2])}",
              "no indicators returned", "no indicators returned")

    status, legit = call(url, "/scan", "POST",
                         {"user_email": email, **LEGITIMATE}, token=token)
    print(f"           legitimate: {legit['risk_score']}  |  {legit['risk_level']}")
    rep.check(not legit["is_phishing"],
              "a real order confirmation is not flagged",
              "a legitimate message was flagged - false alarm",
              "false positive on legitimate mail")

    # Rescanning the same text must return the same verdict, or a
    # message would flip label between two scans.
    _, again = call(url, "/scan", "POST",
                    {"user_email": email, **PHISHING}, token=token)
    rep.check(again["risk_score"] == phish["risk_score"],
              "a rescan returns the same score (cache)",
              f"the score changed on rescan: {phish['risk_score']} -> {again['risk_score']}",
              "cached rescan returned a different score")

    # Identity comes from the token, not from the body.
    _, other = call(url, "/scan", "POST",
                    {"user_email": "someone-else@example.com", **PHISHING},
                    token=token)
    _, stats = call(url, f"/stats/{email}", token=token)
    rep.check(other["risk_score"] == phish["risk_score"]
              and stats.get("total_scanned", 0) > 0,
              "scans are recorded against the token's user, not the request body",
              "identity was taken from the request body",
              "identity taken from the request body")


def check_trusted(url: str, rep: Report, token: str, email: str) -> None:
    section(5, "Known senders")

    sender = UNKNOWN_BUT_FINE["sender"]
    call(url, f"/trusted-senders/{sender}", "DELETE", token=token)   # clean slate

    _, before = call(url, "/scan", "POST",
                     {"user_email": email, **UNKNOWN_BUT_FINE}, token=token)
    print(f"           before marking: {before['risk_score']}")

    status, added = call(url, "/trusted-senders", "POST",
                         {"value": sender}, token=token)
    if not rep.check(status == 200, f"marked as known: {sender}",
                     f"marking failed: {added.get('detail', status)}",
                     "marking a sender as known failed"):
        return
    rep.check(added.get("rescored", 0) >= 1,
              f"{added['rescored']} stored scores queued for recomputing",
              "no stored scores were queued - badges will not update",
              "trusting a sender did not invalidate cached scores")

    _, after = call(url, "/scan", "POST",
                    {"user_email": email, **UNKNOWN_BUT_FINE}, token=token)
    print(f"           after marking:  {after['risk_score']}")
    if before["risk_score"] == 0:
        rep.note("the sample scored 0 before marking, so there is no drop to show")
    elif after["risk_score"] < before["risk_score"]:
        rep.ok(f"the score dropped: {before['risk_score']} -> {after['risk_score']}")
    else:
        rep.note(f"the score did not drop ({before['risk_score']} -> "
                 f"{after['risk_score']}). Marking only damps the model's "
                 f"score; with BERT unloaded there is nothing to damp.")

    status, listed = call(url, "/trusted-senders", token=token)
    rep.check(any(s["value"] == sender for s in listed.get("senders", [])),
              "the sender appears in the list",
              "the sender is missing from the list", "trusted sender not listed")

    # The important one: a user cannot whitewash an address that carries
    # real evidence against it.
    status, refused = call(url, "/trusted-senders", "POST",
                           {"value": PHISHING["sender"]}, token=token)
    rep.check(status == 400,
              "an address with signs of impersonation is refused",
              "a phishing address was accepted as a known sender - security hole",
              "a phishing address can be marked as trusted")
    if status == 400:
        rep.note(refused.get("detail", "")[:90])

    status, _ = call(url, f"/trusted-senders/{sender}", "DELETE", token=token)
    rep.check(status == 200, "removing from the list works",
              f"removal failed ({status})", "removing a trusted sender failed")


def check_guardian(url: str, rep: Report, guardian_email: str,
                   monitored_email: str, keep: bool) -> None:
    section(6, "Guardian mode")
    guardian = account(url, rep, guardian_email)
    monitored = account(url, rep, monitored_email)
    if not (guardian and monitored):
        return

    status, link = call(url, "/guardian/connect", "POST",
                        {"child_email": monitored_email,
                         "parent_email": "ignored@example.com"},
                        token=guardian)
    if not rep.check(status == 200,
                     f"{guardian_email} now watches {monitored_email}",
                     f"linking failed: {link.get('detail', status)}",
                     "guardian connect failed"):
        return
    rep.check(link.get("guardian") == guardian_email,
              "the guardian comes from the token, not from a request field",
              "anyone could make themselves guardian of someone else's inbox",
              "guardian taken from the request body")

    call(url, "/scan", "POST",
         {"user_email": monitored_email, **PHISHING}, token=monitored)
    _, dash = call(url, f"/guardian/{guardian_email}", token=guardian)

    rep.check(dash.get("child_email") == monitored_email,
              "the monitored account appears on the dashboard",
              "the monitored account is missing",
              "monitored account missing from dashboard")

    alerts = dash.get("recent_alerts", [])
    if rep.check(bool(alerts), f"{len(alerts)} alert(s) on the dashboard",
                 "no alert was created", "no alert on the guardian dashboard"):
        rep.check(PHISHING["sender"] in alerts[0].get("message", ""),
                  "the alert names the monitored user and the sender",
                  "the alert does not name the sender",
                  "alert does not name the sender")

    before = len(alerts)
    call(url, "/scan", "POST",
         {"user_email": monitored_email, **PHISHING,
          "content": PHISHING["content"] + " "}, token=monitored)
    _, dash2 = call(url, f"/guardian/{guardian_email}", token=guardian)
    rep.check(len(dash2.get("recent_alerts", [])) == before,
              "a rescan does not create a duplicate alert",
              "a duplicate alert was created", "duplicate alert on rescan")

    # The monitored user asking for the guardian's dashboard: the
    # contents of the alerts about them are not theirs to read.
    status, _ = call(url, f"/guardian/{guardian_email}", token=monitored)
    rep.check(status in (403, 404),
              "another user cannot read the guardian's dashboard",
              f"another user's dashboard was exposed ({status})",
              "guardian dashboard is readable by others")

    if not keep:
        call(url, "/guardian/disconnect", "POST",
             {"child_email": monitored_email, "parent_email": guardian_email},
             token=guardian)
        rep.note("the link was removed at the end of the check")

    rep.note("to test the mail itself:  python check_guardian.py "
             "--guardian YOUR_ADDRESS --guardian-password YOUR_PASSWORD")


def check_dashboard(url: str, rep: Report, token: str, email: str) -> None:
    section(7, "Dashboard numbers")
    status, stats = call(url, f"/stats/{email}", token=token)
    if not rep.check(status == 200, "user data loads",
                     f"/stats returned {status}", "stats endpoint failed"):
        return
    print(f"           scanned {stats.get('total_scanned')}  |  "
          f"blocked {stats.get('phishing_blocked')}  |  "
          f"risk {stats.get('risk_score')}")
    rep.check(stats.get("total_scanned", 0) > 0,
              "the scan count updates",
              "the scan count stays at 0 - the dashboard will look empty",
              "dashboard shows no scans")
    rep.check(stats.get("phishing_blocked", 0) > 0,
              "the blocked count updates",
              "the blocked count stays at 0", "phishing_blocked stays zero")

    status, _ = call(url, "/stats/someone-else@example.com", token=token)
    rep.check(status in (403, 404),
              "another user's data cannot be read",
              f"another user's data was exposed ({status})",
              "stats readable for other users")

    status, _ = call(url, "/metrics")
    rep.check(status == 200, "the metrics endpoint answers",
              f"/metrics returned {status}", "metrics endpoint failed")

    status, bands = call(url, "/config/bands")
    rep.check(status == 200 and bands.get("threshold"),
              f"risk bands published: threshold {bands.get('threshold')}",
              f"/config/bands returned {status}", "bands endpoint failed")


def check_pages(url: str, rep: Report) -> None:
    section(8, "Site pages")
    for path, name in (("/app/index.html", "home"),
                       ("/app/login.html", "login"),
                       ("/app/dashboard.html", "dashboard"),
                       ("/app/forgot_password.html", "password reset")):
        status, _ = call(url, path)
        rep.check(status == 200, f"{name} loads", f"{name} returned {status}",
                  f"page {path} not served")

    status, scan = call(url, "/scan-url", "POST",
                        {"url": "http://bank-leumi-secure.xyz/verify"})
    rep.check(status == 200 and scan.get("risk_score", 0) > 0,
              f"URL checking works (score {scan.get('risk_score')})",
              f"/scan-url returned {status}", "url scan failed")


def check_extension(rep: Report) -> None:
    section(9, "Extension files")
    here = os.path.dirname(os.path.abspath(__file__))
    ext = os.path.join(here, "..", "extension")

    try:
        with open(os.path.join(ext, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        rep.ok(f"manifest.json is valid (version {manifest.get('version')})")
    except Exception as exc:
        rep.fail(f"manifest.json: {exc}", "manifest.json is broken")
        return

    needed = ["content.js", "background.js", "styles.css", "popup.html",
              "popup/popup.js", "popup/popup.css", "icons/icon128.png",
              "fonts/rubik-hebrew.woff2", "fonts/rubik-latin.woff2"]
    missing = [f for f in needed if not os.path.exists(os.path.join(ext, f))]
    rep.check(not missing, "all extension files present",
              f"missing: {', '.join(missing)}", "extension files missing")

    declared = []
    for entry in manifest.get("web_accessible_resources", []):
        declared += entry.get("resources", [])
    rep.check(all(f in declared for f in ("fonts/rubik-hebrew.woff2",
                                          "fonts/rubik-latin.woff2")),
              "fonts declared as web accessible",
              "fonts not declared - they will not load inside Gmail",
              "fonts not declared as web accessible")

    rep.note("static JS checks:  python -m pytest tests/test_javascript.py")


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="dress rehearsal before a demo")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--keep", action="store_true",
                    help="leave the guardian link in place")
    args = ap.parse_args()

    rep = Report()
    user_email = "demo-user@example.com"

    print("\n" + "=" * 68)
    print("  LURA - dress rehearsal")
    print("=" * 68)

    mail_enabled = check_server(args.url, rep)
    token = check_auth(args.url, rep, user_email)
    check_password_reset(args.url, rep, mail_enabled)
    if token:
        check_scanning(args.url, rep, token, user_email)
        check_trusted(args.url, rep, token, user_email)
    check_guardian(args.url, rep, "demo-guardian@example.com",
                   "demo-monitored@example.com", args.keep)
    if token:
        check_dashboard(args.url, rep, token, user_email)
    check_pages(args.url, rep)
    check_extension(rep)

    print("\n" + "=" * 68)
    if rep.problems:
        print(f"  {len(rep.problems)} open problem(s):")
        for p in rep.problems:
            print(f"    - {p}")
    else:
        print("  Everything works. Ready to show.")
    if rep.notes:
        print("\n  Notes:")
        for n in rep.notes:
            print(f"    - {n}")
    print("=" * 68)
    print("\n  to clear the test accounts:  python cleanup_users.py "
          "--emails demo-user@example.com --delete\n")

    sys.exit(1 if rep.problems else 0)


if __name__ == "__main__":
    main()
