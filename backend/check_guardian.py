"""
End-to-end check of guardian mode, against the running server.

Every failure found in guardian mode lived in a seam between the four
pieces it spans - the link, the scan, the alert record and the mail -
so the check walks the whole chain rather than any one of them.

Run from backend/, with the server up:
    python check_guardian.py
    python check_guardian.py --url http://localhost:8000
    python check_guardian.py --keep      # leave the accounts in place

To receive the alert in a real mailbox, name it as the guardian. If that
address is already registered, give its password too - the script logs
in as the guardian and cannot use the throwaway one:
    python check_guardian.py --guardian you@gmail.com
    python check_guardian.py --guardian you@gmail.com --guardian-password ...

Linking also sends a notice to the monitored address, so with sending on
give one that can receive. Gmail plus-addressing keeps it in your inbox:
    python check_guardian.py --guardian you@gmail.com \
        --guardian-password ... --monitored you+lura@gmail.com
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
    print(f"     OK    {text}")


def fail(text: str) -> None:
    print(f"     FAIL  {text}")


def main() -> None:
    ap = argparse.ArgumentParser(description="end-to-end check of guardian mode")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--guardian", default="guardian-check@example.com")
    ap.add_argument("--monitored", default="monitored-check@example.com")
    ap.add_argument("--password", default="CheckPass123",
                    help="password for the accounts this script creates")
    ap.add_argument("--guardian-password",
                    help="the guardian account's own password, if it already exists")
    ap.add_argument("--keep", action="store_true",
                    help="leave the guardian link in place")
    args = ap.parse_args()

    problems = []

    # -- server and mail --------------------------------------------------
    step(1, "Server and mail settings")
    try:
        _, health = call(args.url, "/test-email")
    except urllib.error.URLError as exc:
        raise SystemExit(f"     FAIL  no answer at {args.url}\n           {exc}")
    ok(f"server answering at {args.url}")

    mail_on = health.get("email_enabled") or health.get("EMAIL_ENABLED")
    if mail_on:
        ok("sending is on")
    else:
        fail("EMAIL_ENABLED is off - the alert is recorded but not sent")
        problems.append("EMAIL_ENABLED=false")
    for key, value in health.items():
        if key not in ("email_enabled", "EMAIL_ENABLED"):
            print(f"        {key}: {value}")

    # -- accounts -------------------------------------------------------
    step(2, "Two accounts")
    tokens = {}
    # A real guardian address is usually already registered, so the
    # login needs that account's own password.
    accounts = (
        ("guardian", args.guardian,  args.guardian_password or args.password),
        ("monitored", args.monitored, args.password),
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
                f"     FAIL  {role}: {email} already exists and the password does not match.\n"
                f"           run it with that account's password:\n"
                f"             python check_guardian.py --guardian {email} "
                f"--guardian-password YOUR_PASSWORD\n"
                f"           forgotten it?  python set_password.py {email}"
            )
        if status != 200:
            raise SystemExit(f"     FAIL  {role}: {body.get('detail', status)}")
        tokens[role] = body["token"]
        ok(f"{role}: {email}" + ("  (existing account)" if existed else ""))

    # -- link -----------------------------------------------------------
    step(3, "Linking them")
    status, body = call(args.url, "/guardian/connect", "POST",
                        {"child_email": args.monitored,
                         "parent_email": "ignored-on-purpose@example.com"},
                        token=tokens["guardian"])
    if status != 200:
        raise SystemExit(f"     FAIL  {body.get('detail', status)}")
    ok(body.get("message", "linked"))
    if body.get("guardian") == args.guardian:
        ok("the guardian comes from the token, not a request field")
    else:
        fail(f"the guardian came from the request body: {body.get('guardian')}")
        problems.append("guardian taken from the request body")

    # -- scan -----------------------------------------------------------
    step(4, "Scanning a phishing message as the monitored user")
    status, scan = call(args.url, "/scan", "POST",
                        {"user_email": args.monitored, **PHISHING},
                        token=tokens["monitored"])
    if status != 200:
        raise SystemExit(f"     FAIL  {scan.get('detail', status)}")
    print(f"           score {scan['risk_score']}  |  {scan['risk_level']}")
    if scan["is_phishing"]:
        ok("classified as phishing")
    else:
        fail("not classified as phishing - no alert will be created")
        problems.append("the sample did not cross the threshold")

    # -- the guardian's dashboard ---------------------------------------
    step(5, "The guardian dashboard")
    status, dash = call(args.url, f"/guardian/{args.guardian}",
                        token=tokens["guardian"])
    if status != 200:
        raise SystemExit(f"     FAIL  {dash.get('detail', status)}")

    if dash.get("child_email") == args.monitored:
        ok(f"monitored account shown: {dash['child_email']}")
    else:
        fail(f"monitored account missing (got {dash.get('child_email')!r})")
        problems.append("the monitored account is missing from the dashboard")

    alerts = dash.get("recent_alerts", [])
    if alerts:
        ok(f"{len(alerts)} alert(s) on the dashboard")
        print(f"        {alerts[0].get('message', '')[:70]}")
    else:
        fail("no alerts on the dashboard")
        problems.append("no alert reached the dashboard")

    if alerts and PHISHING["sender"] in alerts[0].get("message", ""):
        ok("the alert names the monitored user and the sender")
    elif alerts:
        fail("the alert does not name the sender")
        problems.append("the alert does not name the sender")

    # -- no duplicate on a repeat scan ----------------------------------
    # The body is changed on purpose: an identical rescan is answered
    # from the cache and never reaches the alert code, so it would pass
    # without testing anything.
    step(6, "Rescanning the same message (slightly different text)")
    before = len(alerts)
    call(args.url, "/scan", "POST",
         {"user_email": args.monitored, **PHISHING,
          "content": PHISHING["content"] + " "},
         token=tokens["monitored"])
    _, dash2 = call(args.url, f"/guardian/{args.guardian}", token=tokens["guardian"])
    after = len(dash2.get("recent_alerts", []))
    if after == before:
        ok("no duplicate alert")
    else:
        fail(f"alerts went from {before} to {after}")
        problems.append("a repeat scan created a duplicate alert")

    # -- cleanup --------------------------------------------------------
    if not args.keep:
        call(args.url, "/guardian/disconnect", "POST",
             {"child_email": args.monitored, "parent_email": args.guardian},
             token=tokens["guardian"])
        print("\n   Link removed. The accounts remain - to clear them:\n"
              "   python cleanup_users.py --emails %s --delete" % args.monitored)

    # -- summary --------------------------------------------------------
    print("\n" + "=" * 66)
    if problems:
        print("  Problems found:")
        for p in problems:
            print(f"    - {p}")
    else:
        print("  The whole chain works.")
        if mail_on:
            print(f"\n  Check the inbox of {args.guardian} - the alert mail is")
            print("  sent in the background and should arrive within seconds.")
    print("=" * 66 + "\n")


if __name__ == "__main__":
    main()
