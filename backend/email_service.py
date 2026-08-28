"""
LURA - outgoing mail.

Two messages are sent from here: the alert to a guardian when phishing
is found in the account they watch, and a password reset link.

Configuration (see .env.example):
    SMTP_HOST        SMTP server        (default: smtp.gmail.com)
    SMTP_PORT        SMTP port          (default: 587)
    SMTP_USER        the Gmail address mail is sent from
    SMTP_PASSWORD    a Gmail App Password, not the account password
    EMAIL_FROM_NAME  sender name        (default: LURA)
    EMAIL_ENABLED    "true" to send, "false" to log only (default: false)

With EMAIL_ENABLED=false nothing is sent and the call is logged instead,
so the rest of the system can be run without SMTP credentials.
"""


from __future__ import annotations

import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from pathlib import Path

from config import (
    APP_BASE_URL,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    EMAIL_ENABLED,
    EMAIL_FROM_NAME,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
)

# The icon embedded in the message body. The files live under extension/icons/.
ICON_PATH = Path(__file__).parent.parent / "extension" / "icons" / "icon128.png"
ICON_CID = "lura_icon"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_guardian_phishing_alert(
    *,
    guardian_email: str,
    monitored_name: str,
    monitored_email: str,
    risk_score: float,
    phishing_sender: str,
    phishing_subject: str,
    risk_level: str,
) -> bool:
    """
    Alert a guardian that phishing was found in the account they watch.

    Called from a background task, so it never delays the scan response
    and never fails it: a mail that cannot be sent is logged and the
    detection itself still stands, recorded on the dashboard.

    Returns True only if the message actually went out.
    """
    if not EMAIL_ENABLED:
        logger.info(
            "[Email] מצב כבוי – היה נשלח ל-%s על %s",
            guardian_email,
            monitored_name,
        )
        return False

    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning(
            "[Email] פרטי SMTP לא מוגדרים – דלג על שליחת מייל ל-%s",
            guardian_email,
        )
        return False

    try:
        msg = _build_message(
            to_email=guardian_email,
            monitored_name=monitored_name,
            monitored_email=monitored_email,
            risk_score=risk_score,
            phishing_sender=phishing_sender,
            phishing_subject=phishing_subject,
            risk_level=risk_level,
        )

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, guardian_email, msg.as_string())

        logger.info(
            "[Email] התראה נשלחה ל-%s עבור %s (סיכון %s%%)",
            guardian_email,
            monitored_name,
            risk_score,
        )
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error(
            "[Email] שגיאת אימות SMTP – בדוק SMTP_USER ו-SMTP_PASSWORD"
        )
    except smtplib.SMTPException as exc:
        logger.error("[Email] שגיאת SMTP: %s", exc)
    except OSError as exc:
        logger.error("[Email] שגיאת רשת בשליחת מייל: %s", exc)
    except Exception as exc:
        logger.error("[Email] שגיאה לא צפויה: %s", exc)

    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _risk_color(risk_score: float) -> str:
    """
    An HTML colour for a risk score.

    The cut-offs are the same ones the rest of the system uses. They were
    hard-coded here as 80 and 50, so after the threshold was calibrated a
    message the extension called "סכנה גבוהה" could arrive in the
    guardian's mail painted orange.
    """
    if risk_score >= HIGH_RISK_THRESHOLD:
        return "#dc2626"  # red
    if risk_score >= MEDIUM_RISK_THRESHOLD:
        return "#f59e0b"  # orange
    return "#eab308"      # yellow


def _attach_icon(msg: MIMEMultipart) -> None:
    """Attaches the LURA icon as an inline image (cid) for an <img> tag."""
    if not ICON_PATH.exists():
        logger.warning("[Email] אייקון לא נמצא: %s", ICON_PATH)
        return
    with open(ICON_PATH, "rb") as f:
        img = MIMEImage(f.read())
    img.add_header("Content-ID", f"<{ICON_CID}>")
    img.add_header("Content-Disposition", "inline")
    msg.attach(img)


# ---------------------------------------------------------------------------
# One shell for every message we send.
#
# Mail clients strip <style> and most modern CSS, so everything here is a
# table with inline styles - the only layout that renders the same in
# Gmail, Outlook and Apple Mail.
#
# The look is deliberately plain: a white page, one hairline frame, the
# wordmark, and the text. Colour appears once, on the risk score, where
# it carries meaning.
# ---------------------------------------------------------------------------

INK, INK_SOFT, INK_FAINT, RULE = "#16141F", "#4A4660", "#8B87A0", "#E6E3EE"


def _shell(*, eyebrow: str, body: str) -> str:
    return f"""\
<!DOCTYPE html>
<html dir="rtl" lang="he">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F7F6FA;">
<table width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background:#F7F6FA;padding:32px 16px;">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" border="0"
           style="max-width:520px;width:100%;background:#FFFFFF;
                  border:1px solid {RULE};border-radius:10px;">
      <tr><td style="padding:26px 32px 20px;border-bottom:1px solid {RULE};">
        <table cellpadding="0" cellspacing="0" border="0"><tr>
          <td style="font:600 15px/1 -apple-system,'Segoe UI',Arial,sans-serif;
                     color:{INK};letter-spacing:.06em;padding-left:9px;">LURA</td>
          <td><img src="cid:{ICON_CID}" width="22" height="22"
              alt="" style="display:block;width:22px;height:22px;"></td>
        </tr></table>
      </td></tr>
      <tr><td style="padding:28px 32px 32px;direction:rtl;text-align:right;
                     font-family:-apple-system,'Segoe UI',Arial,sans-serif;">
        <p style="margin:0 0 18px;font-size:12px;letter-spacing:.09em;
                  color:{INK_FAINT};text-transform:uppercase;">{eyebrow}</p>
        {body}
      </td></tr>
      <tr><td style="padding:0 32px 26px;direction:rtl;text-align:right;">
        <p style="margin:0;font:12px/1.6 -apple-system,'Segoe UI',Arial,sans-serif;
                  color:{INK_FAINT};">LURA · זיהוי פישינג בזמן אמת</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>
"""


def _facts(rows: list[tuple[str, str]]) -> str:
    """A short label/value list. Two columns on one hairline grid."""
    cells = "".join(
        f'<tr><td style="padding:11px 0;border-top:1px solid {RULE};'
        f'font:12.5px/1.5 -apple-system,Arial,sans-serif;color:{INK_FAINT};'
        f'white-space:nowrap;vertical-align:top;width:96px;">{label}</td>'
        f'<td style="padding:11px 0 11px 12px;border-top:1px solid {RULE};'
        f'font:14.5px/1.55 -apple-system,Arial,sans-serif;color:{INK};'
        f'word-break:break-word;">{value}</td></tr>'
        for label, value in rows
    )
    return (f'<table width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'style="margin:0 0 22px;">{cells}</table>')

def _build_message(
    *,
    to_email: str,
    monitored_name: str,
    monitored_email: str,
    risk_score: float,
    phishing_sender: str,
    phishing_subject: str,
    risk_level: str,
) -> MIMEMultipart:
    subject_line = (
        f"LURA: {monitored_name} קיבל מייל פישינג "
        f"({risk_score:.0f}% סיכון)"
    )

    msg = MIMEMultipart("related")
    msg["Subject"] = subject_line
    msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to_email
    msg["X-Priority"] = "1" if risk_score >= HIGH_RISK_THRESHOLD else "3"

    alt_part = MIMEMultipart("alternative")

    plain = _build_plain_text(
        monitored_name=monitored_name,
        monitored_email=monitored_email,
        risk_score=risk_score,
        phishing_sender=phishing_sender,
        phishing_subject=phishing_subject,
        risk_level=risk_level,
    )
    html = _build_html(
        monitored_name=monitored_name,
        monitored_email=monitored_email,
        risk_score=risk_score,
        phishing_sender=phishing_sender,
        phishing_subject=phishing_subject,
        risk_level=risk_level,
    )

    alt_part.attach(MIMEText(plain, "plain", "utf-8"))
    alt_part.attach(MIMEText(html, "html", "utf-8"))
    msg.attach(alt_part)

    _attach_icon(msg)

    return msg



def _build_plain_text(
    *,
    monitored_name: str,
    monitored_email: str,
    risk_score: float,
    phishing_sender: str,
    phishing_subject: str,
    risk_level: str,
) -> str:
    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    return (
        f"LURA\n\n"
        f"זוהה מייל פישינג בתיבה של {monitored_name} ({monitored_email}).\n\n"
        f"שולח    {phishing_sender}\n"
        f"נושא     {phishing_subject or '(ללא נושא)'}\n"
        f"סיכון    {risk_score:.0f}% · {risk_level}\n"
        f"זמן      {now}\n\n"
        f"כדאי לוודא מולו שלא נלחץ קישור ושלא נמסרו פרטים.\n\n"
        f"LURA · זיהוי פישינג בזמן אמת"
    )


def _build_html(
    *,
    monitored_name: str,
    monitored_email: str,
    risk_score: float,
    phishing_sender: str,
    phishing_subject: str,
    risk_level: str,
) -> str:
    color = _risk_color(risk_score)
    body = f"""
        <p style="margin:0 0 22px;font-size:16px;line-height:1.65;color:{INK};">
          זוהה מייל פישינג בתיבה של <strong>{monitored_name}</strong>
          <span style="color:{INK_FAINT};font-size:14px;">({monitored_email})</span>.
        </p>
        {_facts([
            ("שולח", f'<span style="direction:ltr;unicode-bidi:embed;">{phishing_sender}</span>'),
            ("נושא", phishing_subject or "(ללא נושא)"),
            ("סיכון", f'<span style="color:{color};font-weight:700;">{risk_score:.0f}%</span>'
                      f'<span style="color:{INK_FAINT};"> · {risk_level}</span>'),
            ("זמן", f'<span style="direction:ltr;unicode-bidi:embed;">'
                    f'{datetime.now().strftime("%d/%m/%Y %H:%M")}</span>'),
        ])}
        <p style="margin:0;font-size:14.5px;line-height:1.7;color:{INK_SOFT};">
          כדאי לוודא מולו שלא נלחץ קישור במייל הזה ושלא נמסרו פרטים אישיים.
        </p>"""
    return _shell(eyebrow="התראת פישינג", body=body)

def send_password_reset(*, to_email: str, name: str, token: str) -> bool:
    """
    Send a one-time password reset link.

    The token is created in API/auth.py and is short-lived (see
    RESET_TOKEN_TTL_MINUTES). This link is the only way to reset a
    password - no endpoint accepts an email address on its own.
    """
    if not EMAIL_ENABLED:
        logger.info("[Email] מצב כבוי – היה נשלח קישור איפוס ל-%s", to_email)
        return False

    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("[Email] פרטי SMTP לא מוגדרים – דלג על קישור איפוס")
        return False

    link = f"{APP_BASE_URL}/app/forgot_password.html?token={token}"

    msg = MIMEMultipart("related")
    msg["Subject"] = "LURA – איפוס סיסמה"
    msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to_email

    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(_reset_plain_text(name, link), "plain", "utf-8"))
    alt_part.attach(MIMEText(_reset_html(name, link), "html", "utf-8"))
    msg.attach(alt_part)

    _attach_icon(msg)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        logger.info("[Email] קישור איפוס סיסמה נשלח ל-%s", to_email)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("[Email] שגיאת אימות SMTP – בדוק SMTP_USER ו-SMTP_PASSWORD")
    except smtplib.SMTPException as exc:
        logger.error("[Email] שגיאת SMTP בשליחת איפוס: %s", exc)
    except OSError as exc:
        logger.error("[Email] שגיאת רשת בשליחת איפוס: %s", exc)
    except Exception as exc:
        logger.error("[Email] שגיאה לא צפויה בשליחת איפוס: %s", exc)

    return False



def _reset_plain_text(name: str, link: str) -> str:
    return (
        f"LURA\n\n"
        f"שלום {name},\n\n"
        f"לאיפוס הסיסמה:\n{link}\n\n"
        f"הקישור תקף 30 דקות ולשימוש אחד.\n"
        f"אם לא ביקשת לאפס — אפשר להתעלם.\n\n"
        f"LURA · זיהוי פישינג בזמן אמת"
    )


def _reset_html(name: str, link: str) -> str:
    body = f"""
        <p style="margin:0 0 24px;font-size:16px;line-height:1.65;color:{INK};">
          שלום {name}, אפשר לבחור סיסמה חדשה כאן:
        </p>
        <table cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px;">
          <tr><td style="border-radius:8px;background:#6B3FE0;">
            <a href="{link}" style="display:inline-block;padding:12px 26px;
               font:600 15px -apple-system,'Segoe UI',Arial,sans-serif;
               color:#FFFFFF;text-decoration:none;">בחירת סיסמה חדשה</a>
          </td></tr>
        </table>
        <p style="margin:0;font-size:14px;line-height:1.7;color:{INK_SOFT};">
          הקישור תקף 30 דקות ולשימוש אחד.
          אם לא ביקשת לאפס — אפשר להתעלם מההודעה, הסיסמה הנוכחית נשארת בתוקף.
        </p>"""
    return _shell(eyebrow="איפוס סיסמה", body=body)

def send_guardian_link_notice(*, to_email: str, monitored_name: str,
                              guardian_email: str, guardian_name: str) -> bool:
    """
    Tell someone that an account named them as the one it watches over.

    Guardian mode is set up by the guardian alone, so without this the
    monitored person is never told it happened. The link itself shares
    nothing on its own - alerts only start once the extension is
    installed and signed in on this address - and saying that plainly
    is most of what this message is for.

    Sent from a background task: a mail that cannot go out must not fail
    the request that created the link.
    """
    if not EMAIL_ENABLED:
        logger.info("[Email] mail off - would have told %s that %s is watching",
                    to_email, guardian_email)
        return False

    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("[Email] SMTP not configured - skipping guardian notice")
        return False

    msg = MIMEMultipart("related")
    msg["Subject"] = "LURA – הוגדר מפקח על התיבה שלך"
    msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to_email

    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(
        _link_notice_plain(monitored_name, guardian_name, guardian_email),
        "plain", "utf-8"))
    alt_part.attach(MIMEText(
        _link_notice_html(monitored_name, guardian_name, guardian_email),
        "html", "utf-8"))
    msg.attach(alt_part)

    _attach_icon(msg)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        logger.info("[Email] guardian notice sent to %s", to_email)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("[Email] SMTP auth failed - check SMTP_USER and SMTP_PASSWORD")
    except smtplib.SMTPException as exc:
        logger.error("[Email] SMTP error sending guardian notice: %s", exc)
    except OSError as exc:
        logger.error("[Email] network error sending guardian notice: %s", exc)
    except Exception as exc:
        logger.error("[Email] unexpected error sending guardian notice: %s", exc)

    return False



def _link_notice_plain(name: str, guardian_name: str, guardian_email: str) -> str:
    return (
        f"LURA\n\n"
        f"שלום {name},\n\n"
        f"החשבון של {guardian_name} ({guardian_email}) הוגדר כמפקח על\n"
        f"כתובת המייל הזאת.\n\n"
        f"כשיזוהה מייל פישינג בתיבה שלך, תישלח אליו התראה עם השולח,\n"
        f"הנושא וציון הסיכון. תוכן המיילים אינו נשלח.\n\n"
        f"עד שתתקין את התוסף ותתחבר בו בכתובת הזאת — לא נשלח דבר.\n"
        f"אפשר להסיר את השיוך בכל רגע מלוח הבקרה.\n\n"
        f"LURA · זיהוי פישינג בזמן אמת"
    )


def _link_notice_html(name: str, guardian_name: str, guardian_email: str) -> str:
    body = f"""
        <p style="margin:0 0 20px;font-size:16px;line-height:1.65;color:{INK};">
          שלום {name}, החשבון של <strong>{guardian_name}</strong>
          <span style="color:{INK_FAINT};font-size:14px;">({guardian_email})</span>
          הוגדר כמפקח על כתובת המייל הזאת.
        </p>
        {_facts([
            ("נשלח אליו", "השולח, הנושא וציון הסיכון של מיילים שזוהו כפישינג"),
            ("לא נשלח", "תוכן המיילים, ומיילים שלא זוהו"),
        ])}
        <p style="margin:0;font-size:14.5px;line-height:1.7;color:{INK_SOFT};">
          עד שתתקין את התוסף ותתחבר בו בכתובת הזאת לא נשלח דבר,
          ואפשר להסיר את השיוך בכל רגע מלוח הבקרה.
        </p>"""
    return _shell(eyebrow="הוגדר מפקח על התיבה שלך", body=body)

