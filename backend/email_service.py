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
        f"LURA – התראת פישינג\n"
        f"{'=' * 40}\n\n"
        f"שלום,\n\n"
        f"LURA זיהה מייל פישינג שנשלח אל {monitored_name} ({monitored_email}).\n\n"
        f"פרטי האיום:\n"
        f"  ציון סיכון : {risk_score:.0f}%\n"
        f"  רמת סיכון  : {risk_level}\n"
        f"  שולח חשוד  : {phishing_sender}\n"
        f"  נושא       : {phishing_subject or '(ללא נושא)'}\n"
        f"  זמן זיהוי  : {now}\n\n"
        f"כדאי לפנות ל-{monitored_name} ולוודא שלא נלחץ קישור במייל הזה\n"
        f"ושלא נמסרו פרטים אישיים.\n\n"
        f"{'─' * 40}\n"
        f"LURA – מערכת הגנה מפישינג\n"
        f"הודעה זו נשלחה אוטומטית כי החשבון של {monitored_name} מוגדר\n"
        f"במעקב במצב מפקח."
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
    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    subject_display = phishing_subject or "(ללא נושא)"

    return f"""\
<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>התראת LURA</title>
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family:'Segoe UI',Arial,sans-serif;direction:rtl;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:40px 20px;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="max-width:600px;width:100%;border-radius:16px;overflow:hidden;
                    box-shadow:0 25px 50px rgba(0,0,0,0.5);">

        <!-- HEADER -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);
                     padding:32px;text-align:center;border-bottom:3px solid {color};">
            <img src="cid:{ICON_CID}" alt="LURA" style="width:48px;height:48px;margin-bottom:8px;">
            <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800;">LURA</h1>
            <p style="color:#94a3b8;margin:6px 0 0;font-size:13px;">מערכת הגנה מפישינג</p>
          </td>
        </tr>

        <!-- ALERT BANNER -->
        <tr>
          <td style="background:{color};padding:14px 32px;text-align:center;">
            <p style="margin:0;color:#fff;font-size:18px;font-weight:700;">
              זוהה מייל פישינג
            </p>
          </td>
        </tr>

        <!-- BODY -->
        <tr>
          <td style="background:#1e293b;padding:32px;text-align:right;direction:rtl;">

            <p style="color:#e2e8f0;font-size:16px;margin:0 0 8px;">שלום,</p>
            <p style="color:#e2e8f0;font-size:15px;margin:0 0 28px;line-height:1.7;">
              LURA זיהה מייל פישינג שנשלח אל
              <strong style="color:#60a5fa;">{monitored_name}</strong>
              <span style="color:#64748b;font-size:13px;"> ({monitored_email})</span>.
              להלן פרטי האיום:
            </p>

            <!-- Risk Score Card -->
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="background:#0f172a;border-radius:12px;margin-bottom:24px;">
              <tr>
                <td style="padding:24px;text-align:center;">
                  <div style="font-size:56px;font-weight:900;color:{color};line-height:1;">{risk_score:.0f}%</div>
                  <div style="color:#94a3b8;font-size:13px;margin-top:6px;">ציון סיכון</div>
                  <div style="display:inline-block;background:{color};color:#fff;
                               border-radius:20px;padding:4px 18px;margin-top:10px;
                               font-size:14px;font-weight:700;">{risk_level}</div>
                </td>
              </tr>
            </table>

            <!-- Details -->
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="border-radius:10px;overflow:hidden;margin-bottom:24px;">
              <tr>
                <td style="background:#0f172a;padding:13px 18px;border-bottom:1px solid #1e293b;text-align:right;direction:rtl;">
                  <span style="color:#94a3b8;font-size:12px;display:block;margin-bottom:3px;">שולח חשוד</span>
                  <span style="color:#f87171;font-weight:700;font-size:14px;word-break:break-all;">{phishing_sender}</span>
                </td>
              </tr>
              <tr>
                <td style="background:#0f172a;padding:13px 18px;border-bottom:1px solid #1e293b;text-align:right;direction:rtl;">
                  <span style="color:#94a3b8;font-size:12px;display:block;margin-bottom:3px;">נושא המייל</span>
                  <span style="color:#e2e8f0;font-size:14px;">{subject_display}</span>
                </td>
              </tr>
              <tr>
                <td style="background:#0f172a;padding:13px 18px;text-align:right;direction:rtl;">
                  <span style="color:#94a3b8;font-size:12px;display:block;margin-bottom:3px;">זמן זיהוי</span>
                  <span style="color:#e2e8f0;font-size:14px;">{now}</span>
                </td>
              </tr>
            </table>

            <!-- Recommendation -->
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
              <tr>
                <td style="background:#172554;border-right:4px solid #3b82f6;
                           border-radius:0 10px 10px 0;padding:16px 20px;text-align:right;direction:rtl;">
                  <p style="color:#93c5fd;margin:0 0 6px;font-size:14px;font-weight:700;">מה כדאי לעשות עכשיו</p>
                  <p style="color:#dbeafe;margin:0;font-size:14px;line-height:1.7;">
                    כדאי לפנות ל-<strong>{monitored_name}</strong> ולוודא ש:<br>
                    • לא נלחץ אף קישור במייל הזה<br>
                    • לא הוזנו סיסמאות או פרטי כרטיס אשראי<br>
                    • המייל נמחק מתיבת הדואר
                  </p>
                </td>
              </tr>
            </table>

            <hr style="border:none;border-top:1px solid #334155;margin:0 0 20px;">
            <p style="color:#475569;font-size:12px;text-align:center;margin:0;line-height:1.6;">
              הודעה זו נשלחה אוטומטית ממערכת LURA<br>
              היא נשלחה כי החשבון של
              <strong style="color:#64748b;">{monitored_name}</strong>
              מוגדר במעקב במצב מפקח
            </p>

          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

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
        f"LURA – איפוס סיסמה\n"
        f"{'=' * 40}\n\n"
        f"שלום {name},\n\n"
        f"קיבלנו בקשה לאיפוס הסיסמה של החשבון שלך.\n"
        f"אפשר לאפס דרך הקישור הבא:\n\n"
        f"{link}\n\n"
        f"הקישור תקף ל-30 דקות ומיועד לשימוש חד-פעמי.\n\n"
        f"אם לא ביקשת לאפס את הסיסמה — אפשר להתעלם מהודעה זו,\n"
        f"הסיסמה הנוכחית שלך תישאר בתוקף.\n\n"
        f"{'─' * 40}\n"
        f"LURA – מערכת הגנה מפישינג"
    )


def _reset_html(name: str, link: str) -> str:
    return f"""\
<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>איפוס סיסמה – LURA</title>
</head>
<body style="margin:0;padding:0;background:#0f172a;
             font-family:'Segoe UI',Arial,sans-serif;direction:rtl;">
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:#0f172a;padding:40px 20px;">
  <tr>
    <td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
             style="max-width:560px;width:100%;border-radius:16px;overflow:hidden;
                    box-shadow:0 25px 50px rgba(0,0,0,0.5);">

        <tr>
          <td style="background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);
                     padding:32px;text-align:center;border-bottom:3px solid #7c4dff;">
            <img src="cid:{ICON_CID}" alt="LURA"
                 style="width:48px;height:48px;margin-bottom:8px;">
            <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800;">LURA</h1>
            <p style="color:#94a3b8;margin:6px 0 0;font-size:13px;">איפוס סיסמה</p>
          </td>
        </tr>

        <tr>
          <td style="background:#1e293b;padding:32px;text-align:right;direction:rtl;">
            <p style="color:#e2e8f0;font-size:16px;margin:0 0 8px;">שלום {name},</p>
            <p style="color:#e2e8f0;font-size:15px;margin:0 0 28px;line-height:1.7;">
              קיבלנו בקשה לאיפוס הסיסמה של החשבון שלך.
              אפשר לבחור סיסמה חדשה כאן:
            </p>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
              <tr>
                <td align="center">
                  <a href="{link}"
                     style="display:inline-block;background:#7c4dff;color:#fff;
                            padding:14px 34px;border-radius:10px;text-decoration:none;
                            font-size:15px;font-weight:700;">בחר סיסמה חדשה</a>
                </td>
              </tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
              <tr>
                <td style="background:#172554;border-right:4px solid #3b82f6;
                           border-radius:0 10px 10px 0;padding:16px 20px;
                           text-align:right;direction:rtl;">
                  <p style="color:#dbeafe;margin:0;font-size:14px;line-height:1.7;">
                    הקישור תקף ל-<strong>30 דקות</strong> בלבד.
                    <br>אם לא ביקשת לאפס את הסיסמה — אפשר להתעלם מהודעה זו,
                    והסיסמה הנוכחית שלך תישאר בתוקף.
                  </p>
                </td>
              </tr>
            </table>

            <hr style="border:none;border-top:1px solid #334155;margin:0 0 20px;">
            <p style="color:#475569;font-size:12px;text-align:center;margin:0;line-height:1.6;">
              הודעה זו נשלחה אוטומטית ממערכת LURA
            </p>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
</body>
</html>
"""
