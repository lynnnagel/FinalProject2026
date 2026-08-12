"""
LURA – Email Notification Service
========================================
שולח מיילי התראה למפקח (הורה / אבא / אימא / סבא) כאשר מזוהה מייל פישינג
עבור המשתמש המנוטר.

הגדרה:
    הגדר את משתני הסביבה הבאים (ראה .env.example):
        SMTP_HOST        - שרת SMTP  (ברירת מחדל: smtp.gmail.com)
        SMTP_PORT        - פורט SMTP  (ברירת מחדל: 587)
        SMTP_USER        - כתובת Gmail ממנה נשלח
        SMTP_PASSWORD    - App Password של Gmail (לא הסיסמה הרגילה!)
        EMAIL_FROM_NAME  - שם השולח (ברירת מחדל: LURA)
        EMAIL_ENABLED    - "true" להפעלה, "false" לכיבוי (ברירת מחדל: false)
"""


from __future__ import annotations

import logging
import smtplib
from datetime import datetime
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage



from config import (
    EMAIL_ENABLED,
    EMAIL_FROM_NAME,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
)

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
    שלח התראה למפקח (guardian) כאשר המשתמש המנוטר קיבל מייל פישינג.

    Parameters:
        guardian_email    – כתובת המייל של המפקח (הורה/סבא/אימא)
        monitored_name    – שם המשתמש המנוטר (ילד/קשיש)
        monitored_email   – כתובת המייל של המנוטר
        risk_score        – ציון סיכון (0-100)
        phishing_sender   – שולח מייל הפישינג
        phishing_subject  – נושא מייל הפישינג
        risk_level        – רמת סיכון בעברית (סכנה גבוהה / חשוד / זהירות)

    Returns:
        True אם נשלח בהצלחה, False אחרת.
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
            "[Email] ✅ התראה נשלחה ל-%s עבור %s (סיכון %s%%)",
            guardian_email,
            monitored_name,
            risk_score,
        )
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error(
            "[Email] ❌ שגיאת אימות SMTP – בדוק SMTP_USER ו-SMTP_PASSWORD"
        )
    except smtplib.SMTPException as exc:
        logger.error("[Email] ❌ שגיאת SMTP: %s", exc)
    except OSError as exc:
        logger.error("[Email] ❌ שגיאת רשת בשליחת מייל: %s", exc)
    except Exception as exc:
        logger.error("[Email] ❌ שגיאה לא צפויה: %s", exc)

    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _risk_color(risk_score: float) -> str:
    """צבע HTML לפי ציון הסיכון."""
    if risk_score >= 80:
        return "#dc2626"  # אדום
    if risk_score >= 50:
        return "#f59e0b"  # כתום
    return "#eab308"      # צהוב


def _risk_emoji(risk_score: float) -> str:
    if risk_score >= 50:
        return "⚡"
    return "⚠️"


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
    msg["X-Priority"] = "1" if risk_score >= 80 else "3"

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

    icon_path = Path(__file__).parent.parent / "extension" / "icons" / "icon128.png"
    if icon_path.exists():
        with open(icon_path, "rb") as f:
            img = MIMEImage(f.read())
            img.add_header("Content-ID", "<lura_icon>")
            img.add_header("Content-Disposition", "inline")
            msg.attach(img)
    else:
        logger.warning("[Email] אייקון לא נמצא: %s", icon_path)

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
        f"🛡️ LURA – התראת פישינג\n"
        f"{'=' * 40}\n\n"
        f"שלום,\n\n"
        f"LURA זיהה מייל פישינג שנשלח ל-{monitored_name} ({monitored_email}).\n\n"
        f"פרטי האיום:\n"
        f"  ציון סיכון : {risk_score:.0f}%\n"
        f"  רמת סיכון  : {risk_level}\n"
        f"  שולח חשוד  : {phishing_sender}\n"
        f"  נושא       : {phishing_subject or '(ללא נושא)'}\n"
        f"  זמן זיהוי  : {now}\n\n"
        f"מומלץ לפנות ל-{monitored_name} ולוודא שלא לחץ על קישורים במייל זה\n"
        f"ולא מסר פרטים אישיים.\n\n"
        f"{'─' * 40}\n"
        f"LURA – מערכת הגנה מפישינג\n"
        f"הודעה זו נשלחה אוטומטית כי אתה מוגדר כמשגיח על {monitored_name}."
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
    emoji = _risk_emoji(risk_score)
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
            <img src="cid:lura_icon" alt="LURA" style="width:48px;height:48px;margin-bottom:8px;">
            <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800;">LURA</h1>
            <p style="color:#94a3b8;margin:6px 0 0;font-size:13px;">מערכת הגנה מפישינג</p>
          </td>
        </tr>

        <!-- ALERT BANNER -->
        <tr>
          <td style="background:{color};padding:14px 32px;text-align:center;">
            <p style="margin:0;color:#fff;font-size:18px;font-weight:700;">
              &nbsp; זוהה מייל פישינג!
            </p>
          </td>
        </tr>

        <!-- BODY -->
        <tr>
          <td style="background:#1e293b;padding:32px;">

            <p style="color:#e2e8f0;font-size:16px;margin:0 0 8px;">שלום,</p>
            <p style="color:#e2e8f0;font-size:15px;margin:0 0 28px;line-height:1.7;">
              LURA זיהה מייל פישינג שנשלח ל
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
                <td style="background:#0f172a;padding:13px 18px;border-bottom:1px solid #1e293b;">
                  <span style="color:#94a3b8;font-size:12px;display:block;margin-bottom:3px;">שולח חשוד</span>
                  <span style="color:#f87171;font-weight:700;font-size:14px;word-break:break-all;">{phishing_sender}</span>
                </td>
              </tr>
              <tr>
                <td style="background:#0f172a;padding:13px 18px;border-bottom:1px solid #1e293b;">
                  <span style="color:#94a3b8;font-size:12px;display:block;margin-bottom:3px;">נושא המייל</span>
                  <span style="color:#e2e8f0;font-size:14px;">{subject_display}</span>
                </td>
              </tr>
              <tr>
                <td style="background:#0f172a;padding:13px 18px;">
                  <span style="color:#94a3b8;font-size:12px;display:block;margin-bottom:3px;">זמן זיהוי</span>
                  <span style="color:#e2e8f0;font-size:14px;">{now}</span>
                </td>
              </tr>
            </table>

            <!-- Recommendation -->
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
              <tr>
                <td style="background:#172554;border-right:4px solid #3b82f6;
                           border-radius:0 10px 10px 0;padding:16px 20px;">
                  <p style="color:#93c5fd;margin:0 0 6px;font-size:14px;font-weight:700;">💡 מה לעשות עכשיו?</p>
                  <p style="color:#dbeafe;margin:0;font-size:14px;line-height:1.7;">
                    פנה ל-<strong>{monitored_name}</strong> ווודא שהם:<br>
                    • לא לחצו על קישורים במייל זה<br>
                    • לא הזינו סיסמאות או פרטי כרטיס אשראי<br>
                    • מחקו את המייל מתיבת הדואר
                  </p>
                </td>
              </tr>
            </table>

            <hr style="border:none;border-top:1px solid #334155;margin:0 0 20px;">
            <p style="color:#475569;font-size:12px;text-align:center;margin:0;line-height:1.6;">
              הודעה זו נשלחה אוטומטית ממערכת LURA<br>
              אתה מקבל הודעה זו כי הגדרת מעקב על חשבון
              <strong style="color:#64748b;">{monitored_name}</strong>
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

def send_password_reset(*, to_email: str, name: str, token: str) -> bool:
    """שליחת קישור איפוס סיסמה."""
    if not EMAIL_ENABLED or not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("[Email] שליחת מיילים מושבתת")
        return False

    link = f"http://localhost:8000/app/forgot_password.html?token={token}"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "LURA — איפוס סיסמה"
    msg["From"]    = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"]      = to_email

    msg.attach(MIMEText(
        f"שלום {name},\n\nלאיפוס הסיסמה שלך: {link}\n"
        f"הקישור תקף ל-30 דקות.\n\nאם לא ביקשת זאת — התעלם מההודעה.",
        "plain", "utf-8"))
    msg.attach(MIMEText(f"""
      <div dir="rtl" style="font-family:Arial,sans-serif;max-width:520px;margin:auto;
                            background:#0f172a;color:#e2e8f0;padding:32px;border-radius:14px">
        <h2 style="margin:0 0 6px;text-align:center">LURA</h2>
        <p style="color:#94a3b8;text-align:center;margin:0 0 24px;font-size:13px">איפוס סיסמה</p>
        <p>שלום {name},</p>
        <p>קיבלנו בקשה לאיפוס הסיסמה שלך.</p>
        <p style="text-align:center;margin:26px 0">
          <a href="{link}" style="background:#7C4DFF;color:#fff;padding:12px 28px;
             border-radius:8px;text-decoration:none;font-weight:600">אפס סיסמה</a>
        </p>
        <p style="color:#64748b;font-size:12px">הקישור תקף ל-30 דקות.
           אם לא ביקשת זאת — אפשר להתעלם מההודעה.</p>
      </div>""", "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo(); server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        logger.info("[Email] קישור איפוס נשלח ל-%s", to_email)
        return True
    except Exception as exc:
        logger.error("[Email] שגיאה בשליחת איפוס: %s", exc)
        return False