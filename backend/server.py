"""
PhishGuard FastAPI Application
Run with: uvicorn server:app --host localhost --port 8000 --reload
"""
import logging
logging.basicConfig(level=logging.INFO)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from database import init_db
from API.scan import router as scan_router
from API.stats import router as stats_router
from API.guardian import router as guardian_router
from API.metrics import router as metrics_router
from API.auth import router as auth_router
from API.url_scan import router as url_scan_router

app = FastAPI(
    title="LURA API",
    description="זיהוי פישינג בזמן אמת",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

init_db()

app.include_router(scan_router)
app.include_router(stats_router)
app.include_router(guardian_router)
app.include_router(metrics_router)
app.include_router(auth_router)
app.include_router(url_scan_router)

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/app", StaticFiles(directory=frontend_path, html=True), name="frontend")

@app.get("/", tags=["health"])
async def root():
    return {
        "message": "LURA API Active",
        "version": "1.0.0",
        "endpoints": {
            "scan":             "POST /scan",
            "stats":            "GET  /stats/{user_email}",
            "auth_register":    "POST /auth/register",
            "auth_login":       "POST /auth/login",
            "scan_url":         "POST /scan-url",
            "guardian_connect": "POST /guardian/connect",
            "guardian_data":    "GET  /guardian/{parent_email}",
            "metrics":          "GET  /metrics",
            "swagger_docs":     "GET  /docs",
            "frontend":         "GET  /app",
        },
    }

@app.get("/test-email", tags=["health"])
async def test_email():
    from config import EMAIL_ENABLED, SMTP_USER, SMTP_PASSWORD, SMTP_HOST, SMTP_PORT
    from email_service import send_guardian_phishing_alert
    import smtplib

    status = {
        "EMAIL_ENABLED": EMAIL_ENABLED,
        "SMTP_USER": SMTP_USER or "(ריק)",
        "SMTP_PASSWORD_SET": bool(SMTP_PASSWORD),
        "SMTP_HOST": SMTP_HOST,
        "SMTP_PORT": SMTP_PORT,
    }

    if not EMAIL_ENABLED:
        status["error"] = "EMAIL_ENABLED=false — שליחת מיילים כבויה"
        return status

    if not SMTP_USER or not SMTP_PASSWORD:
        status["error"] = "SMTP_USER או SMTP_PASSWORD ריקים — בדוק את קובץ .env"
        return status

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
        status["smtp_login"] = "✅ התחברות SMTP הצליחה"
    except smtplib.SMTPAuthenticationError:
        status["smtp_login"] = "❌ שגיאת אימות — בדוק SMTP_USER ו-SMTP_PASSWORD"
    except Exception as e:
        status["smtp_login"] = f"❌ שגיאה: {e}"

    return status


@app.get("/test-email/send", tags=["health"])
async def test_email_send():
    from config import EMAIL_ENABLED, SMTP_USER
    from email_service import send_guardian_phishing_alert

    if not EMAIL_ENABLED:
        return {"success": False, "error": "EMAIL_ENABLED=false"}

    ok = send_guardian_phishing_alert(
        guardian_email=SMTP_USER,
        monitored_name="ילד לדוגמה",
        monitored_email="child@example.com",
        risk_score=85.0,
        phishing_sender="scammer@evil.com",
        phishing_subject="דחוף! אשר את החשבון שלך",
        risk_level="סכנה גבוהה",
    )
    return {"success": ok, "sent_to": SMTP_USER}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="localhost", port=8000, reload=True)