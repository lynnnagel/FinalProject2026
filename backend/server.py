"""
PhishGuard FastAPI Application
Run with: uvicorn server:app --host localhost --port 8000 --reload
"""
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
    title="PhishGuard API",
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
        "message": "PhishGuard API פעיל",
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="localhost", port=8000, reload=True)