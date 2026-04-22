"""
PhishGuard FastAPI Application
================================
Entry-point for the backend server.

Run with:
    uvicorn server:app --host localhost --port 8000 --reload

Or directly:
    python server.py
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import CORS_ORIGIN_REGEX
from database import init_db
from API.scan import router as scan_router
from API.stats import router as stats_router
from API.guardian import router as guardian_router
from API.metrics import router as metrics_router

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="PhishGuard API",
    description="זיהוי פישינג בזמן אמת – Real-time phishing detection with Guardian Mode",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS – allow Chrome/Firefox extensions and local development
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Database initialisation
# CREATE TABLE IF NOT EXISTS – existing data is NEVER dropped.
# ---------------------------------------------------------------------------
init_db()

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(scan_router)
app.include_router(stats_router)
app.include_router(guardian_router)
app.include_router(metrics_router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/", tags=["health"])
async def root():
    return {
        "message": "PhishGuard API פעיל",
        "version": "1.0.0",
        "endpoints": {
            "scan":              "POST /scan",
            "stats":             "GET  /stats/{user_email}",
            "guardian_connect":  "POST /guardian/connect",
            "guardian_data":     "GET  /guardian/{parent_email}",
            "metrics":           "GET  /metrics",
            "swagger_docs":      "GET  /docs",
        },
    }


# ---------------------------------------------------------------------------
# Dev-server entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="localhost", port=8000, reload=True)
