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

from database import init_db
from API.scan import router as scan_router
from API.stats import router as stats_router
from API.guardian import router as guardian_router
from API.metrics import router as metrics_router

app = FastAPI(
    title="PhishGuard API",
    description="זיהוי פישינג בזמן אמת – Real-time phishing detection with Guardian Mode",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# allow_origins=["*"] + allow_credentials=False is required because Gmail
# sends requests from https://mail.google.com which is not a chrome-extension origin
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


@app.get("/", tags=["health"])
async def root():
    return {
        "message": "PhishGuard API פעיל",
        "version": "1.0.0",
        "endpoints": {
            "scan":             "POST /scan",
            "stats":            "GET  /stats/{user_email}",
            "guardian_connect": "POST /guardian/connect",
            "guardian_data":    "GET  /guardian/{parent_email}",
            "metrics":          "GET  /metrics",
            "swagger_docs":     "GET  /docs",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="localhost", port=8000, reload=True)
