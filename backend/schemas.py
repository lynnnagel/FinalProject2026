"""
Pydantic request/response schemas for the PhishGuard API.
"""
from typing import List
from pydantic import BaseModel, EmailStr


# ---------------------------------------------------------------------------
# /scan
# ---------------------------------------------------------------------------
class EmailInput(BaseModel):
    user_email: EmailStr
    sender: str
    subject: str
    content: str


class RiskAnalysis(BaseModel):
    risk_score: float
    is_phishing: bool
    risk_level: str
    indicators: List[str]
    recommendation: str
    response_time: float


# ---------------------------------------------------------------------------
# /stats
# ---------------------------------------------------------------------------
class UserStats(BaseModel):
    total_scanned: int
    phishing_blocked: int
    risk_score: float
    daily_active: bool
    recent_alerts: int


# ---------------------------------------------------------------------------
# /guardian
# ---------------------------------------------------------------------------
class GuardianConnectRequest(BaseModel):
    child_email: EmailStr
    parent_email: EmailStr


class GuardianData(BaseModel):
    child_name: str
    child_email: str
    risk_score: float
    recent_alerts: List[dict]
    phishing_blocked_today: int
