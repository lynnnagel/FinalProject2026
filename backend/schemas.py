"""
Pydantic request/response schemas for the PhishGuard API.
"""
from typing import List, Optional
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
class AlertSummary(BaseModel):
    risk_level: str
    message: str
    created_at: Optional[str] = None


class UserStats(BaseModel):
    total_scanned: int
    phishing_blocked: int
    risk_score: float
    daily_active: bool
    recent_alerts: int
    recent_alerts_list: List[AlertSummary] = []


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


# /auth
#------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str
    email: str
    name: str


class UserProfile(BaseModel):
    email: str
    name: str
    total_scanned: int
    phishing_blocked: int
    risk_score: float
    daily_active: bool