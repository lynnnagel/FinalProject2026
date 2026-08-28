"""Pydantic request/response schemas for the LURA API."""

from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


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
    # The guardian always comes from the token, never from here. The
    # field is kept because the extension and the page still send it,
    # and it is optional so that a stray value cannot turn a working
    # request into a 422.
    parent_email: Optional[EmailStr] = None


class GuardianData(BaseModel):
    child_name: str
    child_email: str
    risk_score: float
    recent_alerts: List[dict]
    phishing_blocked_today: int


class WatchedAccount(BaseModel):
    """
    One account a guardian watches, and how far it is through setup.

    Linking an address is only the first of three steps - the person
    also has to open an account and sign the extension in - and until
    now nothing said which of them was still missing. `state` is what
    the dashboard turns into a sentence.
    """
    email: str
    name: str
    state: str            # needs_account | needs_extension | active
    risk_score: float
    total_scanned: int
    phishing_blocked_today: int
    last_scan: Optional[str] = None


class WatchedList(BaseModel):
    accounts: List[WatchedAccount]


# /auth
#------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    """Asks for a reset link. Carries no password."""
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """
    The reset itself. Identified only by the token sent to the mailbox -
    there is no email field, so nobody can reset a stranger's password.
    """
    token: str
    new_password: str = Field(min_length=8)

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

# ------------------------------------------------------------------------------
# /trusted-senders
# ------------------------------------------------------------------------------

class TrustedSenderRequest(BaseModel):
    """A full address (a@b.com) or a domain (b.com)."""
    value: str = Field(min_length=3, max_length=254)


class TrustedSenderItem(BaseModel):
    value: str
    is_domain: bool


class TrustedSenderList(BaseModel):
    senders: list[TrustedSenderItem]
