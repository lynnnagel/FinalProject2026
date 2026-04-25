"""
POST /scan-url  – ניתוח קישור לזיהוי פישינג
"""
from fastapi import APIRouter
from pydantic import BaseModel

from url_detector import url_detector

router = APIRouter(tags=["url"])


class URLInput(BaseModel):
    url: str


@router.post("/scan-url")
async def scan_url(data: URLInput):
    if not data.url or len(data.url.strip()) < 4:
        return {
            "risk_score": 0,
            "risk_level": "לא תקין",
            "indicators": ["הזן כתובת URL תקינה"],
            "recommendation": "",
            "is_dangerous": False,
        }
    return url_detector.analyze_url(data.url.strip())