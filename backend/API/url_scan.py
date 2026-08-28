"""
POST /scan-url - analyse a single link.

The rule engine only: there is no message to give the model. This backs
the "check a link" box on the home page, which is the one thing a
visitor can try without installing anything.
"""
from fastapi import APIRouter
from pydantic import BaseModel

from url_detector import url_detector

router = APIRouter(tags=["url"])


class URLInput(BaseModel):
    url: str


@router.post("/scan-url")
def scan_url(data: URLInput):
    if not data.url or len(data.url.strip()) < 4:
        return {
            "risk_score": 0,
            "risk_level": "לא תקין",
            "indicators": ["הזן כתובת URL תקינה"],
            "recommendation": "",
            "is_dangerous": False,
            "url": data.url or "",
        }
    return url_detector.analyze_url(data.url.strip())