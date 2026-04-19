"""
GET /metrics  –  System-level performance and KPI metrics.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import EmailRecord, User

router = APIRouter(tags=["metrics"])


@router.get("/metrics", summary="מטריקות מערכת")
async def get_metrics(db: Session = Depends(get_db)):
    """
    Return system performance metrics.

    Note: True FP/FN rates require a labelled ground-truth dataset.
    These will be populated in April 2026 after the training dataset
    (Kaggle + PhishTank + Enron) has been integrated and BERT is trained.
    """
    total_emails = db.query(EmailRecord).count()
    total_phishing = (
        db.query(EmailRecord).filter(EmailRecord.is_phishing == True).count()  # noqa: E712
    )

    active_users = db.query(User).filter(User.daily_active == True).count()  # noqa: E712
    total_users = db.query(User).count()

    # Baseline latency: heuristics-only (~0.3 s).
    # Will be updated to measured p95 after BERT integration.
    avg_response_time = 0.3

    return {
        "detection_accuracy": "N/A – requires labelled dataset",
        "total_emails_scanned": total_emails,
        "phishing_blocked": total_phishing,
        "false_positive_rate": "N/A – requires labelled dataset",
        "false_negative_rate": "N/A – requires labelled dataset",
        "avg_response_time_seconds": avg_response_time,
        "daily_active_users": active_users,
        "total_users": total_users,
        "active_user_percentage": (
            f"{(active_users / total_users * 100):.1f}%"
            if total_users > 0
            else "0.0%"
        ),
        "targets": {
            "detection_accuracy": "≥ 85%",
            "false_positive_rate": "< 10%",
            "false_negative_rate": "< 5%",
            "response_time_p95": "< 2 s",
            "daily_emails_per_user": "~ 10 / day",
            "active_user_ratio": "~ 50%",
        },
        "roadmap_note": (
            "FP/FN rates and accuracy will be calculated after the "
            "labelled dataset is integrated and BERT is fine-tuned (April 2026)."
        ),
    }
