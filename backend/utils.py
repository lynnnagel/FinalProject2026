"""Shared utility helpers used across the LURA backend."""

from datetime import datetime, date


def today_start() -> datetime:
    """Return a datetime representing midnight (00:00:00) of the current UTC day."""
    today = date.today()
    return datetime(today.year, today.month, today.day, 0, 0, 0, 0)


def get_name_from_email(email: str) -> str:
    """Derive a display name from an e-mail address (part before '@')."""
    return email.split("@")[0]
