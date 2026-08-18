"""
Database engine, session factory, and helper functions.
Import get_db() as a FastAPI dependency for DB access.
"""
import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DATABASE_URL

logger = logging.getLogger(__name__)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # needed for SQLite
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a DB session and closes it when done."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables that do not yet exist.
    Safe to call on every startup – existing data is NEVER dropped.
    """
    # Import models here so SQLAlchemy registers them on Base before create_all
    import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


# ---------------------------------------------------------------------------
# מיגרציה מינימלית
#
# create_all יוצר טבלאות חסרות, אך אינו נוגע בטבלה קיימת. עמודה שנוספה
# למודל אחרי שהמסד כבר נוצר פשוט לא תהיה שם, וכל שאילתה שמזכירה אותה
# תיפול ב-"no such column" — על מסד שכבר מכיל את היסטוריית הסריקות של
# המשתמש. הפונקציה מוסיפה עמודות חסרות בלבד; היא לעולם אינה מוחקת או
# משנה עמודה קיימת, ולכן בטוחה להרצה בכל עלייה.
#
# פרויקט גדול יותר היה משתמש ב-Alembic. כאן מדובר בעמודות בודדות,
# ותלות נוספת אינה מוצדקת.
# ---------------------------------------------------------------------------
_EXPECTED_COLUMNS = {
    "emails": {
        "scoring_version": "VARCHAR DEFAULT ''",
        "content_hash": "VARCHAR DEFAULT ''",
    },
}


def _add_missing_columns() -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table, columns in _EXPECTED_COLUMNS.items():
            if table not in existing_tables:
                continue
            present = {c["name"] for c in inspector.get_columns(table)}
            for column, ddl in columns.items():
                if column in present:
                    continue
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
                logger.info("נוספה עמודה חסרה: %s.%s", table, column)
