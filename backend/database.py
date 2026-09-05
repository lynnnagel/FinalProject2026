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
# A minimal migration
#
# create_all creates missing tables but never touches an existing one. A
# column added to a model after the database was created simply is not
# there, and any query mentioning it fails with "no such column" - on a
# database that already holds the user's scan history. This function
# only adds missing columns; it never drops or alters an existing one,
# so it is safe to run on every startup.
#
# A larger project would use Alembic. Here it is a couple of columns,
# and another dependency is not worth it.
# ---------------------------------------------------------------------------
_EXPECTED_COLUMNS = {
    "emails": {
        "scoring_version": "VARCHAR DEFAULT ''",
        "content_hash": "VARCHAR DEFAULT ''",
        "indicators": "VARCHAR DEFAULT ''",
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
                logger.info("Added missing column: %s.%s", table, column)
