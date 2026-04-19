"""
Database engine, session factory, and helper functions.
Import get_db() as a FastAPI dependency for DB access.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DATABASE_URL

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
