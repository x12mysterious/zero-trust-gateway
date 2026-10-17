from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings

Base = declarative_base()

_pool_kwargs: dict = {}
if ":memory:" in settings.database_url:
    _pool_kwargs["poolclass"] = StaticPool

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    **_pool_kwargs,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
