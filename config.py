import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # Heroku may provide postgres:// (deprecated scheme). Convert to postgresql:// for SQLAlchemy.
    uri = os.getenv("DATABASE_URL", "sqlite:///local.db")
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Heroku Key-Value Store may provide REDIS_TLS_URL, while REDIS_URL may be absent.
    REDIS_URL = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"

    # Internal-only tool flag (purely informational; use network restrictions for real protection)
    INTERNAL_ONLY = True
