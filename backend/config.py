"""
VulnGuard AI - Configuration management
Loads settings from environment variables with sane defaults for local/dev use.
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me-in-production")
    JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.environ.get("JWT_EXPIRES_HOURS", 12)))

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'vulnguard.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

    # Scanner safety limits — keep this tool scoped to authorized lab/local testing
    MAX_CRAWL_PAGES = int(os.environ.get("MAX_CRAWL_PAGES", 25))
    MAX_CRAWL_DEPTH = int(os.environ.get("MAX_CRAWL_DEPTH", 3))
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 8))
    CONCURRENT_REQUESTS = int(os.environ.get("CONCURRENT_REQUESTS", 6))
    RATE_LIMIT_DELAY = float(os.environ.get("RATE_LIMIT_DELAY", 0.15))

    REPORTS_DIR = os.path.join(BASE_DIR, "reports", "generated")
