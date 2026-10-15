from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database: SQLite for v1 (swap to postgresql+asyncpg in production).
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR / 'vulnscan.db'}"

    # Fix generation. Leave OLLAMA_BASE_URL or ANTHROPIC_API_KEY empty to
    # use the offline template-based fix generator.
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:latest"
    FIX_GENERATOR_PROVIDER: str = "auto"  # auto | ollama | anthropic | template

    # Crawler / politeness.
    SCAN_DEFAULT_DELAY_MS: int = 250
    SCAN_MAX_CONCURRENT_REQUESTS: int = 5
    CRAWL_MAX_DEPTH: int = 5
    CRAWL_MAX_PAGES: int = 200
    RESPECT_ROBOTS_TXT: bool = True

    # Consent gate.
    CONSENT_CONFIRMATION_PHRASE_TEMPLATE: str = "I own or am authorized to test {domain}"

    # Auth/session checks.
    AUTH_LOGIN_ATTEMPT_COUNT: int = 10

    # XSS module.
    XSS_MAX_PLAYWRIGHT_ATTEMPTS: int = 20

    # Reporting.
    REPORT_OUTPUT_DIR: str = str(BASE_DIR / "reports")

    # Base URL of the API, used to build absolute report links when serving.
    APP_BASE_URL: str = "http://localhost:8000"


@lru_cache
def get_settings() -> Settings:
    return Settings()
