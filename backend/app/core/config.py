"""MiniSOC application settings.

Loads configuration from environment variables and .env file.
Includes detection engine thresholds and windows.
"""

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings

# Absolute path to backend directory (contains app/, tests/, minisoc.db)
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_FILE = BACKEND_DIR / "minisoc.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DB_FILE.as_posix()}"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "MiniSOC Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"  # Secure default: production

    # Database: resolved relative to backend directory by default, overridable by DATABASE_URL env var
    DATABASE_URL: str = DEFAULT_DATABASE_URL

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def resolve_database_url(cls, v: str | None) -> str:
        """Resolve SQLite relative paths relative to BACKEND_DIR rather than process CWD."""
        if not v:
            return DEFAULT_DATABASE_URL
        prefix = "sqlite:///"
        if v.startswith(prefix):
            raw_path = v[len(prefix):]
            if raw_path == ":memory:":
                return v
            path_obj = Path(raw_path)
            if not path_obj.is_absolute():
                clean_str = raw_path.lstrip("./").lstrip(".\\")
                resolved = (BACKEND_DIR / clean_str).resolve()
                return f"{prefix}{resolved.as_posix()}"
        return v

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Threat Detection Thresholds and Windows
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_MINUTES: int = 5

    SUCCESSFUL_LOGIN_AFTER_BF_WINDOW_MINUTES: int = 10

    PORT_SCAN_PORT_THRESHOLD: int = 10
    PORT_SCAN_WINDOW_MINUTES: int = 2

    POWERSHELL_INCIDENT_WINDOW_MINUTES: int = 5

    SUSPICIOUS_POWERSHELL_INDICATORS: list[str] = [
        "-encodedcommand",
        "-enc",
        "iex",
        "invoke-expression",
        "downloadstring",
        "-windowstyle hidden",
        "-executionpolicy bypass",
    ]

    @property
    def allowed_origins_list(self) -> list[str]:
        """Parse comma-separated origins into a list."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    model_config = {
        "env_file": (BACKEND_DIR / ".env", ".env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()
