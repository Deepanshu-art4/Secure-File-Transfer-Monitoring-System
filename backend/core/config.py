import os
from pathlib import Path
from typing import List, Set
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application Settings loaded from environment variables and .env file.
    Follows 12-factor application security best practices.
    """
    # Meta
    PROJECT_NAME: str = "Secure File Transfer Monitoring System"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api"

    # Cryptography & JWT Security
    SECRET_KEY: str = "change-this-in-production-to-a-very-long-and-cryptographically-secure-random-secret"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours

    # Database
    DATABASE_URL: str = "sqlite:///./secure_transfer.db"

    # File Storage Paths (Resolved relative to project/backend root)
    STORAGE_DIR: str = "storage/uploads"
    QUARANTINE_DIR: str = "storage/quarantine"
    REPORTS_DIR: str = "storage/reports"

    # File Upload Restrictions
    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_EXTENSIONS: str = "pdf,docx,xlsx,txt,zip,tar,gz,csv,png,jpg,jpeg,json,xml"

    # Detection Engine Thresholds (Configurable)
    RULE_LARGE_FILE_MB: int = 50
    RULE_WORK_HOURS_START: int = 9   # 09:00 (9 AM)
    RULE_WORK_HOURS_END: int = 18    # 18:00 (6 PM)
    RULE_EXCESSIVE_TRANSFERS_COUNT: int = 10
    RULE_EXCESSIVE_WINDOW_MINUTES: int = 10
    RULE_FAILED_ATTEMPTS_THRESHOLD: int = 3

    # Threat Intelligence Integration
    ABUSEIPDB_API_KEY: str = ""

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def allowed_extensions_set(self) -> Set[str]:
        return {ext.strip().lower().lstrip(".") for ext in self.ALLOWED_EXTENSIONS.split(",") if ext.strip()}

    @property
    def max_upload_size_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    def ensure_directories_exist(self, base_dir: Path | None = None) -> None:
        """Ensures all isolated storage directories exist with proper access permissions."""
        base = base_dir or Path(__file__).resolve().parent.parent
        for path_str in [self.STORAGE_DIR, self.QUARANTINE_DIR, self.REPORTS_DIR]:
            dir_path = base / path_str if not os.path.isabs(path_str) else Path(path_str)
            dir_path.mkdir(parents=True, exist_ok=True)


settings = Settings()
