from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # SQL Server
    SQL_SERVER_HOST: str = "localhost"
    SQL_SERVER_PORT: int = 1433
    SQL_SERVER_DB: str = "sealr"
    SQL_SERVER_USER: str = "sa"
    SQL_SERVER_PASSWORD: str = "Sealr@Dev123"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # AI Models
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-5.4"
    OPENAI_THINKING_MODEL: str = "gpt-5.4-thinking"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-opus-4-6"

    # Security
    ENCRYPTION_KEY: str = ""
    JWT_SECRET: str = "dev-secret-change-in-production"

    # GitHub
    GITHUB_API_BASE: str = "https://api.github.com"
    GITHUB_WEBHOOK_SECRET: str = ""
    GITHUB_APP_ID: str = ""
    GITHUB_APP_PRIVATE_KEY: str = ""

    # Frontend
    FRONTEND_URL: str = "http://localhost:3000"

    # Docker
    DOCKER_HOST: str = "unix:///var/run/docker.sock"

    # S3 / MinIO
    S3_ENDPOINT: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = "sealr"
    S3_SECRET_KEY: str = "sealr123"
    S3_BUCKET: str = "sealr-scans"

    # Logging
    LOG_LEVEL: str = "info"

    # Dev mode: use SQLite + in-process tasks, no Docker/DB/Redis required
    DEV_MODE: bool = False

    @property
    def database_url(self) -> str:
        if self.DEV_MODE:
            return "sqlite+aiosqlite:///./sealr_dev.db"
        return (
            f"mssql+aioodbc://{self.SQL_SERVER_USER}:{self.SQL_SERVER_PASSWORD}"
            f"@{self.SQL_SERVER_HOST}:{self.SQL_SERVER_PORT}/{self.SQL_SERVER_DB}"
            f"?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
        )

    @property
    def sync_database_url(self) -> str:
        if self.DEV_MODE:
            return "sqlite:///./sealr_dev.db"
        return (
            f"mssql+pyodbc://{self.SQL_SERVER_USER}:{self.SQL_SERVER_PASSWORD}"
            f"@{self.SQL_SERVER_HOST}:{self.SQL_SERVER_PORT}/{self.SQL_SERVER_DB}"
            f"?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
        )

    model_config = {"env_file": (".env", "../.env"), "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
