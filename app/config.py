from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    jwt_secret: str = "dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    step_up_expire_minutes: int = 5
    step_up_token_expire_minutes: int = 10
    database_url: str = "sqlite:///./zero_trust.db"

    # Configurable risk thresholds (academic prototype — not industry-standard)
    risk_low_max: int = 29
    risk_medium_max: int = 59

    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    login_rate_limit: int = 10

    supported_os: list[str] = ["windows", "macos", "linux"]
    business_hour_start: int = 8
    business_hour_end: int = 18

    class Config:
        env_file = ".env"


settings = Settings()
