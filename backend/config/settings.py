from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    security_level: str = "LOW"
    llm_provider: str = "ollama"

    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    # Base URL for internal HTTP calls (tool sandbox → banking APIs in same container).
    internal_api_base_url: str = "http://127.0.0.1:8000"

    # Gateway/auth
    jwt_secret: str = "dev-insecure-secret"
    jwt_issuer: str = "agenthive"
    jwt_audience: str = "nexabank"
    access_token_ttl_s: int = 3600

    # Rate limiting (requests per window)
    rate_limit_window_s: int = 60
    rate_limit_requests_low: int = 10_000  # intentionally permissive
    rate_limit_requests_medium: int = 600
    rate_limit_requests_hard: int = 120
    rate_limit_requests_secure: int = 60
    redis_url: str = "redis://redis:6379/0"

    # Audit log path (jsonl)
    audit_log_path: str = "/data/audit.jsonl"

    # LLM keys / endpoints / models
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"

    anthropic_api_key: str | None = None
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-3-5-sonnet-latest"

    gemini_api_key: str | None = None
    gemini_base_url: str = "https://generativelanguage.googleapis.com"
    gemini_model: str = "gemini-1.5-flash"

    # Leave blank to auto-detect (host Ollama first, then docker ollama service)
    ollama_base_url: str = ""
    ollama_model: str = "qwen2.5:7b"
    ollama_embedding_model: str = "nomic-embed-text"

    llm_timeout_s: float = 30.0


settings = Settings()

