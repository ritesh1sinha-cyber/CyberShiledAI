from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    qwen_base_url: str = "https://example.invalid/v1"
    qwen_api_key: str = ""
    qwen_model: str = "Qwen/Qwen3-8B"
    qwen_ca_cert: str = str(ROOT / "vm06-ca.crt")
    nvd_api_key: str = ""

    # Retrieval and the similarity metric both embed through this endpoint, so the
    # index and the scores a fresh checkout builds come from the same vectors.
    embeddings_base_url: str = "https://example.invalid/v1"
    embeddings_api_key: str = ""
    embeddings_model: str = "bge-small-en-v1.5"
    embeddings_ca_cert: str = str(ROOT / "vm02-ca.crt")

    max_steps: int = 10
    max_retries: int = 2
    http_timeout_s: float = 30.0
    investigation_timeout_s: float = 600.0
    api_base_url: str = "http://127.0.0.1:8000"
    trace_file: str = str(ROOT / "data" / "traces" / "investigations.jsonl")

    langfuse_enabled: bool = False
    langfuse_host: str = "http://127.0.0.1:3100"
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""


settings = Settings()
