from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SIEM_", extra="ignore")
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = Field(default="siem", pattern=r"^[a-zA-Z0-9_-]+$")
    mongodb_server_selection_timeout_ms: int = Field(default=3000, ge=0)
    mongodb_connect_timeout_ms: int = Field(default=3000, ge=0)
    mongodb_socket_timeout_ms: int = Field(default=60000, ge=0)
    datasets_root: str = "ds/Datasets"
    system_log_datasets_root: str = "ds/OS"
    ml_model_dir: str = "data/ml"
    ml_threads: int = Field(default=2, ge=1, le=32)
    raw_log_host: str = "127.0.0.1"
    raw_log_port: int = Field(default=0, ge=0, le=65535)
    http_log_token: SecretStr | None = None
    web_access_log_path: str | None = None
    web_local_collector_enabled: bool = True
    web_local_collector_endpoint: str = "http://127.0.0.1:8000/api/v1/web-services/batches"
    web_collector_keys: dict[str, SecretStr] = Field(default_factory=dict)
    auth_required: bool = True
    session_cookie_secure: bool = True
