from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SIEM_", extra="ignore")
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = Field(default="siem", pattern=r"^[a-zA-Z0-9_-]+$")
    mongodb_server_selection_timeout_ms: int = Field(default=3000, ge=0)
    mongodb_connect_timeout_ms: int = Field(default=3000, ge=0)
    mongodb_socket_timeout_ms: int = Field(default=60000, ge=0)
    datasets_root: str = "ds/Datasets"
    ml_model_dir: str = "data/ml"
    ml_threads: int = Field(default=2, ge=1, le=32)
    raw_log_host: str = "127.0.0.1"
    raw_log_port: int = Field(default=0, ge=0, le=65535)
    auth_required: bool = True
    session_cookie_secure: bool = True
