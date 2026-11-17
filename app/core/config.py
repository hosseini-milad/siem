from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SIEM_")
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = Field(default="siem", pattern=r"^[a-zA-Z0-9_-]+$")
    mongodb_server_selection_timeout_ms: int = Field(default=3000, ge=0)
    mongodb_connect_timeout_ms: int = Field(default=3000, ge=0)
    mongodb_socket_timeout_ms: int = Field(default=60000, ge=0)
    datasets_root: str = "ds/Datasets"
    ml_model_dir: str = "data/ml"
    ml_threads: int = Field(default=2, ge=1, le=32)
    elasticsearch_url: AnyHttpUrl = 'http://127.0.0.1:9200'
    elasticsearch_index: str = Field(default='siem-events', pattern=r'^[a-z0-9][a-z0-9_-]{0,127}$')
    logstash_url: AnyHttpUrl = 'http://127.0.0.1:9600'
    logstash_input_url: AnyHttpUrl = 'http://127.0.0.1:8080'
    kibana_url: AnyHttpUrl = 'http://127.0.0.1:5601'
    elk_timeout_seconds: float = Field(default=10, gt=0, le=120)
