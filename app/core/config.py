from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SIEM_")
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = Field(default="siem", pattern=r"^[a-zA-Z0-9_-]+$")
    datasets_root: str = "ds/Datasets"
