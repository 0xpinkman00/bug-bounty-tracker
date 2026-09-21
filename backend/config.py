from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str = 'postgresql+psycopg://tracker:tracker@127.0.0.1:5433/tracker'
    redis_url: str = 'redis://localhost:6379/0'
    github_token: str = ''
    backend_port: int = 8000
    frontend_port: int = 5173
    notify_enabled: bool = True

settings = Settings()
