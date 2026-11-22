import os

try:
    from pydantic_settings import BaseSettings
    
    class Settings(BaseSettings):
        PROJECT_NAME: str = "AI Password Auditor"
        API_V1_STR: str = "/api/v1"
        SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-for-ai-password-auditor-12345")
        ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
        
        # Database
        DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/password_auditor")
        
        # ML Model Configs
        MODEL_DIR: str = os.path.dirname(os.path.abspath(__file__)) + "/../models"
        MODEL_PATH: str = MODEL_DIR + "/classifier.joblib"
        
        # Security Policy Defaults
        MIN_PASSWORD_LENGTH: int = 12
        MIN_ENTROPY: float = 60.0 # bits
        
        class Config:
            case_sensitive = True
            
    settings = Settings()
except Exception:
    # Minimal fallback configuration if pydantic_settings is missing
    class FallbackSettings:
        PROJECT_NAME = "AI Password Auditor"
        API_V1_STR = "/api/v1"
        SECRET_KEY = "super-secret-key-for-ai-password-auditor-12345"
        ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 8
        DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/password_auditor"
        MODEL_DIR = os.path.dirname(os.path.abspath(__file__)) + "/../models"
        MODEL_PATH = MODEL_DIR + "/classifier.joblib"
        MIN_PASSWORD_LENGTH = 12
        MIN_ENTROPY = 60.0
    settings = FallbackSettings()

