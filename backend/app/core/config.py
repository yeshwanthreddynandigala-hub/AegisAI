"""
Application Configuration and Constants.
Provides environment-aware configuration for paths, databases, and security parameters.
"""

from pathlib import Path
from pydantic import BaseModel
import os

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_DIR = BASE_DIR.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

SYNTHETIC_ENV_DIR = BASE_DIR / "synthetic_sandbox"
SYNTHETIC_ENV_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = DATA_DIR / "agent_sentinel.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH.as_posix()}")

class Settings(BaseModel):
    app_name: str = "AI Agent Behavior Security & Threat Investigation System"
    app_version: str = "1.0.0"
    debug: bool = False
    database_url: str = DATABASE_URL
    base_dir: Path = BASE_DIR
    synthetic_env_dir: Path = SYNTHETIC_ENV_DIR
    max_policy_denials_before_lockout: int = 3
    ml_model_dir: Path = BASE_DIR / "models_storage"

    # Optional External LLM Config
    llm_provider: str = os.getenv("LLM_PROVIDER", "offline")  # offline | gemini | openai
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model_name: str = os.getenv("LLM_MODEL_NAME", "mock-analyst-v1")

settings = Settings()
settings.ml_model_dir.mkdir(parents=True, exist_ok=True)
