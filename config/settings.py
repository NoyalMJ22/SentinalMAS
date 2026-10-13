"""
Sentinel-MAS: Centralized Configuration
========================================
Loads settings from .env file and provides defaults.
All configuration is accessed through the 'settings' object.

Usage:
    from config.settings import settings
    print(settings.LLM_PROVIDER)
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ============================================
# Load .env file from project root
# ============================================
# Path(__file__) = this file (settings.py)
# .parent = config/
# .parent = project root (SentinalMAS/)
PROJECT_ROOT = Path(__file__).parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class Settings:
    """
    Central configuration for Sentinel-MAS.
    
    Reads from environment variables (set in .env file).
    Provides sensible defaults so the project works out of the box.
    """

    def __init__(self):
        # --- Project Paths ---
        self.PROJECT_ROOT: Path = PROJECT_ROOT
        self.LOG_DIR: Path = PROJECT_ROOT / os.getenv("LOG_DIR", "data/logs")
        
        # Create log directory if it doesn't exist
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)

        # --- LLM Provider ---
        # Options: "mock", "openai", "groq"
        self.LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "mock")
        self.OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
        self.GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
        self.LLM_MODEL: str = os.getenv("LLM_MODEL", "")

        # Default model names per provider
        self.DEFAULT_MODELS: dict = {
            "openai": "gpt-4o-mini",
            "groq": "llama-3.1-8b-instant",
            "mock": "mock-model",
        }

        # --- Neo4j ---
        self.NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
        self.NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")

        # --- Application ---
        self.DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

        # --- Agent Names (for reference throughout the system) ---
        self.AGENT_NAMES: list = [
            "ResearchAgent",
            "AnalystAgent",
            "ManagerAgent",
            "AttackerAgent",
            "DefenderAgent",
        ]

    def get_llm_model(self) -> str:
        """Get the LLM model name. Uses explicit setting or falls back to default."""
        if self.LLM_MODEL:
            return self.LLM_MODEL
        return self.DEFAULT_MODELS.get(self.LLM_PROVIDER, "mock-model")

    def __repr__(self) -> str:
        return (
            f"Settings(\n"
            f"  LLM_PROVIDER={self.LLM_PROVIDER},\n"
            f"  LLM_MODEL={self.get_llm_model()},\n"
            f"  NEO4J_URI={self.NEO4J_URI},\n"
            f"  LOG_DIR={self.LOG_DIR},\n"
            f"  DEBUG={self.DEBUG}\n"
            f")"
        )


# ============================================
# Create a single settings instance
# ============================================
# Import this anywhere: from config.settings import settings
settings = Settings()
