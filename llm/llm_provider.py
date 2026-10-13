"""
Sentinel-MAS: LLM Provider Interface
=====================================
Abstract base class for all LLM providers.
This makes the LLM modular — swap between OpenAI, Groq, or Mock mode
without changing any agent code.

Usage:
    from llm.llm_provider import get_llm_provider
    llm = get_llm_provider()
    response = llm.generate("What is AI security?")
"""

from abc import ABC, abstractmethod
from config.settings import settings


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    
    Every LLM provider (OpenAI, Groq, Mock) must implement
    the 'generate' method. This way, agents don't care which
    LLM they're using — they just call generate().
    """

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: The user/task prompt to send to the LLM
            system_prompt: Optional system-level instructions
            
        Returns:
            The LLM's text response
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the name of this provider (e.g., 'mock', 'openai')."""
        pass


def get_llm_provider() -> LLMProvider:
    """
    Factory function: creates the right LLM provider based on settings.
    
    Reads LLM_PROVIDER from .env file:
    - "mock"   → MockProvider (no API key needed, works offline)
    - "openai" → OpenAIProvider (needs OPENAI_API_KEY)
    - "groq"   → GroqProvider (needs GROQ_API_KEY)
    
    Returns:
        An instance of the appropriate LLMProvider
    """
    provider = settings.LLM_PROVIDER.lower()

    if provider == "mock":
        from llm.mock_provider import MockProvider
        return MockProvider()
    elif provider == "openai":
        from llm.openai_provider import OpenAIProvider
        return OpenAIProvider()
    elif provider == "groq":
        from llm.groq_provider import GroqProvider
        return GroqProvider()
    else:
        print(f"[WARN] Unknown LLM provider '{provider}', falling back to mock mode.")
        from llm.mock_provider import MockProvider
        return MockProvider()
