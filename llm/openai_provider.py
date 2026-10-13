"""
Sentinel-MAS: OpenAI LLM Provider
===================================
Uses OpenAI's API (GPT-4o-mini, GPT-4o, etc.) for agent responses.
Only used when LLM_PROVIDER=openai in .env file.
"""

from llm.llm_provider import LLMProvider
from config.settings import settings


class OpenAIProvider(LLMProvider):
    """
    OpenAI-based LLM provider.
    Requires OPENAI_API_KEY in .env file.
    """

    def __init__(self):
        if not settings.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY not set in .env file. "
                "Either set it or use LLM_PROVIDER=mock"
            )
        
        from openai import OpenAI
        self._client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self._model = settings.get_llm_model()

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate a response using OpenAI's API."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=0.7,
                max_tokens=1000,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            print(f"[WARN] OpenAI API error: {e}")
            print("   Falling back to a default response.")
            return f"[OpenAI Error] Could not generate response: {str(e)}"

    def get_provider_name(self) -> str:
        return f"openai ({self._model})"
