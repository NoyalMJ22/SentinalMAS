"""
Sentinel-MAS: Groq LLM Provider
=================================
Uses Groq's API (free tier with Llama models) for agent responses.
Only used when LLM_PROVIDER=groq in .env file.
"""

from llm.llm_provider import LLMProvider
from config.settings import settings


class GroqProvider(LLMProvider):
    """
    Groq-based LLM provider.
    Requires GROQ_API_KEY in .env file.
    Groq offers a free tier which is great for students!
    """

    def __init__(self):
        if not settings.GROQ_API_KEY:
            raise ValueError(
                "GROQ_API_KEY not set in .env file. "
                "Either set it or use LLM_PROVIDER=mock"
            )
        
        from groq import Groq
        self._client = Groq(api_key=settings.GROQ_API_KEY)
        self._model = settings.get_llm_model()

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate a response using Groq's API."""
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
            print(f"[WARN] Groq API error: {e}")
            print("   Falling back to a default response.")
            return f"[Groq Error] Could not generate response: {str(e)}"

    def get_provider_name(self) -> str:
        return f"groq ({self._model})"
