from llm.base_provider import LLMProviderError


class LLMProviderConfigError(LLMProviderError):
    """Configuration error (missing key, invalid model, etc.)."""

    def __init__(self, message: str, provider: str = "config") -> None:
        super().__init__(message, provider=provider, retryable=False, original=None)

