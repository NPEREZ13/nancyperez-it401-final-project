class AiService:
    """Wraps calls to an LLM or other AI provider."""

    def __init__(self, api_key=None):
        self.api_key = api_key

    def generate(self, prompt, **kwargs):
        # Placeholder implementation — wire up to your chosen AI provider's SDK.
        raise NotImplementedError("AiService.generate is not implemented yet")
