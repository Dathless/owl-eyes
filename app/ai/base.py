"""Provider boundary and fixed public failures; upstream bodies stay private."""

from typing import Protocol

from app.schemas import ErrorInfo, ProviderKey

MESSAGES = {
    "provider_auth_failed": "Provider authentication failed.",
    "provider_unreachable": "Provider could not be reached.",
    "provider_rate_limited": "Provider rate limit reached.",
    "provider_timeout": "Analysis deadline or provider timeout reached.",
    "provider_response_too_large": "Provider response exceeds its byte limit.",
    "provider_model_missing": "Configured model is unavailable.",
    "unsupported_output_mode": "Provider does not support the configured output mode.",
    "provider_redirect_rejected": "Provider redirects are disabled.",
    "provider_refusal": "Provider declined the analysis request.",
    "provider_output_truncated": "Provider output was incomplete.",
    "provider_tool_call_rejected": "Provider attempted an unsupported tool call.",
    "invalid_provider_response": "Provider returned an invalid response envelope.",
    "context_length_exceeded": "Provider context is too small for this analysis.",
    "invalid_analysis": "Analysis failed schema or semantic validation.",
    "unknown_evidence": "Analysis references evidence outside the supplied snapshot.",
    "snapshot_budget_exceeded": "Analysis metadata exceeds its input budget.",
    "no_usable_evidence": "No evidence fits the analysis snapshot.",
    "provider_unavailable": "The selected provider is not configured.",
    "internal_analysis_error": "Analysis could not be completed.",
}


class AnalysisError(Exception):
    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        retry_after: float = 0,
        repair_hint: str = "",
        detail: str = "",
    ):
        message = MESSAGES[code] + (" " + detail if detail else "")
        self.error = ErrorInfo(code=code, message=message[:240], retryable=retryable)
        self.retry_after = min(max(retry_after, 0), 5)
        self.repair_hint = repair_hint
        super().__init__(code)


class AIProvider(Protocol):
    provider_id: ProviderKey
    model: str

    async def generate(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, object],
        output_tokens: int,
        deadline: float,
    ) -> str: ...
