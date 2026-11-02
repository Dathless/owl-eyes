"""Bridge from immutable collection data to the configured provider profile."""

import httpx

from app.ai.analyzer import (
    REPAIR_POLICY_UTF8_BYTES,
    SNAPSHOT_POLICY_UTF8_BYTES,
    SYSTEM,
    AttemptObserver,
    analyze_scan,
    build_analysis_snapshot,
    provider_schema,
)
from app.ai.base import AnalysisError
from app.ai.providers import OllamaProvider, OpenAICompatibleProvider
from app.config import Settings
from app.schemas import AnalysisOutcome, ProviderId, ScanRecord


class AnalysisService:
    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.providers = {}
        if settings.ollama_enabled:
            self.providers[ProviderId.OLLAMA] = OllamaProvider(client, settings)
        if settings.openai_compatible_enabled:
            self.providers[ProviderId.OPENAI_COMPATIBLE] = OpenAICompatibleProvider(
                client, settings
            )

        for profile in settings.external_providers:
            if not profile.enabled:
                continue
            effective = settings.model_copy(
                update={
                    "openai_base_url": profile.base_url,
                    "openai_model": profile.model_id,
                    "openai_api_key": profile.api_key,
                    "openai_output_mode": profile.output_mode,
                    "openai_token_limit_field": profile.token_limit_field,
                }
            )
            provider = OpenAICompatibleProvider(client, effective)
            provider.provider_id = profile.provider_id
            self.providers[profile.provider_id] = provider

    async def __call__(self, scan: ScanRecord) -> AnalysisOutcome:
        return await self.analyze(scan)

    async def analyze(
        self, scan: ScanRecord, *, on_attempt: AttemptObserver | None = None
    ) -> AnalysisOutcome:
        provider = self.providers.get(scan.provider_id)
        if provider is None:
            return AnalysisOutcome(error=AnalysisError("provider_unavailable").error)
        try:
            input_budget = None
            if isinstance(provider, OllamaProvider):
                input_budget = (
                    provider.input_budget(
                        system=SYSTEM,
                        schema=provider_schema(),
                        output_tokens=self.settings.ai_output_tokens,
                    )
                    - REPAIR_POLICY_UTF8_BYTES
                    - SNAPSHOT_POLICY_UTF8_BYTES
                )
                if input_budget <= 0:
                    raise AnalysisError("context_length_exceeded")
            snapshot = build_analysis_snapshot(
                scan,
                self.settings,
                input_budget=input_budget,
                prioritize_signals=isinstance(provider, OllamaProvider),
            )
        except AnalysisError as error:
            return AnalysisOutcome(error=error.error)
        scan.partial |= snapshot.truncated
        return await analyze_scan(
            snapshot, provider, self.settings, on_attempt=on_attempt
        )
