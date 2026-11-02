"""Two explicit HTTP profiles with capped decoded bodies and absolute deadlines."""

import asyncio
import json
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import anyio
import httpx

from app.ai.base import AnalysisError
from app.config import Settings
from app.schemas import ProviderId


def retry_delay(value: str | None) -> float:
    if not value:
        return 0
    try:
        seconds = float(value)
        if seconds != seconds:
            return 0
        return min(max(seconds, 0), 5)
    except ValueError:
        try:
            return min(
                max(
                    (
                        parsedate_to_datetime(value).astimezone(UTC) - datetime.now(UTC)
                    ).total_seconds(),
                    0,
                ),
                5,
            )
        except (ValueError, TypeError, OverflowError):
            return 0


class HTTPProvider:
    def __init__(self, client: httpx.AsyncClient, settings: Settings):
        self.client, self.settings = client, settings
        self.last_usage: dict[str, int] = {}

    async def _post(self, url: str, body: dict, headers: dict, deadline: float) -> dict:
        scope = anyio.CancelScope()

        async def send() -> dict | None:
            with scope:
                return await self._request(url, body, headers, deadline)
            return None

        request = asyncio.create_task(send())
        try:
            async with asyncio.timeout_at(deadline):
                try:
                    result = await asyncio.shield(request)
                except asyncio.CancelledError:
                    # Keep asyncio cancellation outside HTTPX's nested cancel scopes.
                    scope.cancel()
                    while not request.done():
                        try:
                            await asyncio.shield(request)
                        except asyncio.CancelledError:
                            continue
                        except Exception:
                            break
                    if not request.cancelled():
                        request.exception()
                    raise
        except TimeoutError:
            raise AnalysisError("provider_timeout", retryable=True) from None
        assert result is not None
        return result

    async def _request(
        self, url: str, body: dict, headers: dict, deadline: float
    ) -> dict:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise AnalysisError("provider_timeout", retryable=True)
        try:
            async with asyncio.timeout_at(deadline):
                async with self.client.stream(
                    "POST",
                    url,
                    json=body,
                    headers=headers,
                    follow_redirects=False,
                    timeout=httpx.Timeout(remaining, connect=min(10, remaining)),
                ) as response:
                    if response.status_code in (401, 403):
                        raise AnalysisError("provider_auth_failed")
                    if response.status_code == 404:
                        raise AnalysisError("provider_model_missing")
                    if response.status_code == 429:
                        raise AnalysisError(
                            "provider_rate_limited",
                            retryable=True,
                            retry_after=retry_delay(
                                response.headers.get("Retry-After")
                            ),
                        )
                    if 500 <= response.status_code <= 599:
                        raise AnalysisError(
                            "provider_unreachable",
                            retryable=True,
                            retry_after=retry_delay(
                                response.headers.get("Retry-After")
                            ),
                        )
                    if 300 <= response.status_code <= 399:
                        raise AnalysisError("provider_redirect_rejected")
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        if (
                            len(chunks) + len(chunk)
                            > self.settings.ai_max_response_bytes
                        ):
                            raise AnalysisError("provider_response_too_large")
                        chunks.extend(chunk)
                    try:
                        value = json.loads(chunks)
                    except (ValueError, UnicodeError, RecursionError):
                        raise AnalysisError("invalid_provider_response") from None
                    if not isinstance(value, dict):
                        raise AnalysisError("invalid_provider_response")
                    if response.status_code >= 400:
                        error = str(value.get("error", "")).lower()
                        if "context_length" in error or "context length" in error:
                            raise AnalysisError("context_length_exceeded")
                        if any(
                            word in error
                            for word in (
                                "response_format",
                                "json_schema",
                                "format",
                                "schema",
                            )
                        ):
                            raise AnalysisError("unsupported_output_mode")
                        if "model" in error and any(
                            word in error
                            for word in ("not found", "not exist", "missing")
                        ):
                            raise AnalysisError("provider_model_missing")
                        raise AnalysisError("invalid_provider_response")
                    return value
        except (TimeoutError, httpx.TimeoutException):
            raise AnalysisError("provider_timeout", retryable=True) from None
        except httpx.RequestError:
            raise AnalysisError("provider_unreachable", retryable=True) from None


class OllamaProvider(HTTPProvider):
    provider_id = ProviderId.OLLAMA

    def __init__(self, client: httpx.AsyncClient, settings: Settings):
        super().__init__(client, settings)
        self.model = settings.ollama_model

    def input_budget(self, *, system: str, schema: dict, output_tokens: int) -> int:
        # A byte upper bound avoids relying on a model-specific tokenizer.
        overhead = len(
            (
                system
                + "\nReturn JSON matching this schema: "
                + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
            ).encode()
        )
        return self.settings.ollama_context_tokens - output_tokens - 256 - overhead

    def validate_context(
        self, *, system: str, user: str, schema: dict, output_tokens: int
    ) -> None:
        if len(user.encode()) > self.input_budget(
            system=system, schema=schema, output_tokens=output_tokens
        ):
            raise AnalysisError("context_length_exceeded")

    async def generate(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, object],
        output_tokens: int,
        deadline: float,
    ) -> str:
        self.validate_context(
            system=system, user=user, schema=schema, output_tokens=output_tokens
        )
        self.last_usage = {}
        grounded_system = (
            system
            + "\nReturn JSON matching this schema: "
            + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
        )
        data = await self._post(
            self.settings.ollama_base_url + "/api/chat",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": grounded_system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "format": schema,
                "options": {
                    "num_predict": output_tokens,
                    "num_thread": self.settings.ollama_num_threads,
                    "temperature": 0,
                    "num_ctx": self.settings.ollama_context_tokens,
                },
            },
            {},
            deadline,
        )
        self.last_usage = {
            key: data[key]
            for key in ("prompt_eval_count", "eval_count")
            if type(data.get(key)) is int and data[key] >= 0
        }
        message = data.get("message")
        if not isinstance(message, dict) or data.get("done") is not True:
            raise AnalysisError("invalid_provider_response")
        if message.get("tool_calls"):
            raise AnalysisError("provider_tool_call_rejected")
        if data.get("done_reason") in {"length", "max_tokens"}:
            raise AnalysisError("provider_output_truncated")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise AnalysisError("invalid_provider_response")
        return content


class OpenAICompatibleProvider(HTTPProvider):
    provider_id = ProviderId.OPENAI_COMPATIBLE

    def __init__(self, client: httpx.AsyncClient, settings: Settings):
        super().__init__(client, settings)
        self.model = settings.openai_model

    async def generate(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, object],
        output_tokens: int,
        deadline: float,
    ) -> str:
        self.last_usage = {}
        mode = self.settings.openai_output_mode
        body = {
            "model": self.model,
            "stream": False,
            self.settings.openai_token_limit_field: output_tokens,
        }
        if mode == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "analysis", "strict": True, "schema": schema},
            }
        else:
            system += "\nReturn JSON matching this schema: " + json.dumps(
                schema, ensure_ascii=False, separators=(",", ":")
            )
            if mode == "json_object":
                body["response_format"] = {"type": "json_object"}
        body["messages"] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        url = self.settings.openai_base_url
        if not url.endswith("/chat/completions"):
            url += "/chat/completions"
        data = await self._post(
            url,
            body,
            {
                "Authorization": "Bearer "
                + self.settings.openai_api_key.get_secret_value()
            },
            deadline,
        )
        usage = data.get("usage")
        self.last_usage = {
            key: usage[key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
            if isinstance(usage, dict)
            and type(usage.get(key)) is int
            and usage[key] >= 0
        }
        try:
            choices = data["choices"]
            if len(choices) != 1:
                raise ValueError()
            choice = choices[0]
            message = choice["message"]
            if message.get("refusal"):
                raise AnalysisError("provider_refusal")
            if message.get("tool_calls") or message.get("function_call"):
                raise AnalysisError("provider_tool_call_rejected")
            if choice.get("finish_reason") == "length":
                raise AnalysisError("provider_output_truncated")
            if choice.get("finish_reason") != "stop":
                raise AnalysisError("invalid_provider_response")
            content = message["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError()
            return content
        except (KeyError, ValueError, TypeError, IndexError, AttributeError):
            raise AnalysisError("invalid_provider_response") from None
