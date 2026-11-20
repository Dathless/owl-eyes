"""Two explicit HTTP profiles with capped decoded bodies and absolute deadlines."""

import asyncio
import json
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import anyio
import httpx

from app.ai.base import AnalysisError
from app.ai.budget import request_tokens, require_fit
from app.ai.research import DEFAULT_QUERY, ResearchTools
from app.config import Settings
from app.schemas import ProviderId
from app.services.cve_lookup import CVELookupService


def native_messages(messages: list[dict], *, external: bool) -> list[dict]:
    """Translate canonical call/result pairs without changing their data."""
    result = []
    for message in messages:
        value = dict(message)
        if value.get("tool_calls"):
            calls = []
            for call in value["tool_calls"]:
                function = dict(call["function"])
                if external:
                    function["arguments"] = json.dumps(
                        function["arguments"], ensure_ascii=False
                    )
                    calls.append(
                        {"id": call["id"], "type": "function", "function": function}
                    )
                else:
                    calls.append({"function": function})
            value["tool_calls"] = calls
        if value["role"] == "tool":
            value.pop("tool_name" if external else "tool_call_id", None)
        result.append(value)
    return result


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
    def __init__(
        self,
        client: httpx.AsyncClient,
        settings: Settings,
        *,
        research: ResearchTools | None = None,
    ):
        self.client, self.settings = client, settings
        self.last_usage: dict[str, int] = {}
        self.research = research or ResearchTools(
            client, CVELookupService(client), [DEFAULT_QUERY]
        )

    @property
    def external(self) -> bool:
        return not isinstance(self, OllamaProvider)

    @property
    def context_tokens(self) -> int:
        return (
            self.settings.openai_context_tokens
            if self.external
            else self.settings.ollama_context_tokens
        )

    def generation_input(
        self, *, system: str, user: str, schema: dict, context: list[dict] | None = None
    ) -> dict:
        body = {}
        if not self.external:
            # Native structured output already supplies the schema once.
            body["format"] = schema
        elif self.settings.openai_output_mode == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "analysis", "strict": True, "schema": schema},
            }
        else:
            system += "\nReturn JSON matching this schema: " + json.dumps(
                schema, ensure_ascii=False, separators=(",", ":")
            )
            if self.settings.openai_output_mode == "json_object":
                body["response_format"] = {"type": "json_object"}
        body["messages"] = native_messages(
            [{"role": "system", "content": system}, {"role": "user", "content": user}]
            + (context or []),
            external=self.external,
        )
        return body

    def input_budget(self, *, system: str, schema: dict, output_tokens: int) -> int:
        return (
            self.context_tokens
            - output_tokens
            - request_tokens(
                self.generation_input(system=system, user="", schema=schema)
            )
        )

    def validate_context(
        self,
        *,
        system: str,
        user: str,
        schema: dict,
        output_tokens: int,
        context: list[dict] | None = None,
    ) -> None:
        require_fit(
            self.generation_input(
                system=system, user=user, schema=schema, context=context
            ),
            self.context_tokens,
            output_tokens,
        )

    def planning_tokens(self, messages: list[dict], tools: list[dict]) -> int:
        return request_tokens(
            {
                "messages": native_messages(messages, external=self.external),
                "tools": tools,
            }
        )

    async def _post(self, url: str, body: dict, headers: dict, deadline: float) -> dict:
        output = body.get("options", {}).get(
            "num_predict", body.get(self.settings.openai_token_limit_field, 256)
        )
        require_fit(body, self.context_tokens, output)
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
                        if (
                            "does not support tools" in error
                            or "doesn't support tools" in error
                        ):
                            raise AnalysisError("provider_tools_unsupported")
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

    def __init__(
        self,
        client: httpx.AsyncClient,
        settings: Settings,
        *,
        research: ResearchTools | None = None,
    ):
        super().__init__(client, settings, research=research)
        self.model = settings.ollama_model

    def _message(self, data: dict) -> dict:
        for key in ("prompt_eval_count", "eval_count"):
            if type(data.get(key)) is int and data[key] >= 0:
                self.last_usage[key] = self.last_usage.get(key, 0) + data[key]
        message = data.get("message")
        if not isinstance(message, dict) or data.get("done") is not True:
            raise AnalysisError("invalid_provider_response")
        if data.get("done_reason") in {"length", "max_tokens"}:
            raise AnalysisError("provider_output_truncated")
        return message

    async def plan(
        self, *, messages: list[dict], tools: list[dict], deadline: float
    ) -> dict:
        self.last_usage = {}
        body = {
            "model": self.model,
            "messages": native_messages(messages, external=False),
            "tools": tools,
            "stream": False,
            "options": {
                "num_predict": 256,
                "num_thread": self.settings.ollama_num_threads,
                "temperature": 0,
                "num_ctx": self.settings.ollama_context_tokens,
            },
        }
        data = await self._post(
            self.settings.ollama_base_url + "/api/chat", body, {}, deadline
        )
        return self._message(data)

    async def generate(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, object],
        output_tokens: int,
        deadline: float,
        context: list[dict] | None = None,
    ) -> str:
        self.validate_context(
            system=system, user=user, schema=schema, output_tokens=output_tokens
        )
        self.last_usage = {}
        options = {
            "num_predict": output_tokens,
            "num_thread": self.settings.ollama_num_threads,
            "temperature": 0,
            "num_ctx": self.settings.ollama_context_tokens,
        }
        body = self.generation_input(
            system=system, user=user, schema=schema, context=context
        )
        body.update(model=self.model, stream=False, options=options)
        data = await self._post(
            self.settings.ollama_base_url + "/api/chat", body, {}, deadline
        )
        message = self._message(data)
        if message.get("tool_calls"):
            raise AnalysisError("provider_tool_call_rejected")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise AnalysisError("invalid_provider_response")
        return content


class OpenAICompatibleProvider(HTTPProvider):
    provider_id = ProviderId.OPENAI_COMPATIBLE

    def __init__(
        self,
        client: httpx.AsyncClient,
        settings: Settings,
        *,
        research: ResearchTools | None = None,
    ):
        super().__init__(client, settings, research=research)
        self.model = settings.openai_model

    def _endpoint(self) -> str:
        url = self.settings.openai_base_url
        return url if url.endswith("/chat/completions") else url + "/chat/completions"

    def _headers(self) -> dict:
        return {
            "Authorization": "Bearer " + self.settings.openai_api_key.get_secret_value()
        }

    async def plan(
        self, *, messages: list[dict], tools: list[dict], deadline: float
    ) -> dict:
        self.last_usage = {}
        data = await self._post(
            self._endpoint(),
            {
                "model": self.model,
                "messages": native_messages(messages, external=True),
                "tools": tools,
                "stream": False,
                self.settings.openai_token_limit_field: 256,
            },
            self._headers(),
            deadline,
        )
        self._usage(data)
        try:
            choices = data["choices"]
            if len(choices) != 1:
                raise ValueError()
            choice = choices[0]
            message = choice["message"]
            if message.get("refusal"):
                raise AnalysisError("provider_refusal")
            if choice.get("finish_reason") == "length":
                raise AnalysisError("provider_output_truncated")
            if choice.get("finish_reason") not in {"stop", "tool_calls"}:
                raise ValueError()
            return message
        except (KeyError, ValueError, TypeError, IndexError, AttributeError):
            raise AnalysisError("invalid_provider_response") from None

    def _usage(self, data: dict) -> None:
        usage = data.get("usage")
        self.last_usage = {
            key: usage[key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
            if isinstance(usage, dict)
            and type(usage.get(key)) is int
            and usage[key] >= 0
        }

    async def generate(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, object],
        output_tokens: int,
        deadline: float,
        context: list[dict] | None = None,
    ) -> str:
        self.last_usage = {}
        body = self.generation_input(
            system=system, user=user, schema=schema, context=context
        )
        body.update(model=self.model, stream=False)
        body[self.settings.openai_token_limit_field] = output_tokens
        data = await self._post(self._endpoint(), body, self._headers(), deadline)
        self._usage(data)
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
