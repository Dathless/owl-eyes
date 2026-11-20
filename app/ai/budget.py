"""Conservative whole-request accounting without a model-specific tokenizer."""

import json

from app.ai.base import AnalysisError

FRAMING_TOKENS = 256


def json_bytes(value) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())


def request_tokens(body: dict) -> int:
    """One UTF-8 byte per token, plus framing; count only model-facing fields.

    Byte-fallback BPE uses at most one token per UTF-8 byte. Native arguments
    are counted after protocol conversion, including external JSON strings.
    Transport escaping of message content is not part of the model's text.
    """
    count = FRAMING_TOKENS
    for message in body.get("messages", []):
        count += len((message.get("content") or "").encode())
        count += json_bytes({k: v for k, v in message.items() if k != "content"}) + 16
    for key in ("tools", "format", "response_format"):
        if key in body:
            count += json_bytes(body[key])
    return count


def require_fit(body: dict, context_tokens: int, output_tokens: int) -> None:
    if request_tokens(body) + output_tokens > context_tokens:
        raise AnalysisError("context_length_exceeded")
