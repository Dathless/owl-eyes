"""Bounded ASGI guards shared by UI, static files, and future API routes."""

import base64
import binascii
import secrets

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings
from app.errors import error_response

BODY_LIMIT = 16 * 1024
HEADER_LIMIT = 16 * 1024
AUTH_LIMIT = 4096
SECURITY_HEADERS = {
    b"cache-control": b"no-store",
    b"content-security-policy": (
        b"default-src 'self'; script-src 'self'; style-src 'self'; "
        b"object-src 'none'; frame-ancestors 'none'"
    ),
    b"x-content-type-options": b"nosniff",
}
SINGLE_HEADERS = {
    b"host",
    b"authorization",
    b"origin",
    b"x-lab-request",
    b"content-type",
    b"content-length",
}


def authenticated(value: bytes, settings: Settings) -> bool:
    scheme, separator, token = value.partition(b" ")
    if not separator or scheme.lower() != b"basic":
        return False
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    username, separator, password = decoded.partition(b":")
    if not separator:
        return False
    username_ok = secrets.compare_digest(
        username, settings.app_username.encode("utf-8")
    )
    password_ok = secrets.compare_digest(
        password, settings.app_password.get_secret_value().encode("utf-8")
    )
    return username_ok & password_ok


class AccessControlMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings, testing: bool = False):
        self.app = app
        self.settings = settings
        self.hosts = {f"{settings.app_host}:{settings.app_port}".encode("ascii")}
        if testing:
            self.hosts.add(f"localhost:{settings.app_port}".encode("ascii"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        response_started = False

        async def secure_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() not in SECURITY_HEADERS
                ]
                message = {
                    **message,
                    "headers": headers + list(SECURITY_HEADERS.items()),
                }
            await send(message)

        async def reject(
            status: int, code: str | None = None, message: str | None = None
        ) -> None:
            headers = {"WWW-Authenticate": "Basic"} if status == 401 else None
            await error_response(status, code, message, headers=headers)(
                scope, receive, secure_send
            )

        raw_headers = scope.get("headers", [])
        if sum(len(key) + len(value) for key, value in raw_headers) > HEADER_LIMIT:
            await reject(431)
            return
        headers: dict[bytes, bytes] = {}
        for key, value in raw_headers:
            key = key.lower()
            if key in SINGLE_HEADERS and key in headers:
                await reject(400)
                return
            headers[key] = value
        if headers.get(b"host") not in self.hosts:
            await reject(
                400, "invalid_host", "Host and port must match the application origin."
            )
            return
        authorization = headers.get(b"authorization", b"")
        if len(authorization) > AUTH_LIMIT:
            await reject(431)
            return
        public_health = scope["path"] == "/healthz" and scope["method"] in {
            "GET",
            "HEAD",
        }
        if not public_health and not authenticated(authorization, self.settings):
            await reject(401)
            return
        if scope["method"] == "POST":
            if headers.get(b"origin") != self.settings.app_origin.encode("ascii"):
                await reject(
                    403, "invalid_origin", "Origin must match the application origin."
                )
                return
            if headers.get(b"x-lab-request") != b"1":
                await reject(403, "invalid_lab_request", "X-Lab-Request must be 1.")
                return
            media_type = (
                headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
            )
            if media_type != b"application/json":
                await reject(415)
                return
        declared_length = headers.get(b"content-length")
        if declared_length is not None:
            if not declared_length.isdigit():
                await reject(400)
                return
            # Compare decimal lengths before int(): even a huge numeral stays bounded.
            normalized_length = declared_length.lstrip(b"0") or b"0"
            if len(normalized_length) > 5 or int(normalized_length) > BODY_LIMIT:
                await reject(413)
                return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > BODY_LIMIT:
                await reject(413)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        try:
            await self.app(scope, bounded_receive, secure_send)
        except Exception:
            if response_started:
                raise
            await reject(500)
