"""Fresh, bounded DVWA session acquisition; no login data enters public capture."""

import asyncio
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin

import anyio
import httpx
from pydantic import SecretStr

from app.tools.adapters.common import uri_scope


class DvwaAuthError(ValueError):
    def __init__(self):
        super().__init__("DVWA login could not be verified.")


@dataclass
class DvwaSession:
    cookie_header: SecretStr
    security_level: str


class _LoginForm(HTMLParser):
    token: str | None = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "user_token":
            self.token = fields.get("value")


async def authenticate_dvwa(target, settings, cancel, *, transport=None):
    """Only request fixed lab paths; cancellation owns the HTTP cancel scope."""
    scope = anyio.CancelScope()

    async def login():
        with scope:
            async with httpx.AsyncClient(
                trust_env=False, follow_redirects=False, timeout=5, transport=transport
            ) as client:

                async def request(method, path, **kwargs):
                    async with client.stream(
                        method, target.url.rstrip("/") + "/" + path, **kwargs
                    ) as response:
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=4096):
                            if len(body) + len(chunk) > 65536:
                                raise DvwaAuthError()
                            body.extend(chunk)
                        return response, body.decode("utf-8", errors="replace")

                response, body = await request("GET", "login.php")
                if response.status_code != 200:
                    raise DvwaAuthError()
                form = _LoginForm()
                form.feed(body)
                data = {
                    "username": settings.dvwa_username,
                    "password": settings.dvwa_password.get_secret_value(),
                    "Login": "Login",
                }
                if form.token is not None:
                    data["user_token"] = form.token
                response, _ = await request("POST", "login.php", data=data)
                if response.status_code not in {200, 302, 303}:
                    raise DvwaAuthError()
                if location := response.headers.get("location"):
                    if (
                        uri_scope(target, urljoin(str(response.url), location))
                        != "dvwa_path"
                    ):
                        raise DvwaAuthError()
                response, body = await request("GET", "index.php")
                if response.status_code != 200 or not re.search(
                    r"""href\s*=\s*["'](?:\./)?logout\.php["']""", body, re.I
                ):
                    raise DvwaAuthError()
                # Use only cookies applicable to this protected URL.
                cookie_request = client.build_request("GET", str(response.url))
                cookies = dict(
                    part.strip().split("=", 1)
                    for part in cookie_request.headers.get("cookie", "").split(";")
                    if "=" in part
                )
                session = cookies.get("PHPSESSID", "")
                security = cookies.get("security", "")
                if not re.fullmatch(
                    r"[A-Za-z0-9,-]{1,256}", session
                ) or security not in {"low", "medium", "high", "impossible"}:
                    raise DvwaAuthError()
                return DvwaSession(
                    SecretStr(f"PHPSESSID={session};security={security}"), security
                )

    if cancel.is_set():
        raise asyncio.CancelledError()
    task = asyncio.create_task(login())
    waiter = asyncio.create_task(cancel.wait())
    try:
        async with asyncio.timeout(20):
            done, _ = await asyncio.wait(
                {task, waiter}, return_when=asyncio.FIRST_COMPLETED
            )
            if waiter in done:
                raise asyncio.CancelledError()
            result = task.result()
            if result is None:
                raise DvwaAuthError()
            return result
    except (httpx.HTTPError, TimeoutError, ValueError):
        raise DvwaAuthError() from None
    finally:
        scope.cancel()
        waiter.cancel()
        await asyncio.shield(asyncio.gather(task, waiter, return_exceptions=True))
