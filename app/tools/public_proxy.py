"""Per-run HTTP/CONNECT transport to one admitted address, without TLS interception."""

import asyncio
from contextlib import suppress
from urllib.parse import urlsplit

import h11

HEADER_BYTES = 16384
BUFFER_BYTES = 65536
IDLE_SECONDS = 10
MAX_CONNECTIONS = 4096
MAX_ACTIVE = 8
MAX_TRANSFER_BYTES = 64 * 1024 * 1024
# Public origins occasionally drop a SYN. Fresh short attempts to the same pin
# recover within typical 5s CLI client deadlines; no request byte precedes them.
CONNECT_ATTEMPTS = 3
CONNECT_ATTEMPT_SECONDS = 1.5


class PinnedOriginProxy:
    """The caller supplies a validated immutable public target snapshot."""

    def __init__(self, target):
        if target.kind != "public_domain" or target.ip is None:
            raise ValueError("An admitted public connection target is required")
        self.target = target
        self.hostname = urlsplit(target.url).hostname
        self.url = ""
        self.warnings = []
        self._server = None
        self._tasks = set()
        self._writers = set()
        self._closing = False
        self._connections = 0
        self._transferred = 0

    async def __aenter__(self):
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, limit=HEADER_BYTES
        )
        port = self._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *_):
        self._closing = True
        self._server.close()
        for writer in tuple(self._writers):
            writer.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._server.wait_closed()

    async def _connect(self):
        for attempt in range(1, CONNECT_ATTEMPTS + 1):
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(str(self.target.ip), self.target.port),
                    CONNECT_ATTEMPT_SECONDS,
                )
            except (OSError, TimeoutError):
                if attempt == CONNECT_ATTEMPTS or self._closing:
                    raise

    def _warn(self, name):
        if name not in self.warnings and len(self.warnings) < 20:
            self.warnings.append(name)

    def _authority(self, value, default_port):
        if any(char in value for char in "/\\?#"):
            raise ValueError("Invalid authority")
        parts = urlsplit("//" + value)
        if (
            parts.hostname != self.hostname
            or (parts.port if parts.port is not None else default_port)
            != self.target.port
            or parts.username is not None
            or parts.password is not None
            or parts.path
            or parts.query
            or parts.fragment
        ):
            raise ValueError("Outside selected authority")

    def _validate(self, request):
        method = request.method.decode("ascii")
        raw = request.target.decode("ascii")
        if any(ord(char) <= 32 or ord(char) == 127 for char in raw) or "\\" in raw:
            raise ValueError("Invalid request target")
        headers = {key.lower(): value for key, value in request.headers}
        if (
            b"transfer-encoding" in headers
            or headers.get(b"content-length", b"0") != b"0"
            or b"upgrade" in headers
            or b"expect" in headers
        ):
            raise ValueError("Unsupported request framing")
        connection = headers.get(b"connection", b"").lower().split(b",")
        if any(
            value.strip() not in {b"", b"close", b"keep-alive"} for value in connection
        ):
            raise ValueError("Unsupported connection upgrade")
        if method == "CONNECT":
            if self.target.scheme != "https":
                raise ValueError("HTTPS target required")
            self._authority(raw, 443)
            if b"host" in headers:
                self._authority(headers[b"host"].decode("ascii"), 443)
            return None
        if method not in {"GET", "HEAD", "OPTIONS"} or self.target.scheme != "http":
            raise ValueError("Unsupported public HTTP method")
        parts = urlsplit(raw)
        # Origin-form paths need no authority check: h11 enforces Host for
        # HTTP/1.1, and a hostless HTTP/1.0 probe (Nikto) is sent upstream with
        # the saved Host like every other request.
        if not raw.startswith("/") or raw.startswith("//"):
            if parts.scheme != "http" or not parts.netloc or parts.fragment:
                raise ValueError("Absolute public HTTP URL required")
            self._authority(parts.netloc, 80)
        if b"host" in headers:
            self._authority(headers[b"host"].decode("ascii"), 80)
        path = parts.path or "/"
        return (path + ("?" + parts.query if parts.query else "")).encode("ascii")

    async def _copy(self, reader, writer):
        while chunk := await asyncio.wait_for(reader.read(BUFFER_BYTES), IDLE_SECONDS):
            self._transferred += len(chunk)
            if self._transferred > MAX_TRANSFER_BYTES:
                self._warn("public_proxy_transfer_limit")
                raise ValueError("Transfer budget reached")
            writer.write(chunk)
            await asyncio.wait_for(writer.drain(), IDLE_SECONDS)

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        self._writers.add(writer)
        upstream = None
        established = False
        self._connections += 1
        try:
            if self._closing:
                return
            if self._connections > MAX_CONNECTIONS or len(self._tasks) > MAX_ACTIVE:
                self._warn("public_proxy_connection_limit")
                raise ValueError("Connection limit reached")
            connection = h11.Connection(
                h11.SERVER, max_incomplete_event_size=HEADER_BYTES
            )
            received = 0
            async with asyncio.timeout(IDLE_SECONDS):
                while (request := connection.next_event()) is h11.NEED_DATA:
                    chunk = await reader.read(4096)
                    if not chunk:
                        return
                    received += len(chunk)
                    if received > HEADER_BYTES:
                        raise ValueError("Request header limit exceeded")
                    connection.receive_data(chunk)
            if not isinstance(request, h11.Request):
                raise ValueError("Expected request")
            path = self._validate(request)
            upstream_reader, upstream = await self._connect()
            self._writers.add(upstream)
            if path is None:
                writer.write(connection.send(h11.Response(status_code=200, headers=[])))
                await writer.drain()
                established = True
                trailing, _ = connection.trailing_data
                if trailing:
                    upstream.write(trailing)
                    await upstream.drain()
                pumps = [
                    asyncio.create_task(self._copy(reader, upstream)),
                    asyncio.create_task(self._copy(upstream_reader, writer)),
                ]
                try:
                    done, _ = await asyncio.wait(
                        pumps, return_when=asyncio.FIRST_COMPLETED
                    )
                    for pump in done:
                        pump.result()
                finally:
                    for pump in pumps:
                        pump.cancel()
                    await asyncio.gather(*pumps, return_exceptions=True)
            else:
                headers = [
                    (key, value)
                    for key, value in request.headers
                    if key.lower()
                    not in {
                        b"host",
                        b"connection",
                        b"proxy-connection",
                        b"proxy-authorization",
                        b"keep-alive",
                        b"content-length",
                        b"te",
                        b"trailer",
                    }
                ]
                authority = self.hostname
                if self.target.port != 80:
                    authority += f":{self.target.port}"
                headers.extend(
                    [(b"Host", authority.encode()), (b"Connection", b"close")]
                )
                outgoing = h11.Connection(h11.CLIENT)
                upstream.write(
                    outgoing.send(
                        h11.Request(method=request.method, target=path, headers=headers)
                    )
                )
                upstream.write(outgoing.send(h11.EndOfMessage()))
                await upstream.drain()
                established = True
                await self._copy(upstream_reader, writer)
        except (ValueError, UnicodeError, h11.ProtocolError):
            self._warn("public_proxy_request_rejected")
            if not established:
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                with suppress(OSError):
                    await writer.drain()
        except (OSError, TimeoutError):
            self._warn("public_proxy_connection_incomplete")
            if not established:
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                with suppress(OSError):
                    await writer.drain()
        finally:
            for stream in (upstream, writer):
                if stream is not None:
                    stream.close()
                    with suppress(OSError, TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 1)
                    self._writers.discard(stream)
            self._tasks.discard(task)
