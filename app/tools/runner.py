"""Linux subprocess collection with bounded capture and process-group cleanup."""

import asyncio
import json
import os
import re
import signal
import stat
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.schemas import Capture, ToolSpec

READ_CHUNK = 4096
ARTIFACT_INTERVAL = 0.1
TERMINATION_GRACE = 1.0
ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)
HEADER_SECRET = re.compile(
    r"(?im)^([ \t]*(?:[<>][ \t]*)?"
    r"(?:set-cookie|cookie|authorization|proxy-authorization|x-api-key|x-auth-token)"
    r"[ \t]*:[ \t]*)[^\n]*"
)
SECRET_KEYS = (
    r"(?:access[_-]?token|refresh[_-]?token|csrf[_-]?token|token|api[_-]?key|"
    r"password|secret|cookie|set-cookie|authorization|proxy-authorization|"
    r"phpsessid|session[_-]?id|security)"
)
SENSITIVE_KEYS = rf"(?:{SECRET_KEYS}|cookies|session|x-api-key|x-auth-token)"
SENSITIVE_FIELD = re.compile(rf"(?i){SENSITIVE_KEYS}")
MALFORMED_JSON_SECRET = re.compile(rf"""(?is)(["']{SENSITIVE_KEYS}["']\s*:\s*).*""")
JSON_SECRET = re.compile(
    rf"""(?i)(["']{SECRET_KEYS}["']\s*:\s*)("(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$))"""
)
ASSIGNMENT_SECRET = re.compile(
    rf"""(?i)(\b{SECRET_KEYS}\s*[=:]\s*)("(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^&;\s,}}\]]+)"""
)


def _clean_terminal(text: str) -> str:
    return "".join(
        character
        for character in ANSI.sub("", text)
        if character in "\n\t"
        or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )


def _scrub_text(text: str) -> str:
    text = _clean_terminal(text)
    text = JSON_SECRET.sub(
        lambda match: match[1] + match[2][0] + "[REDACTED]" + match[2][0], text
    )
    text = ASSIGNMENT_SECRET.sub(r"\1[REDACTED]", text)
    return HEADER_SECRET.sub(r"\1[REDACTED]", text)


def _scrub_json(value: object, depth: int = 0) -> object:
    if depth > 32:
        raise ValueError("Tool JSON is too deeply nested to sanitize")
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key = _clean_terminal(key)
            result[key] = (
                "[REDACTED]"
                if SENSITIVE_FIELD.fullmatch(key)
                else _scrub_json(item, depth + 1)
            )
        return result
    if isinstance(value, list):
        return [_scrub_json(item, depth + 1) for item in value]
    return _scrub_text(value) if isinstance(value, str) else value


def _scrub(raw: bytes) -> str:
    text = _clean_terminal(raw.decode("utf-8", errors="replace"))
    if "<niktoscans" in text:
        # Nikto XML includes its full CLI, including the transient session.
        text = re.sub(r'(\boptions=")[^"]*', r"\1[REDACTED]", text)
    if text.lstrip().startswith(("{", "[")):
        try:
            value = json.loads(text)
        except RecursionError:
            return "[REDACTED: deeply nested JSON]"
        except ValueError:
            # A malformed value has no reliable closing delimiter: discard its tail.
            return _scrub_text(MALFORMED_JSON_SECRET.sub(r'\1"[REDACTED]"', text))
        try:
            return json.dumps(
                _scrub_json(value), ensure_ascii=False, separators=(",", ":")
            )
        except (ValueError, RecursionError):
            return "[REDACTED: deeply nested JSON]"
    return _scrub_text(text)


@dataclass
class _CaptureBudget:
    limit: int
    redact_values: tuple[str, ...] = ()
    streams: dict[str, bytearray] = field(
        default_factory=lambda: {"stdout": bytearray(), "stderr": bytearray()}
    )
    artifacts: dict[str, bytearray] = field(default_factory=dict)
    used: int = 0
    exceeded: asyncio.Event = field(default_factory=asyncio.Event)
    truncated: bool = False

    def append(self, destination: bytearray, data: bytes) -> None:
        remaining = self.limit - self.used
        destination.extend(data[:remaining])
        self.used += min(len(data), remaining)
        if len(data) > remaining:
            self.mark_exceeded()

    def mark_exceeded(self) -> None:
        self.truncated = True
        self.exceeded.set()

    def sanitized(self) -> tuple[dict[str, str], dict[str, str]]:
        remaining = self.limit
        streams: dict[str, str] = {}
        artifacts: dict[str, str] = {}
        for source, destination in (
            (self.streams, streams),
            (self.artifacts, artifacts),
        ):
            for name, raw in source.items():
                data = bytes(raw)
                for value in self.redact_values:
                    if value:
                        data = data.replace(value.encode("utf-8"), b"[REDACTED]")
                cleaned = _scrub(data).encode("utf-8")
                if len(cleaned) > remaining:
                    self.mark_exceeded()
                text = cleaned[:remaining].decode("utf-8", errors="ignore")
                destination[name] = text
                remaining -= len(text.encode("utf-8"))
        return streams, artifacts


async def _drain(
    reader: asyncio.StreamReader, destination: bytearray, budget: _CaptureBudget
) -> None:
    while chunk := await reader.read(READ_CHUNK):
        budget.append(destination, chunk)


async def _monitor_artifacts(paths: tuple[Path, ...], budget: _CaptureBudget) -> None:
    while True:
        size = 0
        for path in paths:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
        if budget.used + size > budget.limit:
            budget.mark_exceeded()
            return
        await asyncio.sleep(ARTIFACT_INTERVAL)


def _read_artifacts(paths: tuple[Path, ...], budget: _CaptureBudget) -> None:
    for path in paths:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        with os.fdopen(descriptor, "rb") as artifact:
            if not stat.S_ISREG(os.fstat(artifact.fileno()).st_mode):
                raise ValueError("Tool artifact must be a regular file")
            output = budget.artifacts.setdefault(path.name, bytearray())
            budget.append(output, artifact.read(budget.limit - budget.used + 1))


def _signal_group(pid: int, sig: signal.Signals) -> bool:
    try:
        os.killpg(pid, sig)
        return True
    except ProcessLookupError:
        return False


async def _stop_group(process: asyncio.subprocess.Process) -> None:
    # The parent may have exited while a descendant still owns a pipe.
    if _signal_group(process.pid, signal.SIGTERM):
        deadline = asyncio.get_running_loop().time() + TERMINATION_GRACE
        while _signal_group(process.pid, 0):
            if asyncio.get_running_loop().time() >= deadline:
                _signal_group(process.pid, signal.SIGKILL)
                break
            await asyncio.sleep(0.01)
    await process.wait()


async def _leader_exit(process: asyncio.subprocess.Process) -> None:
    # Process.wait() can wait for descendant-held pipes, not just leader exit.
    while process.returncode is None:
        await asyncio.sleep(0.01)


async def run_tool(
    spec: ToolSpec,
    semaphore: asyncio.Semaphore,
    cancel_event: asyncio.Event,
    capture_limit_bytes: int,
    *,
    on_started: Callable[[datetime], None] | None = None,
    redact_values: tuple[str, ...] = (),
) -> Capture:
    """Collect and unlink disposable artifacts; caller owns their TemporaryDirectory.

    The semaphore is global to the manager (configured to 1–3). Cancellation of
    this coroutine is propagated only after process, reader, file and slot cleanup.
    Preset tools must not escape the process group through setsid/daemonization.
    """
    if capture_limit_bytes < 1:
        raise ValueError("Capture limit must be positive")
    if not os.path.isabs(spec.argv[0]):
        raise ValueError("Tool executable must be resolved to an absolute path")
    if any(not path.is_absolute() for path in spec.artifact_paths):
        raise ValueError("Artifact paths must be absolute disposable paths")
    if len({path.name for path in spec.artifact_paths}) != len(spec.artifact_paths):
        raise ValueError("Artifact names must be unique")
    budget = _CaptureBudget(capture_limit_bytes, redact_values)
    loop = asyncio.get_running_loop()
    started_at = started = None
    process = None
    admission = spawn = None
    readers: list[asyncio.Task] = []
    watchers: list[asyncio.Task] = []
    reason = "normal"
    task_cancelled = False

    def start_readers() -> None:
        if not readers and process is not None:
            readers.extend(
                [
                    asyncio.create_task(
                        _drain(process.stdout, budget.streams["stdout"], budget)
                    ),
                    asyncio.create_task(
                        _drain(process.stderr, budget.streams["stderr"], budget)
                    ),
                ]
            )

    async def cleanup() -> None:
        nonlocal process
        try:
            if process is None and spawn is not None:
                try:
                    process = await spawn
                except (OSError, ValueError):
                    pass
            start_readers()
            for watcher in watchers:
                watcher.cancel()
            await asyncio.gather(*watchers, return_exceptions=True)
            if process is not None:
                await _stop_group(process)
            await asyncio.gather(*readers)
            _read_artifacts(spec.artifact_paths, budget)
        finally:
            for reader in readers:
                if not reader.done():
                    reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            try:
                for path in spec.artifact_paths:
                    path.unlink(missing_ok=True)
            finally:
                if admission is not None:
                    if not admission.done():
                        admission.cancel()
                    await asyncio.gather(admission, return_exceptions=True)
                    if (
                        not admission.cancelled()
                        and admission.exception() is None
                        and admission.result()
                    ):
                        semaphore.release()

    try:
        if cancel_event.is_set():
            reason = "cancelled"
        else:
            admission = asyncio.create_task(semaphore.acquire())
            cancellation = asyncio.create_task(cancel_event.wait())
            watchers.append(cancellation)
            await asyncio.wait(
                {admission, cancellation}, return_when=asyncio.FIRST_COMPLETED
            )
            if cancel_event.is_set():
                reason = "cancelled"
            else:
                await admission
                started_at, started = datetime.now(UTC), loop.time()
                spawn = asyncio.create_task(
                    asyncio.create_subprocess_exec(
                        *spec.argv,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=True,
                        cwd=spec.config_directory,
                        limit=min(8192, capture_limit_bytes),
                        env={
                            "PATH": os.defpath,
                            "LANG": "C.UTF-8",
                            "LC_ALL": "C.UTF-8",
                            **(
                                {
                                    "XDG_CONFIG_HOME": str(spec.config_directory),
                                    "HOME": str(spec.config_directory),
                                }
                                if spec.config_directory is not None
                                else {}
                            ),
                            **(
                                {
                                    "DISABLE_NUCLEI_TEMPLATES_"
                                    + source
                                    + "_DOWNLOAD": "true"
                                    for source in (
                                        "PUBLIC",
                                        "GITHUB",
                                        "GITLAB",
                                        "AWS",
                                        "AZURE",
                                    )
                                }
                                if spec.tool_id == "nuclei"
                                else {}
                            ),
                        },
                    )
                )
                try:
                    process = await asyncio.shield(spawn)
                except (OSError, ValueError):
                    reason = "spawn_error"
                    budget.append(
                        budget.streams["stderr"], b"Tool could not be started."
                    )
                if process is not None:
                    if on_started:
                        on_started(started_at)
                    start_readers()
                    leader = asyncio.create_task(_leader_exit(process))
                    exceeded = asyncio.create_task(budget.exceeded.wait())
                    monitor = asyncio.create_task(
                        _monitor_artifacts(spec.artifact_paths, budget)
                    )
                    watchers.extend([leader, exceeded, monitor])
                    await asyncio.wait(
                        {leader, exceeded, cancellation},
                        timeout=max(0, started + spec.timeout_seconds - loop.time()),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if cancel_event.is_set():
                        reason = "cancelled"
                    elif budget.exceeded.is_set():
                        reason = "output_limit"
                    elif process.returncode is None:
                        reason = "timeout"
    except asyncio.CancelledError:
        task_cancelled = True
        reason = "cancelled"
    finally:
        finalizer = asyncio.create_task(cleanup())
        while not finalizer.done():
            try:
                await asyncio.shield(finalizer)
            except asyncio.CancelledError:
                task_cancelled = True
        finalizer.result()
    if task_cancelled:
        raise asyncio.CancelledError
    streams, artifacts = budget.sanitized()
    if reason == "normal":
        if cancel_event.is_set():
            reason = "cancelled"
        elif budget.truncated:
            reason = "output_limit"
    return Capture(
        stdout=streams["stdout"],
        stderr=streams["stderr"],
        artifacts=artifacts,
        return_code=process.returncode if process is not None else None,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        duration_ms=max(0, (loop.time() - started) * 1000)
        if started is not None
        else 0,
        termination_reason=reason,
        output_truncated=budget.truncated,
    )
