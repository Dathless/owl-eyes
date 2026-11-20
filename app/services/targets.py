"""Saved target snapshots and bounded public-address admission."""

import asyncio
import re
import shutil
import socket
from contextlib import suppress
from ipaddress import ip_address
from urllib.parse import urlsplit

from app.config import Settings, public_address
from app.errors import OperationError
from app.schemas import TargetResolution, TargetSpec

HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")


def configured_targets(settings: Settings) -> list[TargetSpec]:
    targets = [
        TargetSpec(
            url=settings.lab_target_url,
            ip=settings.lab_target_ip,
            auth_mode=settings.dvwa_auth_mode,
            security_level=settings.dvwa_security_level,
        )
    ]
    for profile in settings.target_profiles:
        parts = urlsplit(profile.url)
        targets.append(
            TargetSpec(
                target_id=profile.target_id,
                name=profile.name,
                kind=profile.kind,
                url=profile.url,
                ip=profile.ip,
                scheme=parts.scheme,
                port=443 if parts.scheme == "https" else 80,
                base_path="/" if profile.kind == "public_domain" else "/dvwa",
                auth_mode=settings.dvwa_auth_mode
                if profile.kind == "dvwa"
                else "public_only_unknown",
                security_level=settings.dvwa_security_level
                if profile.kind == "dvwa"
                else "unknown",
            )
        )
    return targets


NSLOOKUP_SECONDS = 8
NSLOOKUP_OUTPUT_BYTES = 65536
ORIGIN_PROBE_ATTEMPTS = 2
ORIGIN_PROBE_SECONDS = 2
ANSWER = re.compile(r"Address:\s+([0-9A-Fa-f:.]+)")


def parse_nslookup(output: str) -> list[str] | None:
    """Answer addresses, [] for a definitive NXDOMAIN, None when inconclusive.

    The resolver's own "Server/Address: x#53" block precedes the first Name: line.
    """
    addresses, answering = [], False
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            answering = True
        elif answering and (match := ANSWER.fullmatch(line)):
            addresses.append(match[1])
    if addresses:
        return list(dict.fromkeys(addresses))
    return [] if "NXDOMAIN" in output else None


async def nslookup_addresses(hostname: str) -> list[str] | None:
    """Run nslookup with server-owned argv; the hostname is already normalized."""
    executable = shutil.which("nslookup")
    if not executable or not HOSTNAME.fullmatch(hostname):
        return None
    process = await asyncio.create_subprocess_exec(
        executable,
        "-timeout=3",
        "-retry=1",
        hostname,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    try:
        output = await asyncio.wait_for(
            process.stdout.read(NSLOOKUP_OUTPUT_BYTES), NSLOOKUP_SECONDS
        )
    except TimeoutError:
        return None
    finally:
        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.kill()
        await process.wait()
    return parse_nslookup(output.decode("ascii", "replace"))


async def system_addresses(hostname: str, port: int) -> list[str]:
    answers = await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
        5,
    )
    return [item[4][0] for item in answers]


async def origin_reachable(ip, port: int) -> bool:
    """One TCP handshake to the pin; no request byte is written."""
    for _ in range(ORIGIN_PROBE_ATTEMPTS):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), ORIGIN_PROBE_SECONDS
            )
        except (OSError, TimeoutError):
            continue
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
        return True
    return False


def alternate_target(target: TargetSpec, resolution) -> TargetSpec | None:
    """The other standard scheme on the same admitted pin, if it was reachable."""
    if resolution is None or resolution.alternate_url is None:
        return None
    scheme = urlsplit(resolution.alternate_url).scheme
    return TargetSpec.model_validate(
        {
            **target.model_dump(),
            "url": resolution.alternate_url,
            "scheme": scheme,
            "port": 443 if scheme == "https" else 80,
        }
    )


async def resolve_public_target(
    target: TargetSpec, *, probe_alternate: bool = False
) -> tuple[TargetSpec, TargetResolution]:
    """nslookup first, reject every unsafe answer, then pin one address."""
    hostname = urlsplit(target.url).hostname
    try:
        resolver, raw = "nslookup", await nslookup_addresses(hostname)
        if raw is None:
            resolver, raw = "getaddrinfo", await system_addresses(hostname, target.port)
        addresses = {public_address(ip_address(item)) for item in raw}
        if not addresses:
            raise ValueError("No public address")
    except (OSError, ValueError, TimeoutError):
        raise OperationError(
            422,
            "public_target_unavailable",
            "Domain must resolve only to public Internet addresses.",
        ) from None
    ordered = sorted(addresses, key=lambda address: (address.version, int(address)))
    chosen = ordered[0]
    alternate = None
    if probe_alternate:
        scheme, port = ("http", 80) if target.scheme == "https" else ("https", 443)
        if await origin_reachable(chosen, port):
            alternate = f"{scheme}://{hostname}/"
    resolution = TargetResolution(
        resolver=resolver,
        addresses=ordered[:16],
        selected_ip=chosen,
        alternate_url=alternate,
    )
    return target.model_copy(update={"ip": chosen}, deep=True), resolution
