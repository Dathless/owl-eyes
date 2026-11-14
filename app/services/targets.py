"""Saved target snapshots and bounded public-address admission."""

import asyncio
import socket
from ipaddress import ip_address
from urllib.parse import urlsplit

from app.config import Settings, public_address
from app.errors import OperationError
from app.schemas import TargetSpec


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


async def resolve_public_target(target: TargetSpec) -> TargetSpec:
    """Reject every unsafe answer, then pin one address for all connection tools."""
    try:
        answers = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                urlsplit(target.url).hostname, target.port, type=socket.SOCK_STREAM
            ),
            5,
        )
        addresses = {public_address(ip_address(item[4][0])) for item in answers}
        if not addresses:
            raise ValueError("No public address")
    except (OSError, ValueError, TimeoutError):
        raise OperationError(
            422,
            "public_target_unavailable",
            "Domain must resolve only to public Internet addresses.",
        ) from None
    chosen = min(addresses, key=lambda address: (address.version, int(address)))
    return target.model_copy(update={"ip": chosen}, deep=True)
