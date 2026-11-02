"""Fixed server-owned adapter registry and bounded offline binary probes."""

from app.schemas import ToolCapability, ToolId
from app.tools.adapters.curl import CurlAdapter
from app.tools.adapters.ffuf import FfufAdapter
from app.tools.adapters.nikto import NiktoAdapter
from app.tools.adapters.nmap import NmapAdapter
from app.tools.adapters.optional import (
    GobusterAdapter,
    HttpxAdapter,
    NucleiAdapter,
    Wafw00fAdapter,
    WapitiAdapter,
)
from app.tools.adapters.whatweb import WhatwebAdapter
from app.tools.base import ToolAdapter

ADAPTERS = {
    ToolId.NMAP: NmapAdapter,
    ToolId.CURL: CurlAdapter,
    ToolId.WHATWEB: WhatwebAdapter,
    ToolId.FFUF: FfufAdapter,
    ToolId.NIKTO: NiktoAdapter,
    ToolId.NUCLEI: NucleiAdapter,
    ToolId.HTTPX: HttpxAdapter,
    ToolId.WAFW00F: Wafw00fAdapter,
    ToolId.GOBUSTER: GobusterAdapter,
    ToolId.WAPITI: WapitiAdapter,
}


def build_registry(
    capabilities: dict[ToolId, ToolCapability],
) -> dict[ToolId, ToolAdapter]:
    return {tool: adapter(capabilities[tool]) for tool, adapter in ADAPTERS.items()}


# Help text is checked locally, never by issuing a scan or contacting a provider.
PROBES = {
    ToolId.NUCLEI: (
        ("-version",),
        ("-h",),
        (
            "-H",
            "-s,",
            "-pt",
            "-ni",
            "-duc",
            "-dr",
            "-or",
            "-ot",
            "-no-stdin",
            "-nh",
            "-rl",
            "-c,",
            "-bs",
            "-timeout",
            "-retries",
            "-silent",
            "-nc",
            "-jle",
            "-config",
            "-t,",
        ),
    ),
    ToolId.HTTPX: (
        ("-version",),
        ("-h",),
        (
            "-H,",
            "-u,",
            "-config",
            "-j,",
            "-o,",
            "-sc",
            "-cl",
            "-ct",
            "-title",
            "-server",
            "-td",
            "-location",
            "-ob",
            "-nfs",
            "-rl",
            "-timeout",
            "-retries",
            "-duc",
            "-silent",
            "-nc",
            "-no-stdin",
            "-allow",
        ),
    ),
    ToolId.WAFW00F: (
        ("-V",),
        ("-h",),
        ("-H", "-r", "-T", "--no-colors", "-f", "json", "-o"),
    ),
    ToolId.GOBUSTER: (
        ("--version",),
        ("dir", "--help"),
        (
            "--cookies",
            "--url",
            "--wordlist",
            "--threads",
            "--delay",
            "--timeout",
            "--no-progress",
            "--no-color",
            "--quiet",
            "--output",
        ),
    ),
    ToolId.WAPITI: (
        ("--version",),
        ("--help",),
        (
            "--cookie-value",
            "--scope",
            "--module",
            "--depth",
            "--max-links-per-page",
            "--max-files-per-dir",
            "--max-scan-time",
            "--max-attack-time",
            "--tasks",
            "--timeout",
            "--no-bugreport",
            "--flush-session",
            "--store-session",
            "--store-config",
            "--format",
            "json",
            "--output",
        ),
    ),
    ToolId.NMAP: (
        ("--version",),
        ("--help",),
        (
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "--max-retries",
            "--host-timeout",
            "-p",
            "-oX",
        ),
    ),
    ToolId.CURL: (
        ("--version",),
        ("--help", "all"),
        (
            "--cookie",
            "--disable",
            "--noproxy",
            "--globoff",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "--max-time",
            "--proto",
            "--dump-header",
            "--output",
            "--write-out",
        ),
    ),
    ToolId.WHATWEB: (
        ("--version",),
        ("--help",),
        (
            "--cookie",
            "--aggression",
            "--max-threads",
            "--follow-redirect",
            "never",
            "--open-timeout",
            "--read-timeout",
            "--color",
            "--log-json",
        ),
    ),
    ToolId.NIKTO: (
        ("-Version",),
        ("-Help",),
        (
            "-config",
            "-Plugins",
            "-host",
            "-root",
            "-Tuning",
            "-maxtime",
            "-timeout",
            "-nointeractive",
            "-nolookup",
            "-nocheck",
            "-ask",
            "-nocookies",
            "-Option",
            "-Format",
            "xml",
            "-output",
        ),
    ),
    ToolId.FFUF: (
        ("-V",),
        ("-h",),
        (
            "-b ",
            "-config",
            "-u",
            "-w",
            "-t",
            "-rate",
            "-timeout",
            "-maxtime",
            "-noninteractive",
            "-mc",
            "-ignore-body",
            "-scrapers",
            "-of",
            "json",
            "-o",
        ),
    ),
}


# Preserve the public catalog order independently of help-probe declarations.
PROBES = {tool: PROBES[tool] for tool in ToolId}


def local_probe(argv: tuple[str, ...], timeout: float = 10) -> str | None:
    """Use the existing bounded runner for diagnostics too; no inherited secrets."""
    import asyncio
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from app.schemas import ToolSpec
    from app.tools.runner import run_tool

    async def probe():
        with TemporaryDirectory(prefix="penchecker-probe-") as directory:
            spec = ToolSpec(
                tool_id="nuclei" if Path(argv[0]).name == "nuclei" else "ffuf",
                argv=argv,
                timeout_seconds=timeout,
                config_directory=Path(directory),
            )
            capture = await run_tool(
                spec,
                asyncio.Semaphore(1),
                asyncio.Event(),
                65536,
            )
        if (
            capture.termination_reason != "normal"
            or capture.return_code != 0
            or capture.output_truncated
        ):
            return None
        return capture.stdout + capture.stderr

    return asyncio.run(probe())


def probe_capabilities() -> dict[ToolId, ToolCapability]:
    import re
    import shutil
    from pathlib import Path

    from app.tools.adapters.nikto import NIKTO_CONFIG

    capabilities = {}
    for tool, (version_args, help_args, flags) in PROBES.items():
        executable = shutil.which(
            "httpx-toolkit" if tool == ToolId.HTTPX else tool.value
        )
        version = None
        reason = "missing_binary"
        if executable:
            executable = str(Path(executable).absolute())
            prefix = (executable,)
            # Nikto loads configs before processing even version/help arguments.
            if tool == ToolId.NIKTO:
                prefix += ("-config", str(NIKTO_CONFIG))
            version_text = local_probe((*prefix, *version_args))
            help_text = local_probe((*prefix, *help_args)) if help_args else ""
            if tool == ToolId.NMAP and help_text is not None:
                help_text = help_text.replace("/s", "/-s")
            if version_text is None or help_text is None:
                reason = "binary_probe_failed"
            elif not all(flag in help_text for flag in flags):
                reason = "missing_required_flags"
            else:
                lines = [
                    line.strip() for line in version_text.splitlines() if line.strip()
                ]
                version = next(
                    (line for line in lines if re.search(r"\b[vV]?\d+\.\d+", line)), ""
                )[:500]
                reason = None
            # Artifact filename behavior was verified against Kali Nikto 2.6.0.
            if tool == ToolId.NIKTO and reason is None:
                if not version_text.startswith("Nikto 2.6.0 "):
                    reason = "unsupported_nikto_version"
            if tool == ToolId.NIKTO and reason is None:
                required = (
                    "plugins/nikto_core.plugin",
                    "plugins/nikto_tests.plugin",
                    "plugins/nikto_headers.plugin",
                    "plugins/nikto_report_xml.plugin",
                    "templates/nikto.dtd",
                    "databases/db_tests",
                )
                if not NIKTO_CONFIG.is_file() or not all(
                    (Path("/var/lib/nikto") / item).is_file() for item in required
                ):
                    reason = "nikto_baseline_data_missing"
            if tool == ToolId.NUCLEI and reason is None:
                from app.tools.adapters.optional import NUCLEI_TEMPLATES

                if not all(
                    (NUCLEI_TEMPLATES / name).is_file()
                    for name in (
                        "directory-listing.yaml",
                        "phpinfo.yaml",
                        "git-config.yaml",
                        "missing-csp.yaml",
                    )
                ):
                    reason = "nuclei_baseline_templates_missing"
        capabilities[tool] = ToolCapability(
            tool_id=tool,
            executable=executable,
            version=version,
            enabled=reason is None,
            reason=reason,
        )
    return capabilities
