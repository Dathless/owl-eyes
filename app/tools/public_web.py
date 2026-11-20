"""Reviewed public website paths and each CLI's native proxy arguments."""

from urllib.parse import urlsplit

from app.schemas import WEB_TOOL_IDS, TargetSpec, ToolSpec

PUBLIC_PATHS = (
    "index.html",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".git/config",
    "README.md",
    "docs/",
    "phpinfo.php",
)

# Agent follow-up only, offered after an IIS/ASP fingerprint; GET requests only.
IIS_PATHS = (
    "web.config",
    "trace.axd",
    "elmah.axd",
    "global.asa",
    "iisstart.htm",
    "default.asp",
    "default.aspx",
    "aspnet_client/",
    "_vti_bin/",
    "_vti_inf.html",
    "admin/",
)


def public_paths(target: TargetSpec) -> tuple[str, ...]:
    from app.tools.adapters.ffuf import PATHS

    return PUBLIC_PATHS if target.kind == "public_domain" else PATHS


def path_profiles(target: TargetSpec) -> tuple[tuple[str, ...], ...]:
    """Every complete reviewed path list a parser may accept for this target."""
    if target.kind == "public_domain":
        return (PUBLIC_PATHS, IIS_PATHS)
    return (public_paths(target),)


def web_scope(target: TargetSpec) -> str:
    return "http_origin" if target.kind == "public_domain" else "dvwa_path"


def apply_public_proxy(spec: ToolSpec, proxy_url: str) -> ToolSpec:
    """Keep the original URL/Host/SNI; transport alone connects to the pin."""
    if spec.tool_id not in WEB_TOOL_IDS:
        return spec
    proxy = urlsplit(proxy_url)
    if (
        proxy.scheme != "http"
        or proxy.hostname != "127.0.0.1"
        or not proxy.port
        or proxy.username is not None
        or proxy.password is not None
        or proxy.path
        or proxy.query
        or proxy.fragment
    ):
        raise ValueError("loopback_proxy_required")
    argv = list(spec.argv)
    if spec.tool_id == "curl":
        if "--noproxy" in argv:
            offset = argv.index("--noproxy")
            del argv[offset : offset + 2]
        options = ("--proxy", proxy_url)
    elif spec.tool_id == "wget":
        argv = [arg for arg in argv if arg != "--no-proxy"]
        options = (
            "--execute=use_proxy=yes",
            f"--execute=http_proxy={proxy_url}",
            f"--execute=https_proxy={proxy_url}",
            "--execute=no_proxy=",
        )
    else:
        options = {
            "whatweb": ("--proxy", proxy.netloc),
            "ffuf": ("-x", proxy_url),
            "nikto": ("-useproxy", proxy_url),
            "nuclei": ("-proxy", proxy_url),
            # httpx applies its -allow network policy to the proxy dial as well.
            "httpx": ("-http-proxy", proxy_url, "-allow", proxy.hostname),
            "wafw00f": ("-p", proxy_url),
            "gobuster": ("--proxy", proxy_url),
            "wapiti": ("-p", proxy_url),
            "dirb": ("-p", proxy.netloc),
        }[spec.tool_id]
    return spec.model_copy(update={"argv": (*argv, *options)})
