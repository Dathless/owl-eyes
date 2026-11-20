"""A closed catalog of follow-up actions; the LLM never supplies command syntax."""

import json
import re

from app.schemas import ToolId
from app.services.targets import alternate_target
from app.tools.adapters.domain import domain_name
from app.tools.public_web import IIS_PATHS

IIS_FINGERPRINT = re.compile(r"\b(?:microsoft[-_ ]iis|iis|asp(?:[._]net)?)\b", re.I)
PUBLIC_ONLY = {"ffuf_iis_paths"}

# Each ID selects fixed code below. No flags, URL, path or hostname come from AI.
FOLLOWUPS = {
    "curl_head": (
        ToolId.CURL,
        "Compare the HEAD response headers with the default GET",
    ),
    "curl_robots": (ToolId.CURL, "Read only /robots.txt on the selected public origin"),
    "curl_security": (
        ToolId.CURL,
        "Read only /.well-known/security.txt on the selected public origin",
    ),
    "dig_soa": (ToolId.DIG, "Read SOA and CAA records for the selected domain"),
    "dig_dnssec": (
        ToolId.DIG,
        "Request DNSSEC DNSKEY records; this does not validate the chain",
    ),
    "openssl_tls12": (
        ToolId.OPENSSL,
        "Try a TLS 1.2 handshake with hostname verification",
    ),
    "openssl_tls13": (
        ToolId.OPENSSL,
        "Try a TLS 1.3 handshake with hostname verification",
    ),
    "whatweb_headers": (ToolId.WHATWEB, "Use HTTP header fingerprint plugins only"),
    "httpx_head": (ToolId.HTTPX, "Compare HEAD website metadata with the default GET"),
    "nikto_headers": (
        ToolId.NIKTO,
        "Collect HTTP headers using the reviewed headers plugin only",
    ),
    "wget_head": (ToolId.WGET, "Compare the HEAD response with the default GET"),
    "nmap_version_all": (
        ToolId.NMAP,
        "More detailed service detection on the same reviewed web TCP ports",
    ),
    "ffuf_iis_paths": (
        ToolId.FFUF,
        "Probe eleven reviewed IIS/ASP.NET paths (web.config, trace.axd, elmah.axd, "
        "_vti_bin/...) after an IIS or ASP fingerprint",
    ),
}


def iis_fingerprinted(scan) -> bool:
    """True when a collected fingerprint names IIS or ASP/ASP.NET."""
    for result in scan.tools.values():
        for item in result.observations:
            if item.kind not in {"technology", "http", "port"}:
                continue
            text = item.subject + " " + json.dumps(item.value, ensure_ascii=False)
            if IIS_FINGERPRINT.search(text):
                return True
    return False


def path_returned(scan, path: str) -> bool:
    """True when a path-discovery observation shows the origin path answered 200."""
    suffix = "/" + path
    return any(
        item.kind == "http"
        and item.subject.endswith(suffix)
        and item.value.get("status", item.value.get("status_code")) == 200
        for result in scan.tools.values()
        for item in result.observations
    )


def evidence_hint(scan, action: str) -> str | None:
    """Server-computed relevance; the model still decides whether to run it."""
    if action == "ffuf_iis_paths":
        return "IIS/ASP fingerprint observed; default paths target other stacks"
    if action == "curl_robots" and path_returned(scan, "robots.txt"):
        return "robots.txt answered 200 but its content was not read"
    if action == "curl_security" and path_returned(scan, ".well-known/security.txt"):
        return "security.txt answered 200 but its content was not read"
    return None


def followup_catalog(scan, used=()):
    catalog = {}
    for action, (tool, description) in FOLLOWUPS.items():
        if not (
            tool in scan.tools
            and action not in used
            and len(scan.tools[tool].runs) < 4
            and scan.tools[tool].state
            not in {"skipped", "queued", "running", "cancelled"}
            and (
                scan.target.kind == "public_domain"
                or action in {"curl_head", "nmap_version_all", "whatweb_headers"}
            )
            and (
                tool != ToolId.OPENSSL
                or scan.target.scheme == "https"
                or alternate_target(scan.target, scan.resolution) is not None
            )
            and (action != "ffuf_iis_paths" or iis_fingerprinted(scan))
        ):
            continue
        catalog[action] = {"tool_id": str(tool), "description": description}
        if hint := evidence_hint(scan, action):
            catalog[action]["evidence"] = hint
    return catalog


def followup_spec(adapter, target, action_id, workdir, cookie_header=None):
    selected = FOLLOWUPS.get(action_id)
    if selected is None or selected[0] != adapter.tool_id:
        raise ValueError("Unknown tool action")
    if target.kind != "public_domain" and action_id in PUBLIC_ONLY:
        raise ValueError("Unsupported target action")
    if target.kind != "public_domain" and action_id not in {
        "curl_head",
        "nmap_version_all",
        "whatweb_headers",
    }:
        raise ValueError("Unsupported target action")
    collection_target = target.model_copy(deep=True)
    if action_id in {"curl_robots", "curl_security"}:
        path = (
            "robots.txt" if action_id == "curl_robots" else ".well-known/security.txt"
        )
        collection_target = target.model_copy(
            update={"url": target.url.rstrip("/") + "/" + path}
        )
    spec = (
        adapter.build_authenticated_spec(collection_target, workdir, cookie_header)
        if cookie_header is not None
        else adapter.build_spec(collection_target, workdir)
    )
    argv = list(spec.argv)
    artifacts = spec.artifact_paths
    if action_id == "ffuf_iis_paths":
        wordlist = argv[argv.index("-w") + 1]
        with open(wordlist, "w", encoding="ascii") as handle:
            handle.write("\n".join(IIS_PATHS) + "\n")
    if action_id in {"curl_robots", "curl_security"}:
        artifact = workdir / "http-body.txt"
        argv[argv.index("--output") + 1] = str(artifact)
        argv.extend(("--max-filesize", "8192"))
        artifacts = (*artifacts, artifact)
    if action_id == "curl_head":
        argv.insert(2, "--head")
    elif action_id in {"dig_soa", "dig_dnssec"}:
        types = ("SOA", "CAA") if action_id == "dig_soa" else ("DNSKEY",)
        argv = [argv[0], "-r", "+time=3", "+tries=1", "+noall", "+answer", "+comments"]
        if action_id == "dig_dnssec":
            argv.append("+dnssec")
        for kind in types:
            argv.extend((domain_name(target), kind))
    elif action_id in {"openssl_tls12", "openssl_tls13"}:
        argv.append("-tls1_2" if action_id == "openssl_tls12" else "-tls1_3")
    elif action_id == "whatweb_headers":
        argv.append("--plugins=HTTPServer,X-Powered-By,Modern-Security-Headers")
    elif action_id == "httpx_head":
        argv[argv.index("-x") + 1] = "HEAD"
    elif action_id == "nikto_headers":
        argv[argv.index("-Plugins") + 1] = "headers;report_xml"
    elif action_id == "wget_head":
        argv.extend(("--method=HEAD", "--server-response"))
    elif action_id == "nmap_version_all":
        argv = ["--version-all" if arg == "--version-light" else arg for arg in argv]
    return collection_target, spec.model_copy(
        update={"argv": tuple(argv), "artifact_paths": artifacts}
    )
