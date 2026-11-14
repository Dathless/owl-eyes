"""A closed catalog of follow-up actions; the LLM never supplies command syntax."""

from app.schemas import ToolId
from app.tools.adapters.domain import domain_name

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
    "nmap_version_all": (
        ToolId.NMAP,
        "More detailed service detection on the same lab TCP/80 only",
    ),
}


def followup_catalog(scan, used=()):
    return {
        action: {"tool_id": str(tool), "description": description}
        for action, (tool, description) in FOLLOWUPS.items()
        if tool in scan.tools
        and action not in used
        and len(scan.tools[tool].runs) < 4
        and scan.tools[tool].state not in {"skipped", "queued", "running", "cancelled"}
        and (
            scan.target.kind == "public_domain"
            or action in {"curl_head", "nmap_version_all", "whatweb_headers"}
        )
        and (tool != ToolId.OPENSSL or scan.target.scheme == "https")
    }


def followup_spec(adapter, target, action_id, workdir, cookie_header=None):
    selected = FOLLOWUPS.get(action_id)
    if selected is None or selected[0] != adapter.tool_id:
        raise ValueError("Unknown tool action")
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
    elif action_id == "nmap_version_all":
        argv = ["--version-all" if arg == "--version-light" else arg for arg in argv]
    return collection_target, spec.model_copy(
        update={"argv": tuple(argv), "artifact_paths": artifacts}
    )
