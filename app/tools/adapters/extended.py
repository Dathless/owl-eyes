"""Installed Kali CLI presets for bounded DVWA and host-service observations."""

import re

from app.schemas import ToolId
from app.tools.adapters.common import Adapter, dvwa_entry_url, require, uri_scope
from app.tools.adapters.optional import IsolatedAdapter
from app.tools.public_web import public_paths, web_scope

SNMP_OIDS = (".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0")


class DirbAdapter(IsolatedAdapter):
    tool_id = ToolId.DIRB

    def cookie_arguments(self, cookies):
        return ("-c", cookies)

    def preset(self, target, workdir):
        wordlist = workdir / "paths.txt"
        wordlist.write_text("\n".join(public_paths(target)) + "\n", encoding="ascii")
        artifact = workdir / "dirb.txt"
        return (
            (
                target.url,
                str(wordlist),
                "-r",
                "-t",
                "-S",
                "-z",
                "200",
                "-o",
                str(artifact),
            ),
            75,
            (artifact,),
        )

    def extract(self, target, capture, output):
        output.warn("path_responses_are_not_confirmed_vulnerabilities")
        output.warn("dirb_wildcard_precheck_may_stop_scan")
        if target.kind == "public_domain" and target.scheme == "https":
            output.warn("tool_tls_certificate_verification_disabled")
        output.warn("no_matches_does_not_prove_absence")
        text = capture.artifacts["dirb.txt"]
        for number, line in enumerate(text.splitlines(), 1):
            if line.startswith("+ ") or line.startswith("==> DIRECTORY:"):
                match = re.fullmatch(
                    r"\+ (\S+) \(CODE:(\d{3})\|SIZE:(\d+)\)", line.strip()
                )
                directory = re.fullmatch(r"==> DIRECTORY: (\S+)", line.strip())
                require(match is not None or directory is not None)
                url = match[1] if match else directory[1]
                allowed = {
                    target.url.rstrip("/") + "/" + path for path in public_paths(target)
                }
                require(uri_scope(target, url) == web_scope(target) and url in allowed)
                value = {"url": url}
                if match:
                    require(100 <= int(match[2]) <= 599)
                    value.update(status=int(match[2]), length=int(match[3]))
                output.add(
                    kind="http",
                    scope=web_scope(target),
                    subject=url,
                    value=value,
                    source="artifact",
                    locator=f"dirb.txt#line:{number}",
                    excerpt=line,
                )
        require("END_TIME:" in text)


class WgetAdapter(IsolatedAdapter):
    tool_id = ToolId.WGET

    def cookie_arguments(self, cookies):
        return ("--header", f"Cookie: {cookies}")

    def preset(self, target, workdir):
        artifact = workdir / "wget-response.txt"
        return (
            (
                "--no-config",
                "--no-proxy",
                "--no-cookies",
                "--max-redirect=0",
                "--tries=1",
                "--timeout=5",
                "--no-hsts",
                "--no-netrc",
                "--save-headers",
                "--content-on-error",
                "--output-document",
                str(artifact),
                target.url,
            ),
            20,
            (artifact,),
        )

    def extract(self, target, capture, output):
        text = capture.artifacts["wget-response.txt"].replace("\r\n", "\n")
        source, locator = "artifact", "wget-response.txt#headers"
        if text:
            headers, separator, _ = text.partition("\n\n")
            require(bool(separator))
        else:
            # Wget turns --method=HEAD into spider mode and writes no output file.
            blocks = list(
                re.finditer(
                    r"(?m)^  HTTP/1\.[01] [1-5]\d{2}[^\n]*\n(?:  [^\n]*\n)*",
                    capture.stderr,
                )
            )
            require(bool(blocks))
            block = blocks[-1]
            headers = "\n".join(line[2:] for line in block[0].splitlines())
            require(len(headers.splitlines()) > 1)
            require("connection established" not in headers.splitlines()[0].lower())
            start = capture.stderr[: block.start()].count("\n") + 1
            source, locator = (
                "stderr",
                f"lines:{start}-{start + len(headers.splitlines()) - 1}",
            )
        lines = headers.splitlines()
        match = re.fullmatch(r"HTTP/1\.[01] ([1-5]\d{2})(?: .*)?", lines[0])
        require(match is not None)
        value = {"url": dvwa_entry_url(target), "status": int(match[1])}
        for line in lines[1:]:
            name, colon, content = line.partition(":")
            require(bool(colon))
            if name.lower() in {"server", "content-type", "location", "content-length"}:
                value[name.lower()] = content.strip()[:300]
        output.warn("http_response_is_not_a_vulnerability_finding")
        output.add(
            kind="technology",
            scope=web_scope(target),
            subject=dvwa_entry_url(target),
            value=value,
            source=source,
            locator=locator,
            excerpt=headers,
        )


def host_scope_warnings(target, output):
    if target.kind == "public_domain":
        output.warn("host_service_on_resolved_domain_ip")
        output.warn("resolved_ip_may_serve_other_domains")
    else:
        output.warn("host_service_not_dvwa_coverage")


class HostAdapter(Adapter):
    def build_spec(self, target, workdir):
        config = workdir / "config"
        config.mkdir(exist_ok=True)
        spec = super().build_spec(target, workdir)
        return spec.model_copy(update={"config_directory": config})


def samba_arguments(target, workdir):
    config = workdir / "smb.conf"
    # Metasploitable2's legacy Samba requires NT1; never modify the host config.
    config.write_text(
        "[global]\nclient min protocol = NT1\nclient ipc min protocol = NT1\n",
        encoding="ascii",
    )
    return (
        "-s",
        str(config),
        "-N",
        "-U",
        "%",
        "--use-kerberos=off",
        "-I",
        str(target.ip),
        "-p",
        "445",
    )


class SmbclientAdapter(HostAdapter):
    tool_id = ToolId.SMBCLIENT

    def preset(self, target, workdir):
        return (
            (*samba_arguments(target, workdir), "-g", "-t", "5", "-L", str(target.ip)),
            25,
            (),
        )

    def extract(self, target, capture, output):
        output.warn("anonymous_share_listing_does_not_prove_file_access")
        host_scope_warnings(target, output)
        count = 0
        for number, line in enumerate(capture.stdout.splitlines(), 1):
            if "|" not in line:
                continue
            fields = line.split("|", 2)
            require(len(fields) == 3)
            category, name, comment = fields
            require(category in {"Disk", "IPC", "Printer", "Server", "Workgroup"})
            if category in {"Server", "Workgroup"}:
                continue
            require(bool(name))
            output.add(
                kind="technology",
                scope="host_service",
                subject=f"{target.ip}:445/tcp",
                value={"share": name[:200], "type": category, "comment": comment[:500]},
                source="stdout",
                locator=f"line:{number}",
                excerpt=line,
            )
            count += 1
        require(count > 0)


class RpcclientAdapter(HostAdapter):
    tool_id = ToolId.RPCCLIENT

    def preset(self, target, workdir):
        return (
            (*samba_arguments(target, workdir), "-c", "srvinfo", str(target.ip)),
            20,
            (),
        )

    def extract(self, target, capture, output):
        text = capture.stdout
        fields = {}
        patterns = {
            "platform_id": r"\d+",
            "os version": r"\d+\.\d+",
            "server type": r"0x[0-9a-fA-F]+",
        }
        for name, pattern in patterns.items():
            match = re.search(rf"(?m)^\s*{name}\s*:\s*({pattern})\s*$", text)
            require(match is not None)
            fields[name.replace(" ", "_")] = match[1]
        output.warn("rpc_server_metadata_is_not_a_confirmed_vulnerability")
        host_scope_warnings(target, output)
        output.add(
            kind="technology",
            scope="host_service",
            subject=f"{target.ip}:445/tcp",
            value=fields,
            source="stdout",
            locator="srvinfo",
            excerpt=text,
        )


class SnmpgetAdapter(HostAdapter):
    tool_id = ToolId.SNMPGET

    def preset(self, target, workdir):
        return (
            (
                "-v",
                "2c",
                "-c",
                "public",
                "-r",
                "0",
                "-t",
                "2",
                "-m",
                "",
                "-On",
                f"udp6:[{target.ip}]:161"
                if target.ip.version == 6
                else f"udp:{target.ip}:161",
                *SNMP_OIDS,
            ),
            8,
            (),
        )

    def extract(self, target, capture, output):
        output.warn("snmp_public_read_only_system_oids")
        host_scope_warnings(target, output)
        seen = set()
        for number, line in enumerate(capture.stdout.splitlines(), 1):
            if not line.strip():
                continue
            match = re.fullmatch(r"(\.1\.\d[\d.]*) = STRING: (.+)", line)
            require(match is not None)
            oid, value = match.groups()
            require(oid in SNMP_OIDS and oid not in seen)
            seen.add(oid)
            output.add(
                kind="technology",
                scope="host_service",
                subject=f"{target.ip}:161/udp",
                value={"oid": oid, "value": value[:1000]},
                source="stdout",
                locator=f"line:{number}",
                excerpt=line,
            )
        require(seen == set(SNMP_OIDS))
