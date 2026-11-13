"""Installed Kali CLI presets for bounded DVWA and host-service observations."""

import re

from app.schemas import ToolId
from app.tools.adapters.common import Adapter, dvwa_entry_url, require, uri_scope
from app.tools.adapters.ffuf import PATHS
from app.tools.adapters.optional import IsolatedAdapter

SNMP_OIDS = (".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0")


class DirbAdapter(IsolatedAdapter):
    tool_id = ToolId.DIRB

    def cookie_arguments(self, cookies):
        return ("-c", cookies)

    def preset(self, target, workdir):
        wordlist = workdir / "paths.txt"
        wordlist.write_text("\n".join(PATHS) + "\n", encoding="ascii")
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
                allowed = {target.url.rstrip("/") + "/" + path for path in PATHS}
                require(uri_scope(target, url) == "dvwa_path" and url in allowed)
                value = {"url": url}
                if match:
                    require(100 <= int(match[2]) <= 599)
                    value.update(status=int(match[2]), length=int(match[3]))
                output.add(
                    kind="http",
                    scope="dvwa_path",
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
        headers, separator, _ = text.partition("\n\n")
        require(bool(separator))
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
            scope="dvwa_path",
            subject=dvwa_entry_url(target),
            value=value,
            source="artifact",
            locator="wget-response.txt#headers",
            excerpt=headers,
        )


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
        output.warn("host_service_not_dvwa_coverage")
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
        output.warn("host_service_not_dvwa_coverage")
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
                f"udp:{target.ip}:161",
                *SNMP_OIDS,
            ),
            8,
            (),
        )

    def extract(self, target, capture, output):
        output.warn("snmp_public_read_only_system_oids")
        output.warn("host_service_not_dvwa_coverage")
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
