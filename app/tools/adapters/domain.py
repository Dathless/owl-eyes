"""Fixed public DNS, registration and TLS observations; never exploit a target."""

import re
from urllib.parse import urlsplit

from app.schemas import ToolId
from app.tools.adapters.common import Adapter, require


def domain_name(target):
    return urlsplit(target.url).hostname


def pinned_host(target):
    require(target.ip is not None)
    return f"[{target.ip}]" if target.ip.version == 6 else str(target.ip)


def pinned_url(target):
    return f"{target.scheme}://{pinned_host(target)}/"


class DomainAdapter(Adapter):
    def applicability(self, target):
        return super().applicability(target) or (
            "domain_target_required" if target.kind != "public_domain" else None
        )


class DigAdapter(DomainAdapter):
    tool_id = ToolId.DIG

    def preset(self, target, workdir):
        # -r ignores the operator's ~/.digrc; every query type is server-owned.
        queries = tuple(
            item
            for kind in ("A", "AAAA", "MX", "NS", "TXT", "CAA")
            for item in (domain_name(target), kind)
        )
        return (
            ("-r", "+time=3", "+tries=1", "+noall", "+answer", "+comments", *queries),
            30,
            (),
        )

    def extract(self, target, capture, output):
        statuses = re.findall(r"status: ([A-Z]+),", capture.stdout)
        require(statuses)
        found = False
        for number, line in enumerate(capture.stdout.splitlines(), 1):
            match = re.fullmatch(
                r"(\S+)\s+(\d+)\s+IN\s+(A|AAAA|MX|NS|TXT|CAA|SOA|DNSKEY|RRSIG)\s+(.+)",
                line,
            )
            if not match:
                continue
            # CNAME-chain answers may identify a different public DNS owner;
            # preserve it as domain metadata, never as authorization to scan it.
            owner, ttl, kind, value = match.groups()
            output.add(
                kind="dns",
                scope="domain",
                subject=owner[:200],
                value={"type": kind, "ttl": int(ttl), "data": value[:2000]},
                source="stdout",
                locator=f"line:{number}",
                excerpt=line,
            )
            found = True
        for status in dict.fromkeys(statuses):
            if status != "NOERROR":
                output.warn(f"dns_status_{status.lower()}")
        if not found:
            output.add(
                kind="dns",
                scope="domain",
                subject=domain_name(target),
                value={"statuses": statuses[:6], "answers": 0},
                source="stdout",
                locator="dns:status",
                excerpt=capture.stdout[:1000],
            )
        output.warn("dns_records_do_not_establish_vulnerabilities")


class WhoisAdapter(DomainAdapter):
    tool_id = ToolId.WHOIS

    def preset(self, target, workdir):
        return (("--no-recursion", domain_name(target)), 25, ())

    def extract(self, target, capture, output):
        allowed = {
            "domain name",
            "registrar",
            "registrar whois server",
            "creation date",
            "updated date",
            "registry expiry date",
            "registrar registration expiration date",
            "domain status",
            "name server",
            "dnssec",
        }
        count = 0
        for number, line in enumerate(capture.stdout.splitlines(), 1):
            key, separator, value = line.strip().partition(":")
            if separator and key.lower() in allowed and value.strip():
                output.add(
                    kind="registration",
                    scope="domain",
                    subject=key[:200],
                    value={"value": value.strip()[:2000]},
                    source="stdout",
                    locator=f"line:{number}",
                    excerpt=line,
                )
                count += 1
        if not count:
            require(bool(capture.stdout.strip()))
            output.add(
                kind="registration",
                scope="domain",
                subject=domain_name(target),
                value={"status": "unavailable"},
                source="stdout",
                locator="whois:response",
                excerpt=capture.stdout[:1000],
            )
            output.warn("registration_data_unavailable")
        output.warn("registration_metadata_only")


class OpenSSLAdapter(DomainAdapter):
    tool_id = ToolId.OPENSSL

    def applicability(self, target):
        return super().applicability(target) or (
            "https_required" if target.scheme != "https" else None
        )

    def preset(self, target, workdir):
        return (
            (
                "s_client",
                "-connect",
                f"{pinned_host(target)}:443",
                "-servername",
                domain_name(target),
                "-verify_hostname",
                domain_name(target),
                "-verify_return_error",
                "-brief",
                "-no_ign_eof",
            ),
            20,
            (),
        )

    def extract(self, target, capture, output):
        text = capture.stderr + "\n" + capture.stdout
        fields = {}
        names = {
            "Protocol version": "protocol",
            "Ciphersuite": "cipher",
            "Peer certificate": "certificate_subject",
            "Verification": "verification",
            "Verified peername": "verified_peername",
            "Verification error": "verification_error",
        }
        for line in text.splitlines():
            key, separator, value = line.strip().partition(":")
            if separator and key in names:
                fields[names[key]] = value.strip()[:1000]
        if "verification_error" not in fields:
            error = re.search(r"verify error:num=\d+:([^\n]+)", text)
            if error:
                fields["verification_error"] = error[1][:1000]
        require(fields)
        source = "stderr" if capture.stderr.strip() else "stdout"
        output.add(
            kind="tls",
            scope="host_service",
            subject=f"{domain_name(target)}:443",
            value=fields,
            source=source,
            locator="tls:handshake",
            excerpt=text.strip()[:1000],
        )
        output.warn("single_tls_handshake_not_full_protocol_audit")
        if fields.get("verification") != "OK":
            output.warn("tls_certificate_not_verified")
