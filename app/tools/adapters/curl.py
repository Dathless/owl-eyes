"""Single HTTP response without redirects or curlrc configuration."""

import json
import re
from urllib.parse import urljoin, urlsplit

from app.schemas import ToolId
from app.tools.adapters.common import (
    AuthenticatedWebAdapter,
    matches_dvwa_entry,
    require,
    uri_scope,
)

META_MARKER = "__LAB_META__"


class CurlAdapter(AuthenticatedWebAdapter):
    tool_id = ToolId.CURL

    def cookie_arguments(self, cookies):
        return ("--cookie", cookies)

    def preset(self, target, workdir):
        public = target.kind == "public_domain"
        pin = ()
        if public:
            from app.tools.adapters.domain import domain_name, pinned_host

            pin = (
                "--resolve",
                f"{domain_name(target)}:{target.port}:{pinned_host(target)}",
            )
        return (
            (
                "-q",
                "--noproxy",
                "*",
                "--globoff",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "--proto",
                "=http,https" if public else "=http",
                *pin,
                "--dump-header",
                "-",
                "--output",
                "/dev/null",
                "--write-out",
                f"\n{META_MARKER}%{{json}}\n",
                target.url,
            ),
            20,
            (),
        )

    def extract(self, target, capture, output):
        headers, marker, raw_meta = capture.stdout.rpartition("\n" + META_MARKER)
        require(marker)
        meta = json.loads(raw_meta)
        require(
            isinstance(meta, dict)
            and matches_dvwa_entry(target, meta.get("url_effective"))
        )
        blocks = re.findall(r"HTTP/\S+ [^\r\n]+(?:\r?\n(?!\r?\n)[^\r\n]*)*", headers)
        require(blocks)
        block = blocks[-1]
        lines = block.splitlines()
        status = int(lines[0].split()[1])
        require(100 <= status <= 599 and status == meta.get("http_code"))
        fields = {}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            require(sep)
            fields[key.lower()] = value.strip()
        value = {"status": status, "url_effective": meta["url_effective"]}
        location = fields.get("location")
        if location:
            value["location"] = location
        start = capture.stdout.index(block)
        line_number = capture.stdout[:start].count("\n") + 1
        output.add(
            kind="http",
            scope="http_origin" if target.kind == "public_domain" else "dvwa_path",
            subject="response",
            value=value,
            source="stdout",
            locator=f"lines:{line_number}-{line_number + len(lines) - 1}",
            excerpt=block,
        )
        # Headers describe the origin even when collected from a DVWA URL.
        for key in ("server", "x-powered-by", "www-authenticate"):
            if key in fields:
                output.add(
                    kind="http",
                    scope="http_origin",
                    subject=key,
                    value={key: fields[key]},
                    source="stdout",
                    locator=f"header:{key}",
                    excerpt=next(
                        line for line in lines[1:] if line.lower().startswith(key + ":")
                    ),
                )
        output.warn("public_only_coverage")
        if target.kind == "public_domain" and "http-body.txt" in capture.artifacts:
            body = capture.artifacts["http-body.txt"]
            if body:
                output.add(
                    kind="http",
                    scope="http_origin",
                    subject="public_metadata",
                    value={"path": urlsplit(target.url).path, "text": body[:1500]},
                    source="artifact",
                    locator="http-body.txt",
                    excerpt=body[:1000],
                )
                if len(body) > 1500:
                    output.warn("metadata_body_truncated")
        if status in {401, 403}:
            output.warn("authentication_required")
        if 300 <= status < 400:
            output.warn("redirect_not_followed")
            if location:
                destination = urljoin(target.url, location)
                if uri_scope(target, destination) == "dvwa_path" and urlsplit(
                    destination
                ).path.endswith("/login.php"):
                    output.warn("authentication_required")
                if target.url.endswith("/dvwa") and destination == target.url + "/":
                    output.warn("slash_normalization_redirect")
