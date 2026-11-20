"""Baseline scanner signals; no exploit or severity inference."""

from io import StringIO
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml.ElementTree import iterparse, tostring

from app.schemas import ErrorInfo, ToolId, ToolState
from app.tools.adapters.common import (
    AuthenticatedWebAdapter,
    artifact_json,
    require,
    uri_scope,
)
from app.tools.adapters.domain import domain_name

NIKTO_CONFIG = Path(__file__).resolve().parent.parent / "nikto.conf"
# cgi first: Nikto checks its 23 CGI directories once and expands @CGIDIRS tests
# only into those that exist; without it ~380 tests run in all 23 directories.
NIKTO_PLUGINS = "cgi;tests;headers;report_xml"


class NiktoAdapter(AuthenticatedWebAdapter):
    tool_id = ToolId.NIKTO

    def build_authenticated_spec(self, target, workdir, cookie_header):
        spec = self.build_spec(target, workdir)
        # Kali 2.6.0 consumes STATIC-COOKIE; addcookie alone is silently ignored.
        static_cookies = ";".join(f'"{cookie}"' for cookie in cookie_header.split(";"))
        return spec.model_copy(
            update={
                "argv": (
                    *spec.argv,
                    "-Option",
                    f"addcookie={cookie_header}",
                    "-Option",
                    f"STATIC-COOKIE={static_cookies}",
                )
            }
        )

    def preset(self, target, workdir):
        artifact = workdir / "nikto.xml"
        origin = urlsplit(target.url)._replace(path="", query="", fragment="").geturl()
        return (
            (
                "-config",
                str(NIKTO_CONFIG),
                "-Plugins",
                NIKTO_PLUGINS,
                "-h",
                origin,
                "-root",
                target.base_path,
                "-Tuning",
                "123b",
                "-Pause",
                "0.2",
                "-maxtime",
                "900s",
                "-timeout",
                "5",
                "-nointeractive",
                "-nolookup",
                "-nocheck",
                "-ask",
                "no",
                "-nocookies",
                "-Format",
                "xml",
                "-output",
                str(workdir / "nikto"),
            ),
            930,
            (artifact,),
        )

    def extract(self, target, capture, output):
        output.warn("public_only_coverage")
        output.warn("scanner_signals_require_validation")
        output.warn("nikto_root_is_not_a_path_sandbox")
        if target.kind == "public_domain" and target.scheme == "https":
            output.warn("tool_tls_certificate_verification_disabled")
            output.warn("nikto_headers_include_hostless_http10_probe")
        elif target.kind == "public_domain":
            output.warn("nikto_hostless_probes_sent_with_saved_host")
        if "nikto.xml" in capture.artifacts:
            self.extract_xml(target, capture, output)
            return
        # Historical JSON captures remain replayable; production emits XML.
        document = artifact_json(capture, "nikto.json")
        require(isinstance(document, list))
        for host_index, host in enumerate(document):
            require(
                isinstance(host, dict)
                and host.get("ip")
                in (
                    {str(target.ip), domain_name(target)}
                    if target.kind == "public_domain"
                    else {str(target.ip)}
                )
                and str(host.get("port")) == str(target.port)
                and isinstance(host.get("vulnerabilities"), list)
            )
            for index, item in enumerate(host["vulnerabilities"]):
                require(isinstance(item, dict) and isinstance(item.get("msg"), str))
                require(item.get("id") != "FAIL")
                uri = item.get("url", "")
                require(isinstance(uri, str))
                if target.kind == "public_domain":
                    require(uri_scope(target, uri or target.url) == "http_origin")
                value = {
                    key: item[key]
                    for key in ("id", "msg", "url", "method", "references")
                    if key in item
                }
                output.json_item(
                    filename="nikto.json",
                    pointer=f"/{host_index}/vulnerabilities/{index}",
                    item=item,
                    kind="scanner_signal",
                    scope=(
                        "http_origin"
                        if target.kind == "public_domain"
                        or str(item.get("id")) in {"999986", "013587"}
                        else uri_scope(target, uri)
                    ),
                    subject=str(item.get("id", "scanner signal")),
                    value=value,
                )

    def extract_xml(self, target, capture, output):
        stack = []
        host_index, index = -1, 0
        for event, item in iterparse(
            StringIO(capture.artifacts["nikto.xml"]), events=("start", "end")
        ):
            if event == "start":
                if not stack:
                    require(item.tag == "niktoscans")
                stack.append(item.tag)
                if item.tag == "scandetails":
                    require(
                        item.get("targetip")
                        in (
                            {str(target.ip), domain_name(target)}
                            if target.kind == "public_domain"
                            else {str(target.ip)}
                        )
                        and item.get("targetport") == str(target.port)
                    )
                    host_index += 1
                    index = 0
                continue
            if item.tag == "item":
                require(host_index >= 0 and stack[-2] == "scandetails")
                identifier = item.get("id")
                message, uri = item.findtext("description"), item.findtext("uri", "")
                require(identifier and identifier != "FAIL" and message)
                if target.kind == "public_domain":
                    require(uri_scope(target, uri or target.url) == "http_origin")
                output.add(
                    kind="scanner_signal",
                    scope="http_origin"
                    if target.kind == "public_domain"
                    or identifier in {"999986", "013587"}
                    else uri_scope(target, uri),
                    subject=identifier,
                    value={
                        "id": identifier,
                        "msg": message,
                        "url": uri,
                        "method": item.get("method", ""),
                        "references": item.findtext("references", ""),
                    },
                    source="artifact",
                    locator=f"nikto.xml#scandetails/{host_index}/item/{index}",
                    excerpt=tostring(item, encoding="unicode"),
                )
                index += 1
            stack.pop()
        require(host_index >= 0)

    def parse(self, target, capture, scan_id):
        result = super().parse(target, capture, scan_id)
        if "Host maximum execution time of" in capture.stderr + capture.stdout:
            result.state = ToolState.TIMED_OUT
            result.error = ErrorInfo(
                code="tool_timeout",
                message="Nikto reached its time limit; coverage is incomplete.",
            )
            result.warnings.append("nikto_internal_time_limit")
        return result
