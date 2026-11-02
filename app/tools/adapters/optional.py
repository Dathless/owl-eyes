"""Server-owned optional Kali presets. No operator-supplied arguments or URLs."""

import json
import re
from pathlib import Path

from app.schemas import ToolId
from app.tools.adapters.common import (
    AuthenticatedWebAdapter,
    artifact_json,
    require,
    uri_scope,
)
from app.tools.adapters.ffuf import PATHS

NUCLEI_TEMPLATES = Path(__file__).resolve().parent.parent / "nuclei-templates"
NUCLEI_IDS = {
    "penchecker-directory-listing",
    "penchecker-phpinfo",
    "penchecker-git-config",
    "penchecker-missing-csp",
}


def json_lines(capture, filename):
    for number, line in enumerate(capture.artifacts[filename].splitlines(), 1):
        if line.strip():
            item = json.loads(line)
            require(isinstance(item, dict))
            yield number, item


class IsolatedAdapter(AuthenticatedWebAdapter):
    def build_spec(self, target, workdir):
        config = workdir / "config"
        config.mkdir(exist_ok=True)
        spec = super().build_spec(target, workdir)
        return spec.model_copy(update={"config_directory": config})


class NucleiAdapter(IsolatedAdapter):
    tool_id = ToolId.NUCLEI

    def preset(self, target, workdir):
        config = workdir / "nuclei-config.yaml"
        config.write_text("{}\n", encoding="ascii")
        artifact = workdir / "nuclei.jsonl"
        return (
            (
                "-u",
                target.url,
                "-config",
                str(config),
                "-t",
                str(NUCLEI_TEMPLATES),
                "-s",
                "critical,high,medium,low",
                "-pt",
                "http",
                "-ni",
                "-duc",
                "-dr",
                "-or",
                "-ot",
                "-no-stdin",
                "-nh",
                "-rl",
                "5",
                "-c",
                "1",
                "-bs",
                "1",
                "-timeout",
                "5",
                "-retries",
                "0",
                "-silent",
                "-nc",
                "-jle",
                str(artifact),
            ),
            180,
            (artifact,),
        )

    def extract(self, target, capture, output):
        output.warn("scanner_signals_require_validation")
        output.warn("nuclei_reviewed_templates_only")
        output.warn("nuclei_response_cookie_reuse_possible")
        output.warn("no_matches_does_not_prove_absence")
        for number, item in json_lines(capture, "nuclei.jsonl"):
            url = item.get("matched-at")
            info = item.get("info")
            require(isinstance(url, str) and uri_scope(target, url) == "dvwa_path")
            require(
                item.get("template-id") in NUCLEI_IDS and item.get("type") == "http"
            )
            require(isinstance(info, dict))
            require(info.get("severity") in {"critical", "high", "medium", "low"})
            require(isinstance(info.get("name"), str))
            value = {
                "template_id": item["template-id"],
                "name": info["name"][:300],
                "severity": info["severity"],
                "url": url,
            }
            output.add(
                kind="scanner_signal",
                scope="dvwa_path",
                subject=url,
                value=value,
                source="artifact",
                locator=f"nuclei.jsonl#line:{number}",
                excerpt=json.dumps(value, ensure_ascii=False),
            )


class HttpxAdapter(IsolatedAdapter):
    tool_id = ToolId.HTTPX

    def preset(self, target, workdir):
        config = workdir / "httpx-config.yaml"
        config.write_text("{}\n", encoding="ascii")
        artifact = workdir / "httpx.jsonl"
        return (
            (
                "-u",
                target.url,
                "-config",
                str(config),
                "-j",
                "-o",
                str(artifact),
                "-sc",
                "-cl",
                "-ct",
                "-title",
                "-server",
                "-td",
                "-location",
                "-ob",
                "-nfs",
                "-t",
                "1",
                "-rl",
                "5",
                "-timeout",
                "5",
                "-retries",
                "0",
                "-duc",
                "-silent",
                "-nc",
                "-no-stdin",
                "-allow",
                str(target.ip),
            ),
            30,
            (artifact,),
        )

    def extract(self, target, capture, output):
        output.warn("public_only_coverage")
        output.warn("fingerprints_are_not_confirmed_vulnerabilities")
        count = 0
        for number, item in json_lines(capture, "httpx.jsonl"):
            url = item.get("url")
            require(url == target.url and type(item.get("status_code")) is int)
            require(100 <= item["status_code"] <= 599 and not item.get("failed", False))
            value = {
                key: item[key]
                for key in (
                    "url",
                    "status_code",
                    "content_length",
                    "content_type",
                    "title",
                    "webserver",
                    "tech",
                    "location",
                )
                if key in item
            }
            output.json_item(
                filename="httpx.jsonl",
                pointer=f"line:{number}",
                item=value,
                kind="technology",
                scope="dvwa_path",
                subject=url,
                value=value,
            )
            count += 1
        require(count > 0)


class Wafw00fAdapter(IsolatedAdapter):
    tool_id = ToolId.WAFW00F

    def build_authenticated_spec(self, target, workdir, cookie_header):
        spec = self.build_spec(target, workdir)
        headers = workdir / "headers.txt"
        headers.touch(mode=0o600, exist_ok=False)
        cookies = "; ".join(part.strip() for part in cookie_header.split(";"))
        headers.write_text(f"Cookie: {cookies}\n", encoding="ascii")
        return spec.model_copy(update={"argv": (*spec.argv, "-H", str(headers))})

    def preset(self, target, workdir):
        artifact = workdir / "wafw00f.json"
        return (
            (
                target.url,
                "-r",
                "-T",
                "5",
                "--no-colors",
                "-f",
                "json",
                "-o",
                str(artifact),
            ),
            90,
            (artifact,),
        )

    def extract(self, target, capture, output):
        document = artifact_json(capture, "wafw00f.json")
        require(isinstance(document, list) and len(document) > 0)
        output.warn("public_only_coverage")
        output.warn("waf_fingerprints_are_not_vulnerability_findings")
        for index, item in enumerate(document):
            require(isinstance(item, dict) and item.get("url") == target.url)
            require(type(item.get("detected")) is bool)
            value = {
                key: item[key]
                for key in ("url", "detected", "firewall", "manufacturer")
                if key in item
            }
            output.json_item(
                filename="wafw00f.json",
                pointer=f"/{index}",
                item=value,
                kind="technology",
                scope="dvwa_path",
                subject=target.url,
                value=value,
            )


class GobusterAdapter(IsolatedAdapter):
    tool_id = ToolId.GOBUSTER

    def cookie_arguments(self, cookies):
        return ("--cookies", cookies)

    def preset(self, target, workdir):
        wordlist = workdir / "paths.txt"
        wordlist.write_text("\n".join(PATHS) + "\n", encoding="ascii")
        artifact = workdir / "gobuster.txt"
        return (
            (
                "dir",
                "-u",
                target.url,
                "-w",
                str(wordlist),
                "-t",
                "1",
                "--delay",
                "200ms",
                "--timeout",
                "5s",
                "--no-progress",
                "--no-color",
                "-q",
                "-o",
                str(artifact),
            ),
            75,
            (artifact,),
        )

    def extract(self, target, capture, output):
        output.warn("public_only_coverage")
        output.warn("path_responses_are_not_confirmed_vulnerabilities")
        output.warn("gobuster_wildcard_precheck_may_stop_scan")
        for number, line in enumerate(
            capture.artifacts["gobuster.txt"].splitlines(), 1
        ):
            if not line.strip():
                continue
            match = re.fullmatch(
                r"/?(\S+)\s+\(Status:\s*(\d{3})\)\s+\[Size:\s*(\d+)\](?:\s+\[-->.*\])?",
                line.strip(),
            )
            require(match is not None)
            path, status, size = match.groups()
            require(path in PATHS and 100 <= int(status) <= 599)
            url = target.url.rstrip("/") + "/" + path
            output.add(
                kind="http",
                scope="dvwa_path",
                subject=url,
                value={"url": url, "status": int(status), "length": int(size)},
                source="artifact",
                locator=f"gobuster.txt#line:{number}",
                excerpt=line,
            )


class WapitiAdapter(IsolatedAdapter):
    tool_id = ToolId.WAPITI

    def cookie_arguments(self, cookies):
        return ("--cookie-value", cookies)

    def preset(self, target, workdir):
        artifact = workdir / "wapiti.json"
        return (
            (
                "-u",
                target.url,
                "--scope",
                "url",
                "-m",
                "http_headers,cookieflags,csp",
                "-d",
                "0",
                "--max-links-per-page",
                "0",
                "--max-files-per-dir",
                "1",
                "--max-scan-time",
                "60",
                "--max-attack-time",
                "10",
                "--tasks",
                "1",
                "-t",
                "5",
                "--no-bugreport",
                "--flush-session",
                "--store-session",
                str(workdir / "session"),
                "--store-config",
                str(workdir / "config"),
                "-f",
                "json",
                "-o",
                str(artifact),
                "-v",
                "0",
            ),
            90,
            (artifact,),
        )

    def extract(self, target, capture, output):
        document = artifact_json(capture, "wapiti.json")
        require(isinstance(document, dict) and isinstance(document.get("infos"), dict))
        require(document["infos"].get("target") == target.url)
        vulnerabilities = document.get("vulnerabilities")
        require(isinstance(vulnerabilities, dict))
        output.warn("public_only_coverage")
        output.warn("wapiti_passive_headers_cookies_csp_only")
        output.warn("scanner_signals_require_validation")
        for category, items in vulnerabilities.items():
            require(isinstance(items, list))
            for index, item in enumerate(items):
                require(isinstance(item, dict) and isinstance(item.get("info"), str))
                path = item.get("path")
                require(
                    isinstance(path, str) and uri_scope(target, path) == "dvwa_path"
                )
                require(item.get("module") in {"http_headers", "cookieflags", "csp"})
                value = {
                    "category": category[:200],
                    "info": item["info"][:1000],
                    "url": path,
                    "module": item["module"],
                    "level": item.get("level"),
                }
                output.json_item(
                    filename="wapiti.json",
                    pointer=f"/vulnerabilities/{category}/{index}",
                    item=value,
                    kind="scanner_signal",
                    scope="dvwa_path",
                    subject=path,
                    value=value,
                )
