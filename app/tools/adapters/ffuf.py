"""Bounded DVWA path discovery for a literal IPv4 target."""

from app.schemas import ToolId
from app.tools.adapters.common import AuthenticatedWebAdapter, artifact_json, require

PATHS = (
    "index.php",
    "login.php",
    "robots.txt",
    "README",
    "CHANGELOG.txt",
    "docs/",
    "config/",
    "php.ini",
)


class FfufAdapter(AuthenticatedWebAdapter):
    tool_id = ToolId.FFUF

    def cookie_arguments(self, cookies):
        return ("-b", cookies)

    def build_spec(self, target, workdir):
        spec = super().build_spec(target, workdir)
        config = workdir / "config"
        (config / "ffuf" / "scraper").mkdir(parents=True, exist_ok=True)
        return spec.model_copy(update={"config_directory": config})

    def preset(self, target, workdir):
        wordlist = workdir / "paths.txt"
        wordlist.write_text("\n".join(PATHS) + "\n", encoding="ascii")
        artifact = workdir / "ffuf.json"
        return (
            (
                "-config",
                "/dev/null",
                "-u",
                target.url.rstrip("/") + "/FUZZ",
                "-w",
                str(wordlist),
                "-t",
                "1",
                "-rate",
                "5",
                "-timeout",
                "5",
                "-maxtime",
                "30",
                "-noninteractive",
                "-s",
                "-mc",
                "all",
                "-ignore-body",
                "-scrapers",
                "",
                "-of",
                "json",
                "-o",
                str(artifact),
            ),
            35,
            (artifact,),
        )

    def extract(self, target, capture, output):
        document = artifact_json(capture, "ffuf.json")
        require(
            isinstance(document, dict) and isinstance(document.get("results"), list)
        )
        results = document["results"]
        expected = {target.url.rstrip("/") + "/" + path for path in PATHS}
        seen = set()
        for index, item in enumerate(results):
            require(isinstance(item, dict))
            url, status, length = (
                item.get("url"),
                item.get("status"),
                item.get("length"),
            )
            require(url in expected and url not in seen)
            require(type(status) is int and 100 <= status <= 599)
            require(type(length) is int and length >= 0)
            seen.add(url)
            value = {"url": url, "status": status, "length": length}
            if location := item.get("redirectlocation"):
                require(isinstance(location, str))
                value["location"] = location
            output.json_item(
                filename="ffuf.json",
                pointer=f"/results/{index}",
                item=item,
                kind="http",
                scope="dvwa_path",
                subject=url,
                value=value,
            )
        output.warn("public_only_coverage")
        output.warn("path_responses_are_not_confirmed_vulnerabilities")
        output.warn("redirects_not_followed")
        if seen != expected:
            output.warn("path_discovery_incomplete")
            require(False)
