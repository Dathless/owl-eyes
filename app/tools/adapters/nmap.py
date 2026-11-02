"""Nmap TCP/80 observations from entity-safe XML."""

from defusedxml import ElementTree

from app.schemas import ToolId
from app.tools.adapters.common import Adapter, require


class NmapAdapter(Adapter):
    tool_id = ToolId.NMAP

    def preset(self, target, workdir):
        return (
            (
                "-sT",
                "-sV",
                "--version-light",
                "-Pn",
                "-n",
                "--max-retries",
                "1",
                "--host-timeout",
                "60s",
                "-p",
                "80",
                "-oX",
                "-",
                str(target.ip),
            ),
            90,
            (),
        )

    def extract(self, target, capture, output):
        root = ElementTree.fromstring(
            capture.stdout, forbid_entities=True, forbid_external=True
        )
        require(root.tag == "nmaprun")
        for host_index, host in enumerate(root.findall("host")):
            require(
                any(
                    address.get("addr") == str(target.ip)
                    for address in host.findall("address")
                )
            )
            for port_index, port in enumerate(host.findall("ports/port")):
                require(port.get("protocol") == "tcp" and port.get("portid") == "80")
                state = port.find("state")
                require(state is not None and bool(state.get("state")))
                service = port.find("service")
                value = {"port": 80, "protocol": "tcp", "state": state.get("state")}
                if service is not None:
                    value["service"] = {
                        key: value
                        for key, value in service.attrib.items()
                        if key
                        in {
                            "name",
                            "product",
                            "version",
                            "extrainfo",
                            "method",
                            "conf",
                            "tunnel",
                        }
                    }
                output.add(
                    kind="port",
                    scope="host_service",
                    subject=f"{target.ip}:80/tcp",
                    value=value,
                    source="stdout",
                    locator=(
                        f"/nmaprun/host[{host_index + 1}]/ports/port[{port_index + 1}]"
                    ),
                    excerpt=ElementTree.tostring(port, encoding="unicode"),
                )
        if root.find("runstats/finished") is None:
            output.warn("incomplete_tool_output")
