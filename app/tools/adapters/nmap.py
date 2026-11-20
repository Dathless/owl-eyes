"""Nmap TCP service observations from entity-safe XML."""

from defusedxml import ElementTree

from app.schemas import ToolId
from app.tools.adapters.common import Adapter, require

# Public domains: reviewed common service ports on the nslookup-resolved pin.
PUBLIC_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
)  # fmt: skip


def ports(target):
    return PUBLIC_PORTS if target.kind == "public_domain" else (80,)


class NmapAdapter(Adapter):
    tool_id = ToolId.NMAP

    def preset(self, target, workdir):
        return (
            (
                *(("-6",) if target.ip.version == 6 else ()),
                "-sT",
                "-sV",
                "--version-light",
                "-Pn",
                "-n",
                "--max-retries",
                "1",
                "--host-timeout",
                "120s" if target.kind == "public_domain" else "60s",
                "-p",
                ",".join(map(str, ports(target))),
                "-oX",
                "-",
                str(target.ip),
            ),
            150 if target.kind == "public_domain" else 90,
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
                allowed = {str(number) for number in ports(target)}
                require(port.get("protocol") == "tcp" and port.get("portid") in allowed)
                number = int(port.get("portid"))
                state = port.find("state")
                require(state is not None and bool(state.get("state")))
                service = port.find("service")
                value = {"port": number, "protocol": "tcp", "state": state.get("state")}
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
                    subject=f"{target.ip}:{number}/tcp",
                    value=value,
                    source="stdout",
                    locator=(
                        f"/nmaprun/host[{host_index + 1}]/ports/port[{port_index + 1}]"
                    ),
                    excerpt=ElementTree.tostring(port, encoding="unicode"),
                )
        if root.find("runstats/finished") is None:
            output.warn("incomplete_tool_output")
