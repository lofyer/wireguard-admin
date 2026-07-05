import ipaddress
import re


def server_address(subnet: str) -> str:
    network = ipaddress.ip_network(subnet)
    return f"{next(network.hosts())}/{network.prefixlen}"


def validate_interface_name(name: str) -> str:
    name = name.strip()
    if not re.fullmatch(r"[a-zA-Z0-9_=+.-]{1,15}", name):
        raise ValueError(f"Invalid interface name: {name}")
    return name


def validate_subnet(subnet: str) -> str:
    try:
        network = ipaddress.ip_network(subnet.strip(), strict=True)
    except ValueError:
        raise ValueError(f"Invalid subnet: {subnet}")
    if network.num_addresses < 4:
        raise ValueError(f"Subnet {network} is too small")
    return str(network)


def subnets_overlap(subnet: str, others: list[str]) -> str | None:
    network = ipaddress.ip_network(subnet)
    for other in others:
        if network.overlaps(ipaddress.ip_network(other)):
            return other
    return None


def validate_address(address: str, subnet: str, taken: list[str]) -> str:
    network = ipaddress.ip_network(subnet)
    try:
        ip = ipaddress.ip_address(address.split("/")[0].strip())
    except ValueError:
        raise ValueError(f"Invalid IP address: {address}")
    if ip not in network:
        raise ValueError(f"{ip} is not in subnet {subnet}")
    if ip in (network.network_address, network.broadcast_address):
        raise ValueError(f"{ip} is not a usable host address")
    if ip == next(network.hosts()):
        raise ValueError(f"{ip} is reserved for the server")
    if ip in {ipaddress.ip_interface(a).ip for a in taken}:
        raise ValueError(f"{ip} is already assigned to another peer")
    return f"{ip}/32"


def next_free_address(subnet: str, taken: list[str]) -> str:
    network = ipaddress.ip_network(subnet)
    used = {ipaddress.ip_interface(a).ip for a in taken}
    hosts = network.hosts()
    used.add(next(hosts))
    for host in hosts:
        if host not in used:
            return f"{host}/32"
    raise RuntimeError(f"No free addresses left in {subnet}")


def validate_cidr_list(value: str) -> str:
    networks = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            raise ValueError(f"Invalid CIDR: {part}")
    return ", ".join(networks)
