import re
import subprocess

from ..models import Interface, Peer
from .conf import config_path, write_server_config
from .runner import run
from .status import InterfaceStatus, get_status


def is_managed(iface: Interface, status: InterfaceStatus) -> bool:
    return status.public_key == iface.public_key


def interface_up(iface: Interface) -> None:
    status = get_status(iface.name)
    if status.up and not is_managed(iface, status):
        raise RuntimeError(
            f"Interface {iface.name} is up but uses a foreign key; "
            "refusing to manage it. Import it first or pick another name."
        )
    if not status.up:
        run(["wg-quick", "up", str(config_path(iface.name))])
    sync_nat(iface)
    sync_isolation(iface)
    sync_mss_clamp(iface)


def interface_down(iface: Interface) -> None:
    status = get_status(iface.name)
    if status.up and is_managed(iface, status):
        run(["wg-quick", "down", str(config_path(iface.name))])


def sync_routes(iface: Interface, peers: list[Peer]) -> None:
    for peer in peers:
        if not peer.extra_allowed_ips:
            continue
        for subnet in peer.extra_allowed_ips.split(","):
            subnet = subnet.strip()
            args = ["ip", "route", "replace" if peer.enabled else "del", subnet]
            if peer.enabled:
                args += ["dev", iface.name]
            try:
                run(args)
            except subprocess.CalledProcessError:
                pass


def sync_nat(iface: Interface) -> None:
    try:
        route = run(["ip", "route", "show", "default"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return
    match = re.search(r"\bdev\s+(\S+)", route)
    if not match:
        return
    rule = ["POSTROUTING", "-s", iface.subnet, "-o", match.group(1), "-j", "MASQUERADE"]
    try:
        run(["iptables", "-t", "nat", "-C", *rule])
    except FileNotFoundError:
        pass
    except subprocess.CalledProcessError:
        try:
            run(["iptables", "-t", "nat", "-A", *rule])
        except subprocess.CalledProcessError:
            pass


def sync_isolation(iface: Interface) -> None:
    rule = ["-i", iface.name, "-o", iface.name, "-j", "DROP"]
    try:
        if iface.peer_isolation:
            try:
                run(["iptables", "-C", "FORWARD", *rule])
            except subprocess.CalledProcessError:
                run(["iptables", "-I", "FORWARD", "1", *rule])
        else:
            run(["iptables", "-D", "FORWARD", *rule])
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


def sync_mss_clamp(iface: Interface) -> None:
    rule = [
        "-o", iface.name, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ]
    try:
        if iface.mss_clamp:
            try:
                run(["iptables", "-t", "mangle", "-C", "FORWARD", *rule])
            except subprocess.CalledProcessError:
                run(["iptables", "-t", "mangle", "-A", "FORWARD", *rule])
        else:
            run(["iptables", "-t", "mangle", "-D", "FORWARD", *rule])
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


def sync_mtu(iface: Interface) -> None:
    if not iface.mtu:
        return
    try:
        run(["ip", "link", "set", "dev", iface.name, "mtu", str(iface.mtu)])
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


def sync_peers(iface: Interface, peers: list[Peer]) -> None:
    write_server_config(iface, peers)
    status = get_status(iface.name)
    if status.up and is_managed(iface, status):
        stripped = run(["wg-quick", "strip", str(config_path(iface.name))])
        run(["wg", "syncconf", iface.name, "/dev/stdin"], input_text=stripped)
        sync_routes(iface, peers)
        sync_mtu(iface)
    sync_isolation(iface)
    sync_mss_clamp(iface)
