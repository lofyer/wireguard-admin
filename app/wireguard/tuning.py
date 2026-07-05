import re
import subprocess
from dataclasses import dataclass

from .runner import run


def _sysctl_get(key: str) -> str:
    try:
        return run(["sysctl", "-n", key])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _sysctl_set(key: str, value: str) -> bool:
    try:
        run(["sysctl", "-w", f"{key}={value}"])
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def default_out_interface() -> str:
    try:
        route = run(["ip", "route", "show", "default"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    match = re.search(r"\bdev\s+(\S+)", route)
    return match.group(1) if match else ""


@dataclass
class HostTuning:
    rmem_max: str = ""
    wmem_max: str = ""
    netdev_max_backlog: str = ""
    ip_forward: str = ""
    gro_forwarding: str = ""
    out_interface: str = ""


def read_host_tuning() -> HostTuning:
    tuning = HostTuning(
        rmem_max=_sysctl_get("net.core.rmem_max"),
        wmem_max=_sysctl_get("net.core.wmem_max"),
        netdev_max_backlog=_sysctl_get("net.core.netdev_max_backlog"),
        ip_forward=_sysctl_get("net.ipv4.ip_forward"),
        out_interface=default_out_interface(),
    )
    if tuning.out_interface:
        try:
            output = run(["ethtool", "-k", tuning.out_interface])
            match = re.search(r"rx-udp-gro-forwarding:\s*(\S+)", output)
            if match:
                tuning.gro_forwarding = match.group(1)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    return tuning


def apply_udp_buffers(size_bytes: int) -> list[str]:
    errors = []
    for key in ("net.core.rmem_max", "net.core.wmem_max"):
        if not _sysctl_set(key, str(size_bytes)):
            errors.append(f"failed to set {key}")
    return errors


def apply_backlog(value: int) -> list[str]:
    if _sysctl_set("net.core.netdev_max_backlog", str(value)):
        return []
    return ["failed to set net.core.netdev_max_backlog"]


def apply_gro_forwarding(enable: bool) -> list[str]:
    device = default_out_interface()
    if not device:
        return ["no default route interface found"]
    state = "on" if enable else "off"
    try:
        run(
            [
                "ethtool", "-K", device,
                "rx-udp-gro-forwarding", state,
                "rx-gro-list", "off" if enable else "on",
            ]
        )
        return []
    except FileNotFoundError:
        return ["ethtool not installed"]
    except subprocess.CalledProcessError as exc:
        return [f"ethtool failed on {device}: {exc.stderr.strip() or exc}"]
