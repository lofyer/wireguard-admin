from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..config import settings
from ..crypto import decrypt
from ..models import Interface, Peer
from .addressing import server_address


def config_path(name: str) -> Path:
    return settings.wg_config_dir / f"{name}.conf"


def discover_configs() -> list[str]:
    if not settings.wg_config_dir.exists():
        return []
    return sorted(p.stem for p in settings.wg_config_dir.glob("*.conf"))


def server_allowed_ips(peer: Peer) -> str:
    allowed = peer.address
    if peer.extra_allowed_ips:
        allowed += f", {peer.extra_allowed_ips}"
    return allowed


def render_server_config(iface: Interface, peers: list[Peer]) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {decrypt(iface.private_key_enc)}",
        f"Address = {server_address(iface.subnet)}",
        f"ListenPort = {iface.listen_port}",
    ]
    if iface.mtu:
        lines.append(f"MTU = {iface.mtu}")
    if iface.fwmark:
        lines.append(f"FwMark = {iface.fwmark}")
    if iface.route_table:
        lines.append(f"Table = {iface.route_table}")
    if iface.mss_clamp:
        rule = (
            "-o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
        )
        lines.append(f"PostUp = iptables -t mangle -A FORWARD {rule}")
        lines.append(f"PostDown = iptables -t mangle -D FORWARD {rule} || true")
    # wg-quick adds routes for /32 peer addresses automatically; extra
    # site subnets need explicit routes so return traffic enters the tunnel.
    for peer in peers:
        if peer.enabled and peer.extra_allowed_ips:
            for subnet in peer.extra_allowed_ips.split(","):
                subnet = subnet.strip()
                lines.append(f"PostUp = ip route replace {subnet} dev %i")
    for command in (iface.post_up or "").splitlines():
        command = command.strip()
        if command:
            lines.append(f"PostUp = {command}")
    for command in (iface.post_down or "").splitlines():
        command = command.strip()
        if command:
            lines.append(f"PostDown = {command}")
    for peer in peers:
        if not peer.enabled:
            continue
        lines += [
            "",
            "[Peer]",
            f"# {peer.name}",
            f"PublicKey = {peer.public_key}",
        ]
        if peer.preshared_key_enc:
            lines.append(f"PresharedKey = {decrypt(peer.preshared_key_enc)}")
        lines.append(f"AllowedIPs = {server_allowed_ips(peer)}")
    return "\n".join(lines) + "\n"


def render_client_config(peer: Peer, iface: Interface) -> str:
    if not peer.has_private_key:
        raise ValueError(
            "Peer has no private key (imported). Rotate keys to generate a config."
        )
    lines = [
        "[Interface]",
        f"PrivateKey = {decrypt(peer.private_key_enc)}",
        f"Address = {peer.address}",
        f"DNS = {peer.dns or iface.dns}",
    ]
    if iface.mtu:
        lines.append(f"MTU = {iface.mtu}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {iface.public_key}",
    ]
    if peer.preshared_key_enc:
        lines.append(f"PresharedKey = {decrypt(peer.preshared_key_enc)}")
    keepalive = (
        peer.persistent_keepalive
        if peer.persistent_keepalive is not None
        else iface.persistent_keepalive
    )
    lines += [
        f"Endpoint = {iface.host}:{iface.listen_port}",
        f"AllowedIPs = {peer.client_allowed_ips or iface.allowed_ips}",
    ]
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def write_server_config(iface: Interface, peers: list[Peer]) -> None:
    settings.wg_config_dir.mkdir(parents=True, exist_ok=True)
    path = config_path(iface.name)
    path.touch(mode=0o600)
    path.write_text(render_server_config(iface, peers))


def backup_config(name: str) -> Path | None:
    path = config_path(name)
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup = path.with_name(f"{name}.conf.bak-{stamp}")
    backup.write_bytes(path.read_bytes())
    backup.chmod(0o600)
    return backup


@dataclass
class ParsedPeer:
    public_key: str = ""
    preshared_key: str = ""
    allowed_ips: list[str] = field(default_factory=list)
    name: str = ""


@dataclass
class ParsedConfig:
    private_key: str = ""
    address: str = ""
    listen_port: int | None = None
    peers: list[ParsedPeer] = field(default_factory=list)


def parse_config(text: str) -> ParsedConfig:
    parsed = ParsedConfig()
    section = ""
    current: ParsedPeer | None = None
    pending_comment = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            comment = line.lstrip("# ").strip()
            if section == "peer" and current is not None and not current.name:
                current.name = comment
            else:
                pending_comment = comment
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            if section == "peer":
                current = ParsedPeer(name=pending_comment)
                parsed.peers.append(current)
            pending_comment = ""
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if section == "interface":
            if key == "privatekey":
                parsed.private_key = value
            elif key == "address":
                parsed.address = value.split(",")[0].strip()
            elif key == "listenport":
                parsed.listen_port = int(value)
        elif section == "peer" and current is not None:
            if key == "publickey":
                current.public_key = value
            elif key == "presharedkey":
                current.preshared_key = value
            elif key == "allowedips":
                current.allowed_ips += [v.strip() for v in value.split(",") if v.strip()]
    parsed.peers = [p for p in parsed.peers if p.public_key]
    return parsed
