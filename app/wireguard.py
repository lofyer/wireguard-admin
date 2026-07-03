import ipaddress
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import settings
from .crypto import decrypt
from .models import Peer

ONLINE_THRESHOLD_SECONDS = 180


def _run(args: list[str], input_text: str | None = None) -> str:
    result = subprocess.run(
        args, input=input_text, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def genkey() -> str:
    return _run(["wg", "genkey"])


def genpsk() -> str:
    return _run(["wg", "genpsk"])


def pubkey(private_key: str) -> str:
    return _run(["wg", "pubkey"], input_text=private_key)


def generate_keypair() -> tuple[str, str]:
    private = genkey()
    return private, pubkey(private)


@dataclass
class PeerStatus:
    public_key: str
    endpoint: str | None = None
    latest_handshake: datetime | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0

    @property
    def online(self) -> bool:
        if self.latest_handshake is None:
            return False
        delta = datetime.now(timezone.utc) - self.latest_handshake
        return delta.total_seconds() < ONLINE_THRESHOLD_SECONDS


@dataclass
class InterfaceStatus:
    name: str
    public_key: str | None = None
    listen_port: int | None = None
    up: bool = False
    peers: dict[str, PeerStatus] = field(default_factory=dict)

    @property
    def total_rx(self) -> int:
        return sum(p.rx_bytes for p in self.peers.values())

    @property
    def total_tx(self) -> int:
        return sum(p.tx_bytes for p in self.peers.values())


def get_status() -> InterfaceStatus:
    status = InterfaceStatus(name=settings.wg_interface)
    try:
        output = _run(["wg", "show", settings.wg_interface, "dump"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return status

    status.up = True
    lines = output.splitlines()
    if lines:
        fields = lines[0].split("\t")
        if len(fields) >= 3:
            status.public_key = fields[1]
            status.listen_port = int(fields[2])
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        peer = PeerStatus(public_key=fields[0])
        if fields[2] != "(none)":
            peer.endpoint = fields[2]
        handshake = int(fields[4])
        if handshake:
            peer.latest_handshake = datetime.fromtimestamp(handshake, tz=timezone.utc)
        peer.rx_bytes = int(fields[5])
        peer.tx_bytes = int(fields[6])
        status.peers[peer.public_key] = peer
    return status


def _server_key_paths() -> tuple:
    key_dir = settings.data_dir / "server"
    return key_dir / "privatekey", key_dir / "publickey"


def ensure_server_keys() -> tuple[str, str]:
    private_path, public_path = _server_key_paths()
    if private_path.exists() and public_path.exists():
        return private_path.read_text().strip(), public_path.read_text().strip()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private, public = generate_keypair()
    private_path.touch(mode=0o600)
    private_path.write_text(private + "\n")
    public_path.write_text(public + "\n")
    return private, public


def server_address() -> str:
    network = ipaddress.ip_network(settings.wg_subnet)
    return f"{next(network.hosts())}/{network.prefixlen}"


def next_free_address(taken: list[str]) -> str:
    network = ipaddress.ip_network(settings.wg_subnet)
    used = {ipaddress.ip_interface(a).ip for a in taken}
    hosts = network.hosts()
    used.add(next(hosts))
    for host in hosts:
        if host not in used:
            return f"{host}/32"
    raise RuntimeError(f"No free addresses left in {settings.wg_subnet}")


def render_server_config(private_key: str, peers: list[Peer]) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {server_address()}",
        f"ListenPort = {settings.wg_port}",
    ]
    for peer in peers:
        if not peer.enabled:
            continue
        lines += [
            "",
            "[Peer]",
            f"# {peer.name}",
            f"PublicKey = {peer.public_key}",
            f"PresharedKey = {decrypt(peer.preshared_key_enc)}",
            f"AllowedIPs = {peer.address}",
        ]
    return "\n".join(lines) + "\n"


def render_client_config(peer: Peer, server_public_key: str) -> str:
    return "\n".join(
        [
            "[Interface]",
            f"PrivateKey = {decrypt(peer.private_key_enc)}",
            f"Address = {peer.address}",
            f"DNS = {settings.wg_dns}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"PresharedKey = {decrypt(peer.preshared_key_enc)}",
            f"Endpoint = {settings.wg_host}:{settings.wg_port}",
            f"AllowedIPs = {settings.wg_allowed_ips}",
            f"PersistentKeepalive = {settings.wg_persistent_keepalive}",
        ]
    ) + "\n"


def write_server_config(private_key: str, peers: list[Peer]) -> None:
    settings.wg_config_dir.mkdir(parents=True, exist_ok=True)
    config_path = settings.wg_config_dir / f"{settings.wg_interface}.conf"
    config_path.touch(mode=0o600)
    config_path.write_text(render_server_config(private_key, peers))


def interface_up() -> None:
    if not get_status().up:
        _run(["wg-quick", "up", settings.wg_interface])


def sync_peers(private_key: str, peers: list[Peer]) -> None:
    write_server_config(private_key, peers)
    if get_status().up:
        stripped = _run(
            ["wg-quick", "strip", str(settings.wg_config_dir / f"{settings.wg_interface}.conf")]
        )
        _run(["wg", "syncconf", settings.wg_interface, "/dev/stdin"], input_text=stripped)
