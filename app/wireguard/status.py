import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .runner import run

DEFAULT_ONLINE_THRESHOLD_SECONDS = 180

# Adjustable at runtime from the settings page.
online_threshold_seconds = DEFAULT_ONLINE_THRESHOLD_SECONDS


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
        return delta.total_seconds() < online_threshold_seconds


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


def get_status(name: str) -> InterfaceStatus:
    status = InterfaceStatus(name=name)
    try:
        output = run(["wg", "show", name, "dump"])
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


def system_interfaces() -> list[str]:
    try:
        output = run(["wg", "show", "interfaces"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return output.split()
