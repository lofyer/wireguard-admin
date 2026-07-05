import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import wireguard
from .config import settings
from .crypto import encrypt
from .models import AppSetting, Interface, Peer, TrafficSample

RUNTIME_DEFAULTS = {
    "traffic_sample_interval": "60",
    "traffic_retention_days": "30",
    "online_threshold": "180",
    "ui_refresh_seconds": "5",
}


def get_runtime_settings(db: Session) -> dict[str, int]:
    stored = {s.key: s.value for s in db.scalars(select(AppSetting))}
    result = {}
    for key, default in RUNTIME_DEFAULTS.items():
        try:
            result[key] = int(stored.get(key, default))
        except ValueError:
            result[key] = int(default)
    return result


def update_runtime_settings(db: Session, values: dict[str, int]) -> None:
    bounds = {
        "traffic_sample_interval": (10, 3600),
        "traffic_retention_days": (0, 3650),
        "online_threshold": (30, 3600),
        "ui_refresh_seconds": (2, 300),
    }
    for key, (low, high) in bounds.items():
        if key not in values:
            continue
        value = values[key]
        if not low <= value <= high:
            raise ValueError(f"{key} must be between {low} and {high}")
        setting = db.get(AppSetting, key)
        if setting is None:
            db.add(AppSetting(key=key, value=str(value)))
        else:
            setting.value = str(value)
    db.commit()
    wireguard.status_module.online_threshold_seconds = get_runtime_settings(db)[
        "online_threshold"
    ]


def prune_traffic_samples(db: Session) -> int:
    retention_days = get_runtime_settings(db)["traffic_retention_days"]
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    result = db.execute(
        TrafficSample.__table__.delete().where(TrafficSample.sampled_at < cutoff)
    )
    db.commit()
    return result.rowcount or 0


def list_interfaces(db: Session) -> list[Interface]:
    return list(db.scalars(select(Interface).order_by(Interface.id)))


def get_interface(db: Session, interface_id: int) -> Interface | None:
    return db.get(Interface, interface_id)


def get_interface_by_name(db: Session, name: str) -> Interface | None:
    return db.scalar(select(Interface).where(Interface.name == name))


def _check_interface_conflicts(
    db: Session, name: str, subnet: str, listen_port: int, exclude_id: int | None = None
) -> None:
    for other in list_interfaces(db):
        if other.id == exclude_id:
            continue
        if other.name == name:
            raise ValueError(f"Interface {name} already exists")
        if other.listen_port == listen_port:
            raise ValueError(f"Port {listen_port} is already used by {other.name}")
        if ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network(other.subnet)):
            raise ValueError(f"Subnet {subnet} overlaps {other.name} ({other.subnet})")


def create_interface(
    db: Session,
    name: str,
    subnet: str,
    listen_port: int,
    host: str,
    dns: str = "",
    allowed_ips: str = "",
    persistent_keepalive: int = 25,
    peer_isolation: bool = False,
) -> Interface:
    name = wireguard.validate_interface_name(name)
    subnet = wireguard.validate_subnet(subnet)
    if not 1 <= listen_port <= 65535:
        raise ValueError(f"Invalid port: {listen_port}")
    host = host.strip()
    if not host:
        raise ValueError("Endpoint host is required")
    _check_interface_conflicts(db, name, subnet, listen_port)
    if name in wireguard.system_interfaces():
        raise ValueError(
            f"Interface {name} is already running on this host. "
            "Import it instead of creating a new one."
        )
    private, public = wireguard.generate_keypair()
    iface = Interface(
        name=name,
        subnet=subnet,
        listen_port=listen_port,
        host=host,
        dns=dns.strip() or settings.wg_dns,
        allowed_ips=wireguard.validate_cidr_list(allowed_ips) or settings.wg_allowed_ips,
        persistent_keepalive=persistent_keepalive,
        peer_isolation=peer_isolation,
        private_key_enc=encrypt(private),
        public_key=public,
    )
    db.add(iface)
    db.commit()
    apply_config(db, iface)
    try:
        wireguard.interface_up(iface)
    except Exception:
        pass
    return iface


def _validate_mtu(mtu: int) -> int:
    if mtu and not 1280 <= mtu <= 1500:
        raise ValueError("MTU must be between 1280 and 1500 (0 = default)")
    return mtu


def _validate_mark(value: str, label: str) -> str:
    value = value.strip()
    if value and not value.replace("x", "").replace("X", "").isalnum():
        raise ValueError(f"Invalid {label}: {value}")
    return value


def update_interface(
    db: Session,
    iface: Interface,
    host: str,
    dns: str,
    allowed_ips: str,
    persistent_keepalive: int,
    peer_isolation: bool,
    mtu: int = 0,
    mss_clamp: bool = False,
    fwmark: str = "",
    route_table: str = "",
    post_up: str = "",
    post_down: str = "",
) -> Interface:
    host = host.strip()
    if not host:
        raise ValueError("Endpoint host is required")
    iface.host = host
    iface.dns = dns.strip() or settings.wg_dns
    iface.allowed_ips = (
        wireguard.validate_cidr_list(allowed_ips) or settings.wg_allowed_ips
    )
    iface.persistent_keepalive = persistent_keepalive
    iface.peer_isolation = peer_isolation
    iface.mtu = _validate_mtu(mtu)
    iface.mss_clamp = mss_clamp
    iface.fwmark = _validate_mark(fwmark, "FwMark")
    iface.route_table = _validate_mark(route_table, "Table")
    iface.post_up = post_up.strip()
    iface.post_down = post_down.strip()
    db.commit()
    apply_config(db, iface)
    return iface


def toggle_interface(db: Session, iface: Interface) -> Interface:
    if iface.enabled:
        wireguard.interface_down(iface)
        iface.enabled = False
    else:
        iface.enabled = True
        apply_config(db, iface)
        wireguard.interface_up(iface)
    db.commit()
    return iface


def delete_interface(db: Session, iface: Interface, cascade: bool = False) -> None:
    if iface.peers and not cascade:
        raise ValueError(
            f"Interface {iface.name} still has {len(iface.peers)} peers. "
            "Delete them first or use cascade delete."
        )
    try:
        wireguard.interface_down(iface)
    except Exception:
        pass
    wireguard.backup_config(iface.name)
    path = wireguard.config_path(iface.name)
    if path.exists():
        path.unlink()
    db.delete(iface)
    db.commit()


@dataclass
class ImportCandidate:
    name: str
    has_config: bool
    running: bool
    peer_count: int
    listen_port: int | None
    address: str


def import_candidates(db: Session) -> list[ImportCandidate]:
    known = {iface.name for iface in list_interfaces(db)}
    names = set(wireguard.discover_configs()) | set(wireguard.system_interfaces())
    candidates = []
    for name in sorted(names - known):
        parsed = None
        path = wireguard.config_path(name)
        if path.exists():
            try:
                parsed = wireguard.parse_config(path.read_text())
            except Exception:
                parsed = None
        status = wireguard.get_status(name)
        candidates.append(
            ImportCandidate(
                name=name,
                has_config=parsed is not None and bool(parsed.private_key),
                running=status.up,
                peer_count=len(parsed.peers) if parsed else len(status.peers),
                listen_port=(parsed.listen_port if parsed else None) or status.listen_port,
                address=parsed.address if parsed else "",
            )
        )
    return candidates


def import_interface(db: Session, name: str, host: str) -> Interface:
    name = wireguard.validate_interface_name(name)
    if get_interface_by_name(db, name) is not None:
        raise ValueError(f"Interface {name} is already managed")
    path = wireguard.config_path(name)
    if not path.exists():
        raise ValueError(
            f"No config file at {path}. Only wg-quick configs can be imported."
        )
    parsed = wireguard.parse_config(path.read_text())
    if not parsed.private_key:
        raise ValueError(f"{path} has no PrivateKey")
    if not parsed.address:
        raise ValueError(f"{path} has no Address")
    if not parsed.listen_port:
        raise ValueError(f"{path} has no ListenPort")
    host = host.strip()
    if not host:
        raise ValueError("Endpoint host is required")

    network = ipaddress.ip_interface(parsed.address).network
    subnet = str(network)
    _check_interface_conflicts(db, name, subnet, parsed.listen_port)

    wireguard.backup_config(name)
    iface = Interface(
        name=name,
        subnet=subnet,
        listen_port=parsed.listen_port,
        host=host,
        dns=settings.wg_dns,
        allowed_ips=settings.wg_allowed_ips,
        persistent_keepalive=settings.wg_persistent_keepalive,
        private_key_enc=encrypt(parsed.private_key),
        public_key=wireguard.pubkey(parsed.private_key),
        imported=True,
    )
    db.add(iface)
    db.flush()

    used_names: set[str] = set()
    index = 1
    for parsed_peer in parsed.peers:
        address = ""
        extra: list[str] = []
        for cidr in parsed_peer.allowed_ips:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if not address and net.prefixlen == net.max_prefixlen and net.network_address in network:
                address = f"{net.network_address}/{net.max_prefixlen}"
            else:
                extra.append(str(net))
        if not address:
            address = wireguard.next_free_address(
                subnet, [p.address for p in iface.peers]
            )
        peer_name = parsed_peer.name.strip() or f"imported-{index}"
        while peer_name in used_names:
            index += 1
            peer_name = f"imported-{index}"
        used_names.add(peer_name)
        index += 1
        iface.peers.append(
            Peer(
                name=peer_name,
                public_key=parsed_peer.public_key,
                private_key_enc="",
                preshared_key_enc=(
                    encrypt(parsed_peer.preshared_key)
                    if parsed_peer.preshared_key
                    else ""
                ),
                address=address,
                extra_allowed_ips=", ".join(extra),
            )
        )
    db.commit()
    apply_config(db, iface)
    return iface


def bootstrap_default_interface(db: Session) -> None:
    if list_interfaces(db):
        return
    private_path = settings.data_dir / "server" / "privatekey"
    if private_path.exists():
        private = private_path.read_text().strip()
    else:
        private = wireguard.genkey()
    iface = Interface(
        name=settings.wg_interface,
        subnet=settings.wg_subnet,
        listen_port=settings.wg_port,
        host=settings.wg_host,
        dns=settings.wg_dns,
        allowed_ips=settings.wg_allowed_ips,
        persistent_keepalive=settings.wg_persistent_keepalive,
        peer_isolation=settings.wg_peer_isolation,
        private_key_enc=encrypt(private),
        public_key=wireguard.pubkey(private),
    )
    db.add(iface)
    db.commit()
    db.execute(
        Peer.__table__.update()
        .where(Peer.interface_id.notin_(select(Interface.id)))
        .values(interface_id=iface.id)
    )
    db.commit()


def list_peers(db: Session, iface: Interface | None = None) -> list[Peer]:
    query = select(Peer).order_by(Peer.id)
    if iface is not None:
        query = query.where(Peer.interface_id == iface.id)
    return list(db.scalars(query))


def get_peer(db: Session, peer_id: int) -> Peer | None:
    return db.get(Peer, peer_id)


def create_peer(
    db: Session,
    iface: Interface,
    name: str,
    expires_at: datetime | None = None,
    note: str = "",
    quota_bytes: int = 0,
    address: str = "",
    dns: str = "",
    extra_allowed_ips: str = "",
    client_allowed_ips: str = "",
) -> Peer:
    if any(p.name == name for p in list_peers(db, iface)):
        raise ValueError(f"Peer {name} already exists on {iface.name}")
    private, public = wireguard.generate_keypair()
    psk = wireguard.genpsk()
    taken = [p.address for p in list_peers(db, iface)]
    if address:
        address = wireguard.validate_address(address, iface.subnet, taken)
    else:
        address = wireguard.next_free_address(iface.subnet, taken)
    peer = Peer(
        interface_id=iface.id,
        name=name,
        public_key=public,
        private_key_enc=encrypt(private),
        preshared_key_enc=encrypt(psk),
        address=address,
        expires_at=expires_at,
        note=note,
        quota_bytes=quota_bytes,
        dns=dns,
        extra_allowed_ips=wireguard.validate_cidr_list(extra_allowed_ips),
        client_allowed_ips=wireguard.validate_cidr_list(client_allowed_ips),
    )
    db.add(peer)
    db.commit()
    apply_config(db, iface)
    return peer


def create_peers_batch(
    db: Session,
    iface: Interface,
    base_name: str,
    count: int,
    expires_at: datetime | None = None,
    note: str = "",
    quota_bytes: int = 0,
) -> list[Peer]:
    existing = {p.name for p in list_peers(db, iface)}
    peers = []
    index = 1
    for _ in range(count):
        while f"{base_name}-{index}" in existing:
            index += 1
        name = f"{base_name}-{index}"
        existing.add(name)
        peers.append(create_peer(db, iface, name, expires_at, note, quota_bytes))
    return peers


def update_peer(
    db: Session,
    peer: Peer,
    note: str,
    quota_bytes: int,
    dns: str = "",
    extra_allowed_ips: str = "",
    client_allowed_ips: str = "",
    persistent_keepalive: int | None = None,
) -> Peer:
    peer.note = note
    peer.quota_bytes = quota_bytes
    peer.dns = dns
    peer.extra_allowed_ips = wireguard.validate_cidr_list(extra_allowed_ips)
    peer.client_allowed_ips = wireguard.validate_cidr_list(client_allowed_ips)
    if persistent_keepalive is not None and not 0 <= persistent_keepalive <= 3600:
        raise ValueError("Keepalive must be between 0 and 3600")
    peer.persistent_keepalive = persistent_keepalive
    db.commit()
    if not peer.over_quota:
        apply_config(db, peer.interface)
    return peer


def reset_peer_usage(db: Session, peer: Peer) -> Peer:
    peer.cum_rx = 0
    peer.cum_tx = 0
    db.commit()
    apply_config(db, peer.interface)
    return peer


def rotate_peer_keys(db: Session, peer: Peer) -> Peer:
    private, public = wireguard.generate_keypair()
    peer.last_rx = 0
    peer.last_tx = 0
    peer.public_key = public
    peer.private_key_enc = encrypt(private)
    peer.preshared_key_enc = encrypt(wireguard.genpsk())
    db.commit()
    apply_config(db, peer.interface)
    return peer


def toggle_peer(db: Session, peer: Peer) -> Peer:
    peer.enabled = not peer.enabled
    db.commit()
    apply_config(db, peer.interface)
    return peer


def delete_peer(db: Session, peer: Peer) -> None:
    iface = peer.interface
    db.delete(peer)
    db.commit()
    apply_config(db, iface)


def disable_expired_peers(db: Session) -> bool:
    now = datetime.now(timezone.utc)
    changed_ifaces = []
    for peer in list_peers(db):
        if not peer.enabled:
            continue
        expires = peer.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if (expires is not None and expires <= now) or peer.over_quota:
            peer.enabled = False
            if peer.interface not in changed_ifaces:
                changed_ifaces.append(peer.interface)
    if changed_ifaces:
        db.commit()
        for iface in changed_ifaces:
            apply_config(db, iface)
    return bool(changed_ifaces)


def accumulate_usage(db: Session) -> None:
    changed = False
    for iface in list_interfaces(db):
        status = wireguard.get_status(iface.name)
        for peer in list_peers(db, iface):
            peer_status = status.peers.get(peer.public_key)
            if peer_status is None:
                continue
            rx, tx = peer_status.rx_bytes, peer_status.tx_bytes
            # wg counters reset on interface restart or peer re-add
            delta_rx = rx - peer.last_rx if rx >= peer.last_rx else rx
            delta_tx = tx - peer.last_tx if tx >= peer.last_tx else tx
            if delta_rx or delta_tx or rx != peer.last_rx or tx != peer.last_tx:
                peer.cum_rx += delta_rx
                peer.cum_tx += delta_tx
                peer.last_rx = rx
                peer.last_tx = tx
                changed = True
    if changed:
        db.commit()


def apply_config(db: Session, iface: Interface) -> None:
    if not iface.enabled:
        return
    wireguard.sync_peers(iface, list_peers(db, iface))


def apply_all_configs(db: Session) -> None:
    for iface in list_interfaces(db):
        try:
            apply_config(db, iface)
            if iface.enabled:
                wireguard.interface_up(iface)
        except Exception:
            pass


def sample_traffic(db: Session) -> None:
    for iface in list_interfaces(db):
        status = wireguard.get_status(iface.name)
        for peer_status in status.peers.values():
            db.add(
                TrafficSample(
                    interface_name=iface.name,
                    peer_public_key=peer_status.public_key,
                    rx_bytes=peer_status.rx_bytes,
                    tx_bytes=peer_status.tx_bytes,
                )
            )
    db.commit()
