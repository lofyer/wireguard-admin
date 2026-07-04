from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import wireguard
from .crypto import encrypt
from .models import Peer, TrafficSample


def list_peers(db: Session) -> list[Peer]:
    return list(db.scalars(select(Peer).order_by(Peer.id)))


def get_peer(db: Session, peer_id: int) -> Peer | None:
    return db.get(Peer, peer_id)


def create_peer(
    db: Session,
    name: str,
    expires_at: datetime | None = None,
    note: str = "",
    quota_bytes: int = 0,
    address: str = "",
    dns: str = "",
    extra_allowed_ips: str = "",
    client_allowed_ips: str = "",
) -> Peer:
    private, public = wireguard.generate_keypair()
    psk = wireguard.genpsk()
    taken = [p.address for p in list_peers(db)]
    if address:
        address = wireguard.validate_address(address, taken)
    else:
        address = wireguard.next_free_address(taken)
    peer = Peer(
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
    apply_config(db)
    return peer


def create_peers_batch(
    db: Session,
    base_name: str,
    count: int,
    expires_at: datetime | None = None,
    note: str = "",
    quota_bytes: int = 0,
) -> list[Peer]:
    existing = {p.name for p in list_peers(db)}
    peers = []
    index = 1
    for _ in range(count):
        while f"{base_name}-{index}" in existing:
            index += 1
        name = f"{base_name}-{index}"
        existing.add(name)
        peers.append(create_peer(db, name, expires_at, note, quota_bytes))
    return peers


def update_peer(
    db: Session,
    peer: Peer,
    note: str,
    quota_bytes: int,
    dns: str = "",
    extra_allowed_ips: str = "",
    client_allowed_ips: str = "",
) -> Peer:
    peer.note = note
    peer.quota_bytes = quota_bytes
    peer.dns = dns
    peer.extra_allowed_ips = wireguard.validate_cidr_list(extra_allowed_ips)
    peer.client_allowed_ips = wireguard.validate_cidr_list(client_allowed_ips)
    db.commit()
    if not peer.over_quota:
        apply_config(db)
    return peer


def reset_peer_usage(db: Session, peer: Peer) -> Peer:
    peer.cum_rx = 0
    peer.cum_tx = 0
    db.commit()
    apply_config(db)
    return peer


def rotate_peer_keys(db: Session, peer: Peer) -> Peer:
    private, public = wireguard.generate_keypair()
    peer.last_rx = 0
    peer.last_tx = 0
    peer.public_key = public
    peer.private_key_enc = encrypt(private)
    peer.preshared_key_enc = encrypt(wireguard.genpsk())
    db.commit()
    apply_config(db)
    return peer


def toggle_peer(db: Session, peer: Peer) -> Peer:
    peer.enabled = not peer.enabled
    db.commit()
    apply_config(db)
    return peer


def delete_peer(db: Session, peer: Peer) -> None:
    db.delete(peer)
    db.commit()
    apply_config(db)


def disable_expired_peers(db: Session) -> bool:
    now = datetime.now(timezone.utc)
    changed = False
    for peer in list_peers(db):
        if not peer.enabled:
            continue
        expires = peer.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if (expires is not None and expires <= now) or peer.over_quota:
            peer.enabled = False
            changed = True
    if changed:
        db.commit()
        apply_config(db)
    return changed


def accumulate_usage(db: Session) -> None:
    status = wireguard.get_status()
    changed = False
    for peer in list_peers(db):
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


def apply_config(db: Session) -> None:
    private, _ = wireguard.ensure_server_keys()
    wireguard.sync_peers(private, list_peers(db))


def sample_traffic(db: Session) -> None:
    status = wireguard.get_status()
    for peer_status in status.peers.values():
        db.add(
            TrafficSample(
                peer_public_key=peer_status.public_key,
                rx_bytes=peer_status.rx_bytes,
                tx_bytes=peer_status.tx_bytes,
            )
        )
    db.commit()
