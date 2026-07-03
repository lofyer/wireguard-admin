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


def create_peer(db: Session, name: str, expires_at: datetime | None = None) -> Peer:
    private, public = wireguard.generate_keypair()
    psk = wireguard.genpsk()
    address = wireguard.next_free_address([p.address for p in list_peers(db)])
    peer = Peer(
        name=name,
        public_key=public,
        private_key_enc=encrypt(private),
        preshared_key_enc=encrypt(psk),
        address=address,
        expires_at=expires_at,
    )
    db.add(peer)
    db.commit()
    apply_config(db)
    return peer


def rotate_peer_keys(db: Session, peer: Peer) -> Peer:
    private, public = wireguard.generate_keypair()
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
        expires = peer.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if peer.enabled and expires is not None and expires <= now:
            peer.enabled = False
            changed = True
    if changed:
        db.commit()
        apply_config(db)
    return changed


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
