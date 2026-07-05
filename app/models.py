from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Interface(Base):
    __tablename__ = "interfaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(15), unique=True)
    subnet: Mapped[str] = mapped_column(String(64))
    listen_port: Mapped[int] = mapped_column(Integer, unique=True)
    host: Mapped[str] = mapped_column(String(256))
    dns: Mapped[str] = mapped_column(String(128), default="1.1.1.1")
    allowed_ips: Mapped[str] = mapped_column(String(512), default="0.0.0.0/0, ::/0")
    persistent_keepalive: Mapped[int] = mapped_column(Integer, default=25)
    peer_isolation: Mapped[bool] = mapped_column(Boolean, default=False)
    mtu: Mapped[int] = mapped_column(Integer, default=0)
    mss_clamp: Mapped[bool] = mapped_column(Boolean, default=False)
    fwmark: Mapped[str] = mapped_column(String(32), default="")
    route_table: Mapped[str] = mapped_column(String(32), default="")
    post_up: Mapped[str] = mapped_column(String(2048), default="")
    post_down: Mapped[str] = mapped_column(String(2048), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    private_key_enc: Mapped[str] = mapped_column(String(256))
    public_key: Mapped[str] = mapped_column(String(64), unique=True)
    imported: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    peers: Mapped[list["Peer"]] = relationship(
        back_populates="interface", cascade="all, delete-orphan"
    )


class Peer(Base):
    __tablename__ = "peers"
    __table_args__ = (
        UniqueConstraint("interface_id", "name", name="uq_peer_iface_name"),
        UniqueConstraint("interface_id", "address", name="uq_peer_iface_address"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    interface_id: Mapped[int] = mapped_column(
        ForeignKey("interfaces.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(64))
    public_key: Mapped[str] = mapped_column(String(64), unique=True)
    private_key_enc: Mapped[str] = mapped_column(String(256), default="")
    preshared_key_enc: Mapped[str] = mapped_column(String(256), default="")
    address: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    note: Mapped[str] = mapped_column(String(256), default="")
    dns: Mapped[str] = mapped_column(String(128), default="")
    extra_allowed_ips: Mapped[str] = mapped_column(String(512), default="")
    client_allowed_ips: Mapped[str] = mapped_column(String(512), default="")
    persistent_keepalive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quota_bytes: Mapped[int] = mapped_column(Integer, default=0)
    cum_rx: Mapped[int] = mapped_column(Integer, default=0)
    cum_tx: Mapped[int] = mapped_column(Integer, default=0)
    last_rx: Mapped[int] = mapped_column(Integer, default=0)
    last_tx: Mapped[int] = mapped_column(Integer, default=0)

    interface: Mapped[Interface] = relationship(back_populates="peers")

    @property
    def cum_total(self) -> int:
        return self.cum_rx + self.cum_tx

    @property
    def over_quota(self) -> bool:
        return self.quota_bytes > 0 and self.cum_total >= self.quota_bytes

    @property
    def has_private_key(self) -> bool:
        return bool(self.private_key_enc)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256), default="")


class TrafficSample(Base):
    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    interface_name: Mapped[str] = mapped_column(String(15), default="", index=True)
    peer_public_key: Mapped[str] = mapped_column(String(64), index=True)
    rx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
