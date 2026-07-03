from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Peer(Base):
    __tablename__ = "peers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    public_key: Mapped[str] = mapped_column(String(64), unique=True)
    private_key_enc: Mapped[str] = mapped_column(String(256))
    preshared_key_enc: Mapped[str] = mapped_column(String(256))
    address: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    note: Mapped[str] = mapped_column(String(256), default="")
    quota_bytes: Mapped[int] = mapped_column(Integer, default=0)
    cum_rx: Mapped[int] = mapped_column(Integer, default=0)
    cum_tx: Mapped[int] = mapped_column(Integer, default=0)
    last_rx: Mapped[int] = mapped_column(Integer, default=0)
    last_tx: Mapped[int] = mapped_column(Integer, default=0)

    @property
    def cum_total(self) -> int:
        return self.cum_rx + self.cum_tx

    @property
    def over_quota(self) -> bool:
        return self.quota_bytes > 0 and self.cum_total >= self.quota_bytes


class TrafficSample(Base):
    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    peer_public_key: Mapped[str] = mapped_column(String(64), index=True)
    rx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
