from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(
    f"sqlite:///{settings.data_dir / 'wireguard.db'}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


PEER_MIGRATIONS = {
    "note": "ALTER TABLE peers ADD COLUMN note VARCHAR(256) NOT NULL DEFAULT ''",
    "dns": "ALTER TABLE peers ADD COLUMN dns VARCHAR(128) NOT NULL DEFAULT ''",
    "extra_allowed_ips": "ALTER TABLE peers ADD COLUMN extra_allowed_ips VARCHAR(512) NOT NULL DEFAULT ''",
    "client_allowed_ips": "ALTER TABLE peers ADD COLUMN client_allowed_ips VARCHAR(512) NOT NULL DEFAULT ''",
    "quota_bytes": "ALTER TABLE peers ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0",
    "cum_rx": "ALTER TABLE peers ADD COLUMN cum_rx INTEGER NOT NULL DEFAULT 0",
    "cum_tx": "ALTER TABLE peers ADD COLUMN cum_tx INTEGER NOT NULL DEFAULT 0",
    "last_rx": "ALTER TABLE peers ADD COLUMN last_rx INTEGER NOT NULL DEFAULT 0",
    "last_tx": "ALTER TABLE peers ADD COLUMN last_tx INTEGER NOT NULL DEFAULT 0",
}

PEER_COLUMNS = (
    "id, interface_id, name, public_key, private_key_enc, preshared_key_enc, "
    "address, enabled, expires_at, created_at, note, dns, extra_allowed_ips, "
    "client_allowed_ips, quota_bytes, cum_rx, cum_tx, last_rx, last_tx"
)


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}


def _rebuild_peers_with_interface(conn) -> None:
    # SQLite cannot alter unique constraints in place; rebuild the table so
    # name/address become unique per interface instead of globally.
    conn.execute(text("ALTER TABLE peers RENAME TO peers_old"))
    conn.execute(
        text(
            """
            CREATE TABLE peers (
                id INTEGER NOT NULL PRIMARY KEY,
                interface_id INTEGER NOT NULL DEFAULT 1 REFERENCES interfaces (id) ON DELETE CASCADE,
                name VARCHAR(64) NOT NULL,
                public_key VARCHAR(64) NOT NULL UNIQUE,
                private_key_enc VARCHAR(256) NOT NULL DEFAULT '',
                preshared_key_enc VARCHAR(256) NOT NULL DEFAULT '',
                address VARCHAR(64) NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                expires_at DATETIME,
                created_at DATETIME NOT NULL,
                note VARCHAR(256) NOT NULL DEFAULT '',
                dns VARCHAR(128) NOT NULL DEFAULT '',
                extra_allowed_ips VARCHAR(512) NOT NULL DEFAULT '',
                client_allowed_ips VARCHAR(512) NOT NULL DEFAULT '',
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                cum_rx INTEGER NOT NULL DEFAULT 0,
                cum_tx INTEGER NOT NULL DEFAULT 0,
                last_rx INTEGER NOT NULL DEFAULT 0,
                last_tx INTEGER NOT NULL DEFAULT 0,
                CONSTRAINT uq_peer_iface_name UNIQUE (interface_id, name),
                CONSTRAINT uq_peer_iface_address UNIQUE (interface_id, address)
            )
            """
        )
    )
    old_columns = _columns(conn, "peers_old")
    select_columns = ", ".join(
        column.strip() if column.strip() in old_columns else f"1 AS {column.strip()}"
        for column in PEER_COLUMNS.split(",")
    )
    conn.execute(
        text(
            f"INSERT INTO peers ({PEER_COLUMNS}) SELECT {select_columns} FROM peers_old"
        )
    )
    conn.execute(text("DROP TABLE peers_old"))
    conn.execute(
        text("CREATE INDEX ix_peers_interface_id ON peers (interface_id)")
    )


INTERFACE_MIGRATIONS = {
    "mtu": "ALTER TABLE interfaces ADD COLUMN mtu INTEGER NOT NULL DEFAULT 0",
    "mss_clamp": "ALTER TABLE interfaces ADD COLUMN mss_clamp BOOLEAN NOT NULL DEFAULT 0",
    "fwmark": "ALTER TABLE interfaces ADD COLUMN fwmark VARCHAR(32) NOT NULL DEFAULT ''",
    "route_table": "ALTER TABLE interfaces ADD COLUMN route_table VARCHAR(32) NOT NULL DEFAULT ''",
    "post_up": "ALTER TABLE interfaces ADD COLUMN post_up VARCHAR(2048) NOT NULL DEFAULT ''",
    "post_down": "ALTER TABLE interfaces ADD COLUMN post_down VARCHAR(2048) NOT NULL DEFAULT ''",
}


def run_migrations() -> None:
    with engine.connect() as conn:
        peer_columns = _columns(conn, "peers")
        for column, ddl in PEER_MIGRATIONS.items():
            if peer_columns and column not in peer_columns:
                conn.execute(text(ddl))
        if peer_columns and "interface_id" not in peer_columns:
            _rebuild_peers_with_interface(conn)
            peer_columns = _columns(conn, "peers")
        if peer_columns and "persistent_keepalive" not in peer_columns:
            conn.execute(
                text("ALTER TABLE peers ADD COLUMN persistent_keepalive INTEGER")
            )
        iface_columns = _columns(conn, "interfaces")
        for column, ddl in INTERFACE_MIGRATIONS.items():
            if iface_columns and column not in iface_columns:
                conn.execute(text(ddl))
        sample_columns = _columns(conn, "traffic_samples")
        if sample_columns and "interface_name" not in sample_columns:
            conn.execute(
                text(
                    "ALTER TABLE traffic_samples ADD COLUMN "
                    "interface_name VARCHAR(15) NOT NULL DEFAULT ''"
                )
            )
        conn.commit()
