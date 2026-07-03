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
    "quota_bytes": "ALTER TABLE peers ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0",
    "cum_rx": "ALTER TABLE peers ADD COLUMN cum_rx INTEGER NOT NULL DEFAULT 0",
    "cum_tx": "ALTER TABLE peers ADD COLUMN cum_tx INTEGER NOT NULL DEFAULT 0",
    "last_rx": "ALTER TABLE peers ADD COLUMN last_rx INTEGER NOT NULL DEFAULT 0",
    "last_tx": "ALTER TABLE peers ADD COLUMN last_tx INTEGER NOT NULL DEFAULT 0",
}


def run_migrations() -> None:
    with engine.connect() as conn:
        existing = {
            row[1] for row in conn.execute(text("PRAGMA table_info(peers)"))
        }
        for column, ddl in PEER_MIGRATIONS.items():
            if existing and column not in existing:
                conn.execute(text(ddl))
        conn.commit()
