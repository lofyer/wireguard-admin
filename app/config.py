from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    wg_interface: str = "wg0"
    wg_host: str = "127.0.0.1"
    wg_port: int = 51820
    wg_subnet: str = "10.8.0.0/24"
    wg_dns: str = "1.1.1.1"
    wg_allowed_ips: str = "0.0.0.0/0, ::/0"
    wg_persistent_keepalive: int = 25
    wg_config_dir: Path = Path("/etc/wireguard")
    wg_peer_isolation: bool = False

    admin_username: str = "admin"
    admin_password: str = "changeme"
    secret_key: str = "change-this-secret-key"
    session_max_age: int = 12 * 3600

    data_dir: Path = Path("data")

    model_config = {"env_file": ".env"}


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
