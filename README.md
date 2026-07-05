# WireGuard Admin

Self-hosted WireGuard management panel: multiple interfaces, peer lifecycle, live topology, traffic quotas and kernel performance tuning in a single container.

Stack: FastAPI + Jinja2 + SQLite + Tailwind (precompiled) + ECharts. No external services required.

![Docker Hub](https://img.shields.io/badge/docker-lofyer%2Fwireguard--admin-blue)

## Features

### Multi-interface management
- Create any number of WireGuard interfaces (own subnet, port, endpoint host, DNS, keepalive)
- Import existing wg-quick configs: takes over the server key, peers, preshared keys and site subnets; a timestamped backup of the original `.conf` is kept
- Imported peers work as-is (public key only); optionally rotate keys per peer to let the panel generate configs/QR for them
- Enable/disable (up/down) interfaces, cascade delete, conflict checks (name, port, overlapping subnets)

### Peers
- Auto or manual IP assignment, batch creation, notes, expiry dates (auto-disable), traffic quotas (auto-disable when exceeded)
- Per-peer DNS, client routes (AllowedIPs), site subnets behind a peer (site-to-site), keepalive override (0 = off for fixed-IP peers)
- Key rotation, enable/disable, `.conf` download, QR code, copy to clipboard, client setup guide (Linux/macOS/Windows/iOS/Android)
- Private keys and preshared keys encrypted at rest (Fernet, derived from `SECRET_KEY`)

### Topology
- Horizontal layered view (interface, peers, site subnets) rendered with ECharts
- Online/offline/disabled colors, dashed inactive links, hover details, click-through to peer pages, auto-refresh

### Monitoring
- Dashboard with per-interface cards and a live peer table (handshake, endpoint, RX/TX)
- Cumulative usage tracking that survives interface restarts; periodic traffic samples with configurable retention and automatic pruning
- Configurable sample interval, online threshold and UI refresh rate (Settings page, applied at runtime)

### Advanced networking and performance
- Per-interface MTU, MSS clamping, FwMark, routing table (`off` for manual routing), custom PostUp/PostDown lines
- Peer isolation per interface (blocks peer-to-peer forwarding)
- Host tuning from the Settings page: UDP buffer sizes (`rmem_max`/`wmem_max`), `netdev_max_backlog`, UDP GRO forwarding (ethtool) with current kernel values displayed
- NAT (masquerade) and firewall rules managed automatically per interface

## Quick start

```bash
git clone https://github.com/lofyer/wireguard-admin.git
cd wireguard-admin
cat > .env <<'EOF'
WG_HOST=vpn.example.com      # public IP or domain clients connect to
ADMIN_PASSWORD=change-me
SECRET_KEY=generate-a-long-random-string
EOF
docker compose up -d
```

Open `http://<server>:8000`, log in (`admin` / your password). The first interface is created automatically from the environment defaults; add or import more from the Interfaces page.

Or run the published image directly:

```bash
docker run -d --name wireguard-admin \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -e WG_HOST=vpn.example.com \
  -e ADMIN_PASSWORD=change-me \
  -e SECRET_KEY=generate-a-long-random-string \
  -v $(pwd)/volumes/admin-data:/opt/wireguard-admin/data \
  -v $(pwd)/volumes/config:/etc/wireguard \
  lofyer/wireguard-admin:latest
```

Host network mode is used so that newly created interfaces and their UDP ports work without editing port mappings. The panel listens on port 8000.

## Configuration

Environment variables (first-run defaults; interfaces are managed in the database afterwards):

| Variable | Default | Purpose |
|----------|---------|---------|
| `WG_HOST` | required | Public endpoint host for client configs |
| `WG_INTERFACE` | `wg1` | Name of the first interface |
| `WG_PORT` | `51821` | Listen port of the first interface |
| `WG_SUBNET` | `10.8.0.0/24` | Subnet of the first interface |
| `WG_DNS` | `8.8.8.8` | Default client DNS |
| `WG_ALLOWED_IPS` | `0.0.0.0/0, ::/0` | Default client AllowedIPs |
| `WG_PEER_ISOLATION` | `false` | Block peer-to-peer traffic |
| `WG_RELAY_SUBNETS` | empty | Comma-separated subnets to masquerade into (e.g. another host tunnel) |
| `ADMIN_USERNAME` | `admin` | Panel login |
| `ADMIN_PASSWORD` | required | Panel login |
| `SECRET_KEY` | required | Session signing and at-rest key encryption |

## Importing an existing WireGuard service

1. Make sure the interface's wg-quick config is visible at `/etc/wireguard/<name>.conf` (mount it into the container's config volume)
2. Open Interfaces, the unmanaged interface appears under "Import existing interface"
3. Enter the public endpoint host and click Import

The panel backs up the original config, adopts the server key and all peers, and starts managing the interface. Existing clients keep working unchanged. Rotate keys per peer only if you want the panel to generate fresh client configs for them.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
DATA_DIR=./data WG_HOST=localhost ADMIN_PASSWORD=dev SECRET_KEY=dev \
  .venv/bin/uvicorn app.main:app --reload
```

Rebuild the stylesheet after changing Tailwind classes in templates or JS (uses the standalone CLI, no Node project needed):

```bash
tailwindcss -c tailwind.config.js -i input.css -o app/static/tailwind.css --minify
```

See `docs/FEATURES.md` for the original feature specification.
