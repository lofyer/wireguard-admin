# WireGuard Admin Panel - Feature Specification

Stack: FastAPI + Jinja2 (server-rendered) + SQLite + minimal JS, deployed in Docker with NET_ADMIN.

## 1. Auto Configuration

- On first start, auto-generate the server keypair if none exists.
- Auto-create and bring up the WireGuard interface (`wg0`) from settings (subnet, port, DNS).
- Auto-assign the next free IP from the subnet when a peer is created.
- Apply peer changes live with `wg syncconf` (no tunnel drops).
- NAT/forwarding rules (iptables) set up automatically inside the container.
- All settings configurable via environment variables / `.env`.

## 2. Client Key Management

- Generate keypair (private/public) and preshared key per peer on creation.
- Regenerate (rotate) a peer's keys on demand; old key is revoked immediately.
- Peer private keys stored encrypted at rest in SQLite.
- Export client config as downloadable `.conf` file.
- Export client config as QR code (for mobile apps), rendered inline.
- Enable / disable a peer without deleting it.
- Delete (revoke) a peer, removed from the live interface immediately.
- Optional peer expiry date, expired peers are auto-disabled.

## 3. Monitoring

- Dashboard: interface state, listen port, public key, peer count, total RX/TX.
- Per-peer live status: last handshake, online/offline (handshake < 3 min), endpoint, RX/TX bytes.
- Auto-refreshing status via a JSON endpoint polled by the page (no full reload).
- Traffic history sampled periodically and stored, shown as simple usage charts.

## 4. Authentication

- Single admin account (username/password from env, bcrypt hashed).
- Session cookie login (signed, HTTP-only), logout, session expiry.
- All pages and API endpoints require login.

## 5. Web UI Pages

| Page | Purpose |
|------|---------|
| /login | Admin login |
| / | Dashboard (interface status, totals, recent peers) |
| /peers | Peer list with online status, add/enable/disable/delete |
| /peers/{id} | Peer detail: config download, QR code, key rotation, stats |
| /settings | Server settings view (interface, port, subnet, DNS) |

## 6. JSON API (used by UI, reusable for automation)

| Method | Path | Purpose |
|--------|------|---------|
| GET | /api/status | Interface + all peers live stats |
| POST | /api/peers | Create peer |
| POST | /api/peers/{id}/toggle | Enable/disable peer |
| POST | /api/peers/{id}/rotate | Rotate peer keys |
| DELETE | /api/peers/{id} | Delete peer |
| GET | /api/peers/{id}/config | Download .conf |
| GET | /api/peers/{id}/qr | QR code PNG |

## 7. Deployment

- Dockerfile (python slim + wireguard-tools + iptables).
- docker-compose.yml with `cap_add: NET_ADMIN`, sysctl ip_forward, UDP 51820, panel on 8000.
- Persistent volume for SQLite DB and generated configs.
