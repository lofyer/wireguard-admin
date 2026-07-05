import asyncio
import io
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import quote

import qrcode
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from . import service, wireguard
from .auth import SESSION_COOKIE, create_session_token, logged_in, verify_credentials
from .config import settings
from .db import Base, SessionLocal, engine, get_db, run_migrations

PRUNE_EVERY_TICKS = 60

templates = Jinja2Templates(directory="app/templates")


async def _background_sampler() -> None:
    tick = 0
    while True:
        db = SessionLocal()
        try:
            interval = service.get_runtime_settings(db)["traffic_sample_interval"]
        except Exception:
            interval = 60
        finally:
            db.close()
        await asyncio.sleep(interval)
        db = SessionLocal()
        try:
            service.accumulate_usage(db)
            service.disable_expired_peers(db)
            service.sample_traffic(db)
            tick += 1
            if tick % PRUNE_EVERY_TICKS == 0:
                service.prune_traffic_samples(db)
        except Exception:
            pass
        finally:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    run_migrations()
    db = SessionLocal()
    try:
        service.bootstrap_default_interface(db)
        wireguard.status_module.online_threshold_seconds = (
            service.get_runtime_settings(db)["online_threshold"]
        )
        service.prune_traffic_samples(db)
        service.apply_all_configs(db)
    finally:
        db.close()
    task = asyncio.create_task(_background_sampler())
    yield
    task.cancel()


app = FastAPI(title="WireGuard Admin", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def _fmt_bytes(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} PiB"


templates.env.filters["fmt_bytes"] = _fmt_bytes
templates.env.globals["server_address"] = wireguard.server_address


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if not verify_credentials(username, password):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password"}, status_code=401
        )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(),
        max_age=settings.session_max_age,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


def _interface_overview(db: Session) -> list[dict]:
    overview = []
    for iface in service.list_interfaces(db):
        status = wireguard.get_status(iface.name)
        peers = service.list_peers(db, iface)
        overview.append(
            {
                "iface": iface,
                "status": status,
                "peers": peers,
                "online": sum(
                    1
                    for p in peers
                    if (ps := status.peers.get(p.public_key)) is not None and ps.online
                ),
            }
        )
    return overview


@app.get("/", response_class=HTMLResponse, dependencies=[logged_in])
def dashboard(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request, "dashboard.html", {"overview": _interface_overview(db)}
    )


@app.get("/interfaces", response_class=HTMLResponse, dependencies=[logged_in])
def interfaces_page(request: Request, db: Session = Depends(get_db), error: str = ""):
    return templates.TemplateResponse(
        request,
        "interfaces.html",
        {
            "overview": _interface_overview(db),
            "candidates": service.import_candidates(db),
            "error": error,
            "settings": settings,
        },
    )


def _interfaces_error(exc: Exception) -> RedirectResponse:
    return RedirectResponse(f"/interfaces?error={quote(str(exc))}", status_code=303)


@app.post("/interfaces", dependencies=[logged_in])
def create_interface(
    db: Session = Depends(get_db),
    name: str = Form(...),
    subnet: str = Form(...),
    listen_port: int = Form(...),
    host: str = Form(...),
    dns: str = Form(""),
    allowed_ips: str = Form(""),
    persistent_keepalive: int = Form(25),
    peer_isolation: bool = Form(False),
):
    try:
        service.create_interface(
            db, name, subnet, listen_port, host, dns,
            allowed_ips, persistent_keepalive, peer_isolation,
        )
    except (ValueError, RuntimeError) as exc:
        return _interfaces_error(exc)
    return RedirectResponse("/interfaces", status_code=303)


def _get_interface_or_404(db: Session, interface_id: int):
    iface = service.get_interface(db, interface_id)
    if iface is None:
        raise HTTPException(status_code=404, detail="Interface not found")
    return iface


@app.post("/interfaces/import", dependencies=[logged_in])
def import_interface(
    db: Session = Depends(get_db), name: str = Form(...), host: str = Form(...)
):
    try:
        service.import_interface(db, name, host)
    except (ValueError, RuntimeError) as exc:
        return _interfaces_error(exc)
    return RedirectResponse("/interfaces", status_code=303)


@app.post("/interfaces/{interface_id}/update", dependencies=[logged_in])
def update_interface(
    interface_id: int,
    db: Session = Depends(get_db),
    host: str = Form(...),
    dns: str = Form(""),
    allowed_ips: str = Form(""),
    persistent_keepalive: int = Form(25),
    peer_isolation: bool = Form(False),
    mtu: int = Form(0),
    mss_clamp: bool = Form(False),
    fwmark: str = Form(""),
    route_table: str = Form(""),
    post_up: str = Form(""),
    post_down: str = Form(""),
):
    iface = _get_interface_or_404(db, interface_id)
    try:
        service.update_interface(
            db, iface, host, dns, allowed_ips, persistent_keepalive, peer_isolation,
            mtu, mss_clamp, fwmark, route_table, post_up, post_down,
        )
    except (ValueError, RuntimeError) as exc:
        return _interfaces_error(exc)
    return RedirectResponse("/interfaces", status_code=303)


@app.post("/interfaces/{interface_id}/toggle", dependencies=[logged_in])
def toggle_interface(interface_id: int, db: Session = Depends(get_db)):
    try:
        service.toggle_interface(db, _get_interface_or_404(db, interface_id))
    except (ValueError, RuntimeError) as exc:
        return _interfaces_error(exc)
    return RedirectResponse("/interfaces", status_code=303)


@app.post("/interfaces/{interface_id}/delete", dependencies=[logged_in])
def delete_interface(
    interface_id: int, db: Session = Depends(get_db), cascade: bool = Form(False)
):
    iface = _get_interface_or_404(db, interface_id)
    try:
        service.delete_interface(db, iface, cascade)
    except (ValueError, RuntimeError) as exc:
        return _interfaces_error(exc)
    return RedirectResponse("/interfaces", status_code=303)


@app.get("/peers", response_class=HTMLResponse, dependencies=[logged_in])
def peers_page(
    request: Request,
    db: Session = Depends(get_db),
    interface: int = 0,
    error: str = "",
):
    interfaces = service.list_interfaces(db)
    current = None
    if interface:
        current = next((i for i in interfaces if i.id == interface), None)
    if current is None and interfaces:
        current = interfaces[0]
    peers = service.list_peers(db, current) if current else []
    status = wireguard.get_status(current.name) if current else wireguard.InterfaceStatus(name="")
    return templates.TemplateResponse(
        request,
        "peers.html",
        {
            "peers": peers,
            "status": status,
            "error": error,
            "interfaces": interfaces,
            "current": current,
        },
    )


def _parse_quota_gib(value: str) -> int:
    quota = float(value) if value.strip() else 0
    return int(quota * 1024**3)


@app.post("/peers", dependencies=[logged_in])
def create_peer(
    db: Session = Depends(get_db),
    interface_id: int = Form(...),
    name: str = Form(...),
    expires_at: str = Form(""),
    note: str = Form(""),
    quota_gib: str = Form(""),
    count: int = Form(1),
    address: str = Form(""),
    dns: str = Form(""),
    extra_allowed_ips: str = Form(""),
    client_allowed_ips: str = Form(""),
):
    iface = _get_interface_or_404(db, interface_id)
    expiry = datetime.fromisoformat(expires_at) if expires_at else None
    quota = _parse_quota_gib(quota_gib)
    try:
        if count > 1:
            service.create_peers_batch(
                db, iface, name.strip(), min(count, 50), expiry, note.strip(), quota
            )
            return RedirectResponse(f"/peers?interface={iface.id}", status_code=303)
        peer = service.create_peer(
            db,
            iface,
            name.strip(),
            expiry,
            note.strip(),
            quota,
            address.strip(),
            dns.strip(),
            extra_allowed_ips.strip(),
            client_allowed_ips.strip(),
        )
    except ValueError as exc:
        return RedirectResponse(
            f"/peers?interface={iface.id}&error={quote(str(exc))}", status_code=303
        )
    return RedirectResponse(f"/peers/{peer.id}", status_code=303)


def _get_peer_or_404(db: Session, peer_id: int):
    peer = service.get_peer(db, peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    return peer


@app.get("/peers/{peer_id}", response_class=HTMLResponse, dependencies=[logged_in])
def peer_detail(
    request: Request, peer_id: int, db: Session = Depends(get_db), error: str = ""
):
    peer = _get_peer_or_404(db, peer_id)
    iface = peer.interface
    status = wireguard.get_status(iface.name)
    client_config = (
        wireguard.render_client_config(peer, iface) if peer.has_private_key else None
    )
    return templates.TemplateResponse(
        request,
        "peer_detail.html",
        {
            "peer": peer,
            "iface": iface,
            "peer_status": status.peers.get(peer.public_key),
            "client_config": client_config,
            "error": error,
            "server_tunnel_ip": wireguard.server_address(iface.subnet).split("/")[0],
        },
    )


@app.post("/peers/{peer_id}/update", dependencies=[logged_in])
def update_peer(
    peer_id: int,
    db: Session = Depends(get_db),
    note: str = Form(""),
    quota_gib: str = Form(""),
    dns: str = Form(""),
    extra_allowed_ips: str = Form(""),
    client_allowed_ips: str = Form(""),
    persistent_keepalive: str = Form(""),
):
    peer = _get_peer_or_404(db, peer_id)
    try:
        keepalive = int(persistent_keepalive) if persistent_keepalive.strip() else None
        service.update_peer(
            db,
            peer,
            note.strip(),
            _parse_quota_gib(quota_gib),
            dns.strip(),
            extra_allowed_ips.strip(),
            client_allowed_ips.strip(),
            keepalive,
        )
    except ValueError as exc:
        return RedirectResponse(
            f"/peers/{peer_id}?error={quote(str(exc))}", status_code=303
        )
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/reset-usage", dependencies=[logged_in])
def reset_usage(peer_id: int, db: Session = Depends(get_db)):
    service.reset_peer_usage(db, _get_peer_or_404(db, peer_id))
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/toggle", dependencies=[logged_in])
def toggle_peer(peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    service.toggle_peer(db, peer)
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/rotate", dependencies=[logged_in])
def rotate_peer(peer_id: int, db: Session = Depends(get_db)):
    service.rotate_peer_keys(db, _get_peer_or_404(db, peer_id))
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/delete", dependencies=[logged_in])
def delete_peer(peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    interface_id = peer.interface_id
    service.delete_peer(db, peer)
    return RedirectResponse(f"/peers?interface={interface_id}", status_code=303)


@app.get("/peers/{peer_id}/config", dependencies=[logged_in])
def peer_config(peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    if not peer.has_private_key:
        raise HTTPException(
            status_code=409,
            detail="Imported peer has no private key. Rotate keys first.",
        )
    config = wireguard.render_client_config(peer, peer.interface)
    return Response(
        config,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{peer.name}.conf"'},
    )


@app.get("/peers/{peer_id}/qr", dependencies=[logged_in])
def peer_qr(peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    if not peer.has_private_key:
        raise HTTPException(
            status_code=409,
            detail="Imported peer has no private key. Rotate keys first.",
        )
    config = wireguard.render_client_config(peer, peer.interface)
    image = qrcode.make(config)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="image/png")


@app.get("/topology", response_class=HTMLResponse, dependencies=[logged_in])
def topology_page(request: Request):
    return templates.TemplateResponse(request, "topology.html", {})


@app.get("/settings", response_class=HTMLResponse, dependencies=[logged_in])
def settings_page(
    request: Request, db: Session = Depends(get_db), error: str = "", message: str = ""
):
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "settings": settings,
            "interfaces": service.list_interfaces(db),
            "runtime": service.get_runtime_settings(db),
            "tuning": wireguard.tuning.read_host_tuning(),
            "error": error,
            "message": message,
        },
    )


@app.post("/settings/runtime", dependencies=[logged_in])
def update_runtime(
    db: Session = Depends(get_db),
    traffic_sample_interval: int = Form(...),
    traffic_retention_days: int = Form(...),
    online_threshold: int = Form(...),
    ui_refresh_seconds: int = Form(...),
):
    try:
        service.update_runtime_settings(
            db,
            {
                "traffic_sample_interval": traffic_sample_interval,
                "traffic_retention_days": traffic_retention_days,
                "online_threshold": online_threshold,
                "ui_refresh_seconds": ui_refresh_seconds,
            },
        )
    except ValueError as exc:
        return RedirectResponse(f"/settings?error={quote(str(exc))}", status_code=303)
    return RedirectResponse("/settings?message=Saved", status_code=303)


@app.post("/settings/tuning", dependencies=[logged_in])
def apply_host_tuning(
    udp_buffer_mib: int = Form(0),
    netdev_backlog: int = Form(0),
    gro_forwarding: str = Form(""),
):
    errors: list[str] = []
    if udp_buffer_mib:
        if not 1 <= udp_buffer_mib <= 64:
            errors.append("UDP buffer must be 1-64 MiB")
        else:
            errors += wireguard.tuning.apply_udp_buffers(udp_buffer_mib * 1024 * 1024)
    if netdev_backlog:
        if not 1000 <= netdev_backlog <= 100000:
            errors.append("Backlog must be 1000-100000")
        else:
            errors += wireguard.tuning.apply_backlog(netdev_backlog)
    if gro_forwarding in ("on", "off"):
        errors += wireguard.tuning.apply_gro_forwarding(gro_forwarding == "on")
    if errors:
        return RedirectResponse(
            f"/settings?error={quote('; '.join(errors))}", status_code=303
        )
    return RedirectResponse("/settings?message=Applied", status_code=303)


@app.get("/api/status", dependencies=[logged_in])
def api_status(db: Session = Depends(get_db)):
    runtime = service.get_runtime_settings(db)
    interfaces = []
    for iface in service.list_interfaces(db):
        status = wireguard.get_status(iface.name)
        peers = service.list_peers(db, iface)
        interfaces.append(
            {
                "id": iface.id,
                "name": iface.name,
                "up": status.up,
                "enabled": iface.enabled,
                "imported": iface.imported,
                "listen_port": status.listen_port or iface.listen_port,
                "address": wireguard.server_address(iface.subnet),
                "subnet": iface.subnet,
                "host": iface.host,
                "peer_isolation": iface.peer_isolation,
                "total_rx": status.total_rx,
                "total_tx": status.total_tx,
                "peers": [
                    {
                        "id": peer.id,
                        "name": peer.name,
                        "address": peer.address,
                        "enabled": peer.enabled,
                        "note": peer.note,
                        "has_private_key": peer.has_private_key,
                        "extra_allowed_ips": peer.extra_allowed_ips,
                        "client_allowed_ips": peer.client_allowed_ips,
                        "quota_bytes": peer.quota_bytes,
                        "cum_rx": peer.cum_rx,
                        "cum_tx": peer.cum_tx,
                        "over_quota": peer.over_quota,
                        "online": (ps := status.peers.get(peer.public_key)) is not None
                        and ps.online,
                        "endpoint": ps.endpoint if ps else None,
                        "latest_handshake": ps.latest_handshake.isoformat()
                        if ps and ps.latest_handshake
                        else None,
                        "rx_bytes": ps.rx_bytes if ps else 0,
                        "tx_bytes": ps.tx_bytes if ps else 0,
                    }
                    for peer in peers
                ],
            }
        )
    return {
        "interfaces": interfaces,
        "meta": {"refresh_seconds": runtime["ui_refresh_seconds"]},
    }
