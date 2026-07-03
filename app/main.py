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

TRAFFIC_SAMPLE_INTERVAL = 60

templates = Jinja2Templates(directory="app/templates")


async def _background_sampler() -> None:
    while True:
        await asyncio.sleep(TRAFFIC_SAMPLE_INTERVAL)
        db = SessionLocal()
        try:
            service.accumulate_usage(db)
            service.disable_expired_peers(db)
            service.sample_traffic(db)
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
        service.apply_config(db)
        try:
            wireguard.interface_up()
        except Exception:
            pass
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


@app.get("/", response_class=HTMLResponse, dependencies=[logged_in])
def dashboard(request: Request, db: Session = Depends(get_db)):
    status = wireguard.get_status()
    peers = service.list_peers(db)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"status": status, "peers": peers, "settings": settings},
    )


@app.get("/peers", response_class=HTMLResponse, dependencies=[logged_in])
def peers_page(request: Request, db: Session = Depends(get_db), error: str = ""):
    status = wireguard.get_status()
    peers = service.list_peers(db)
    return templates.TemplateResponse(
        request,
        "peers.html",
        {"peers": peers, "status": status, "error": error, "settings": settings},
    )


def _parse_quota_gib(value: str) -> int:
    quota = float(value) if value.strip() else 0
    return int(quota * 1024**3)


@app.post("/peers", dependencies=[logged_in])
def create_peer(
    db: Session = Depends(get_db),
    name: str = Form(...),
    expires_at: str = Form(""),
    note: str = Form(""),
    quota_gib: str = Form(""),
    count: int = Form(1),
    address: str = Form(""),
    dns: str = Form(""),
):
    expiry = datetime.fromisoformat(expires_at) if expires_at else None
    quota = _parse_quota_gib(quota_gib)
    try:
        if count > 1:
            service.create_peers_batch(
                db, name.strip(), min(count, 50), expiry, note.strip(), quota
            )
            return RedirectResponse("/peers", status_code=303)
        peer = service.create_peer(
            db, name.strip(), expiry, note.strip(), quota, address.strip(), dns.strip()
        )
    except ValueError as exc:
        return RedirectResponse(f"/peers?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(f"/peers/{peer.id}", status_code=303)


def _get_peer_or_404(db: Session, peer_id: int):
    peer = service.get_peer(db, peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    return peer


@app.get("/peers/{peer_id}", response_class=HTMLResponse, dependencies=[logged_in])
def peer_detail(request: Request, peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    status = wireguard.get_status()
    _, server_public = wireguard.ensure_server_keys()
    client_config = wireguard.render_client_config(peer, server_public)
    return templates.TemplateResponse(
        request,
        "peer_detail.html",
        {
            "peer": peer,
            "peer_status": status.peers.get(peer.public_key),
            "client_config": client_config,
        },
    )


@app.post("/peers/{peer_id}/update", dependencies=[logged_in])
def update_peer(
    peer_id: int,
    db: Session = Depends(get_db),
    note: str = Form(""),
    quota_gib: str = Form(""),
    dns: str = Form(""),
):
    peer = _get_peer_or_404(db, peer_id)
    service.update_peer(db, peer, note.strip(), _parse_quota_gib(quota_gib), dns.strip())
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/reset-usage", dependencies=[logged_in])
def reset_usage(peer_id: int, db: Session = Depends(get_db)):
    service.reset_peer_usage(db, _get_peer_or_404(db, peer_id))
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/toggle", dependencies=[logged_in])
def toggle_peer(peer_id: int, db: Session = Depends(get_db)):
    service.toggle_peer(db, _get_peer_or_404(db, peer_id))
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/rotate", dependencies=[logged_in])
def rotate_peer(peer_id: int, db: Session = Depends(get_db)):
    service.rotate_peer_keys(db, _get_peer_or_404(db, peer_id))
    return RedirectResponse(f"/peers/{peer_id}", status_code=303)


@app.post("/peers/{peer_id}/delete", dependencies=[logged_in])
def delete_peer(peer_id: int, db: Session = Depends(get_db)):
    service.delete_peer(db, _get_peer_or_404(db, peer_id))
    return RedirectResponse("/peers", status_code=303)


@app.get("/peers/{peer_id}/config", dependencies=[logged_in])
def peer_config(peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    _, server_public = wireguard.ensure_server_keys()
    config = wireguard.render_client_config(peer, server_public)
    return Response(
        config,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{peer.name}.conf"'},
    )


@app.get("/peers/{peer_id}/qr", dependencies=[logged_in])
def peer_qr(peer_id: int, db: Session = Depends(get_db)):
    peer = _get_peer_or_404(db, peer_id)
    _, server_public = wireguard.ensure_server_keys()
    config = wireguard.render_client_config(peer, server_public)
    image = qrcode.make(config)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="image/png")


@app.get("/settings", response_class=HTMLResponse, dependencies=[logged_in])
def settings_page(request: Request):
    _, server_public = wireguard.ensure_server_keys()
    return templates.TemplateResponse(
        request, "settings.html", {"settings": settings, "server_public": server_public}
    )


@app.get("/api/status", dependencies=[logged_in])
def api_status(db: Session = Depends(get_db)):
    status = wireguard.get_status()
    peers = service.list_peers(db)
    return {
        "interface": {
            "name": status.name,
            "up": status.up,
            "listen_port": status.listen_port,
            "total_rx": status.total_rx,
            "total_tx": status.total_tx,
        },
        "peers": [
            {
                "id": peer.id,
                "name": peer.name,
                "address": peer.address,
                "enabled": peer.enabled,
                "note": peer.note,
                "quota_bytes": peer.quota_bytes,
                "cum_rx": peer.cum_rx,
                "cum_tx": peer.cum_tx,
                "over_quota": peer.over_quota,
                "online": (ps := status.peers.get(peer.public_key)) is not None and ps.online,
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
