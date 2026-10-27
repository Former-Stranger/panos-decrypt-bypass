"""Web GUI: shows TLS decryption failures and turns them into bypasses.

Started by `panos-decrypt-bypass serve` (the container's default command).
"""

import asyncio
import contextlib
import logging
import time
import urllib.parse
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from panos_decrypt_bypass import __version__, bypass_lists
from panos_decrypt_bypass.web.advice import bypass_status, explain
from panos_decrypt_bypass.web.auth import COOKIE, Auth
from panos_decrypt_bypass.web.deployer import Busy, DemoDeployer, Deployer
from panos_decrypt_bypass.web.lookup import DemoLookup, Lookup
from panos_decrypt_bypass.web.poller import Poller
from panos_decrypt_bypass.web.settings import Settings
from panos_decrypt_bypass.web.store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).resolve().parent / "static"
PUBLIC_PATHS = {"/login", "/api/login", "/healthz", "/static/login.js", "/static/style.css"}

settings = Settings.from_env()
settings.workspace.ensure()
store = Store(settings.db_path, settings.timezone)
poller = Poller(settings, store)
deployer = (DemoDeployer if settings.demo else Deployer)(settings.workspace)
lookup = DemoLookup() if settings.demo else Lookup()
auth = Auth(settings.auth == "password", settings.password, settings.workspace.session_key, settings.session_hours, settings.cookie_secure)


def same_origin(request: Request) -> None:
    """Block cross-site requests: forms can't set custom headers, and a
    cross-origin fetch() with one needs CORS, which isn't enabled. Together
    with SameSite=Strict cookies this stops other sites from acting for you."""
    if request.headers.get("x-decrypt-viewer") != "1":
        raise HTTPException(403, "Missing X-Decrypt-Viewer header.")
    origin = request.headers.get("origin")
    if origin and urllib.parse.urlsplit(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "Cross-origin request refused.")


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    errors = settings.startup_errors()
    if errors:
        raise RuntimeError(" ".join(errors))
    task = asyncio.create_task(poller.run())
    yield
    task.cancel()


app = FastAPI(title="panos-decrypt-bypass", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def require_login(request: Request, call_next):
    if request.url.path not in PUBLIC_PATHS and not auth.valid(request.cookies.get(COOKIE)):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Not logged in."}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    )
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if not auth.enabled or auth.valid(request.cookies.get(COOKIE)):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC / "login.html")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True}


class LoginRequest(BaseModel):
    password: str = Field(max_length=1024)


@app.post("/api/login", dependencies=[Depends(same_origin)])
async def login(req: LoginRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if auth.locked_out(client):
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    if not await asyncio.to_thread(auth.check_password, req.password):
        auth.record_failure(client)
        await asyncio.sleep(1)
        raise HTTPException(401, "Wrong password.")
    auth.clear_failures(client)
    response = JSONResponse({"ok": True})
    secure = auth.secure_cookie(request.headers.get("x-forwarded-proto", request.url.scheme))
    response.set_cookie(COOKIE, auth.issue(), max_age=auth.max_age, httponly=True, samesite="strict", secure=secure)
    return response


@app.post("/api/logout", dependencies=[Depends(same_origin)])
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE)
    return response


@app.get("/api/status")
def status() -> dict:
    return {
        **poller.status,
        "firewall": "demo data" if settings.demo else settings.firewall_host,
        "poll_seconds": settings.poll_seconds,
        "events_stored": store.count(),
        "problems": settings.problems(),
        "timezone": str(settings.timezone),
        "version": __version__,
        "auth": auth.enabled,
        "configured": settings.workspace.configured() or settings.demo,
        "lookup": settings.domain_lookup,
        "management": {
            "mode": settings.workspace.mode.name,
            "target": settings.workspace.mode.target,
            "publish": settings.workspace.mode.publish,
        },
    }


@app.get("/api/issues")
def issues(
    hours: float = Query(24, gt=0, le=24 * 31),
    failures_only: bool = True,
    hide_bypassed: bool = False,
    q: str = "",
) -> list[dict]:
    rows = store.issues(time.time() - hours * 3600, failures_only, q.strip())
    out = []
    for r in rows:
        host = r["sni"] or r["cn"] or ""
        covered = {(h["kind"], h["entry"]): h for ip in (r["client_ips"] or [""]) for h in bypass_status(settings.bypass_dir, host, ip, r["dst"])}
        r["bypassed_by"] = list(covered.values())
        r["advice"] = explain(r["error"], r["err_index"], r["chain_status"], r["root_status"])
        if not (hide_bypassed and r["bypassed_by"]):
            out.append(r)
    return out


@app.get("/api/events")
def events(target: str, hours: float = Query(24, gt=0, le=24 * 31)) -> list[dict]:
    return store.events(target.lower(), time.time() - hours * 3600)


@app.post("/api/poll", dependencies=[Depends(same_origin)])
def poll_now() -> dict:
    poller.wake.set()
    return {"ok": True}


class LookupRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


@app.post("/api/lookup", dependencies=[Depends(same_origin)])
def lookup_target(req: LookupRequest) -> dict:
    """Registration, DNS and certificate facts about a destination, on demand."""
    if not settings.domain_lookup:
        raise HTTPException(403, "Lookups are turned off (DOMAIN_LOOKUP=false).")
    try:
        return lookup.lookup(req.target)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


class BypassRequest(BaseModel):
    entries: list[str] = Field(min_length=1, max_length=50)
    subdomains: bool = False
    description: str = Field("", max_length=200)


@app.post("/api/bypass", dependencies=[Depends(same_origin)])
def add_bypass(req: BypassRequest) -> dict:
    """Add hostnames to the no-decrypt URL list and deploy them."""
    entries, errors = [], []
    for raw in req.entries:
        try:
            entries.append(bypass_lists.clean("url", raw)[0])
        except ValueError as e:
            errors.append(str(e))
    if errors:
        raise HTTPException(400, " ".join(errors))
    if req.subdomains:
        entries = bypass_lists.with_subdomains(entries)
    description = " ".join(req.description.split()) or None

    try:
        with deployer.lock:  # don't edit the list under a running deploy
            if deployer.job and (deployer.job.active or deployer.job.state == "review"):
                raise Busy(f"Deploy #{deployer.job.id} is {deployer.job.state}. Finish or cancel it first.")
            added = [e for e in entries if bypass_lists.add(settings.bypass_dir, "url", e, description)]
    except Busy as e:
        raise HTTPException(409, str(e)) from e
    if not added:
        return {"added": [], "already": entries, "job": None}
    try:
        job = deployer.start("bypass", added, description or "")
    except Busy as e:  # another deploy started in between: take ours back out
        for entry in added:
            bypass_lists.remove(settings.bypass_dir, "url", entry)
        raise HTTPException(409, str(e)) from e
    return {"added": added, "already": [e for e in entries if e not in added], "job": job.public()}


@app.get("/api/deploy")
def deploy_status() -> dict:
    return {"job": deployer.current()}


@app.post("/api/deploy", dependencies=[Depends(same_origin)])
def deploy_start() -> dict:
    """Plan whatever is pending (list edits, tfvars changes) and wait for review."""
    try:
        return {"job": deployer.start("manual").public()}
    except Busy as e:
        raise HTTPException(409, str(e)) from e


@app.post("/api/deploy/{job_id}/{action}", dependencies=[Depends(same_origin)])
def deploy_action(job_id: int, action: str) -> dict:
    handlers = {"confirm": deployer.confirm, "cancel": deployer.cancel, "retry-push": deployer.retry_push}
    if action not in handlers:
        raise HTTPException(404, f"Unknown action {action}.")
    try:
        return {"job": handlers[action](job_id).public()}
    except Busy as e:
        raise HTTPException(409, str(e)) from e
