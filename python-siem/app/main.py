"""
HyShield SIEM - web app (pages + JSON API) in one FastAPI file.

Run it:   python run.py
Open:     http://127.0.0.1:8000        (API docs: http://127.0.0.1:8000/docs)
"""
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth, charts, config, db, queries, settings as cfg
from .ingest import Ingestor

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=APP_DIR / "templates")   # auto-escapes all {{ values }}

# Lightweight per-process login throttling. Deployments with multiple workers should
# additionally enforce a shared/proxy-level rate limit.
_LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_MAX_FAILURES = 8
_login_failures = defaultdict(deque)
_login_lock = threading.Lock()


def _login_limited(client_ip):
    now = time.monotonic()
    with _login_lock:
        failures = _login_failures[client_ip]
        while failures and now - failures[0] >= _LOGIN_WINDOW_SECONDS:
            failures.popleft()
        return len(failures) >= _LOGIN_MAX_FAILURES


def _record_login_failure(client_ip):
    now = time.monotonic()
    with _login_lock:
        failures = _login_failures[client_ip]
        while failures and now - failures[0] >= _LOGIN_WINDOW_SECONDS:
            failures.popleft()
        failures.append(now)
        if len(_login_failures) > 4096:
            for ip in list(_login_failures)[:1024]:
                if not _login_failures[ip] or now - _login_failures[ip][-1] >= _LOGIN_WINDOW_SECONDS:
                    _login_failures.pop(ip, None)


def _clear_login_failures(client_ip):
    with _login_lock:
        _login_failures.pop(client_ip, None)


def _cookie_secure(request):
    # Explicit deployment configuration is required when TLS terminates at a proxy.
    return config.COOKIE_SECURE or request.url.scheme == "https"



# ----------------------------------------------------------- template helpers
def _parse(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_dt(ts):
    d = _parse(ts)
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else "-"


def fmt_time(ts):
    d = _parse(ts)
    return d.strftime("%H:%M:%S") if d else "-"


def minutes_between(a, b):
    da, db_ = _parse(a), _parse(b)
    return max(1, int((db_ - da).total_seconds() // 60)) if da and db_ else 1


templates.env.filters.update(dt=fmt_dt, tm=fmt_time)
templates.env.globals.update(minutes_between=minutes_between, RISK_COLORS=charts.RISK_COLORS)


def render(request, template, page, refresh=0, **context):
    context.update(page=page, refresh=refresh,
                   current_user=getattr(request.state, "user", None),
                   role_labels=auth.ROLE_LABELS)
    return templates.TemplateResponse(request, template, context)


# ------------------------------------------------------------------ app setup
@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    db.init()
    configured_log_path = Path(cfg.load().get("cowrieLogPath", str(config.LOG_PATH))).expanduser()
    app.state.ingestor = Ingestor(configured_log_path, config.POLL_SECONDS)
    app.state.ingestor.start()
    logging.getLogger("hyshield").info("Tailing %s", configured_log_path)
    yield
    app.state.ingestor.stop()


app = FastAPI(title="HyShield SIEM", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


@app.middleware("http")
async def safety(request: Request, call_next):
    # Block other websites from submitting our forms.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed_origin = urlparse(origin)
                request_host = urlparse("//" + request.headers.get("host", ""))
                origin_hostname = (parsed_origin.hostname or "").lower()
                request_hostname = (request_host.hostname or "").lower()
                origin_port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
                request_port = request_host.port or (443 if parsed_origin.scheme == "https" else 80)
                # Browsers may reach the same local server through either localhost
                # or 127.0.0.1. Treat these as equivalent only for loopback aliases
                # on the same port; keep strict host+port validation for other hosts.
                loopback_names = {"localhost", "127.0.0.1", "::1"}
                same_host = origin_hostname == request_hostname
                same_loopback = (origin_hostname in loopback_names
                                 and request_hostname in loopback_names)
                if (parsed_origin.scheme not in ("http", "https")
                        or not parsed_origin.netloc
                        or not request_host.hostname
                        or origin_port != request_port
                        or not (same_host or same_loopback)):
                    return PlainTextResponse("Cross-origin request blocked", status_code=403)
            except (TypeError, ValueError):
                return PlainTextResponse("Invalid request origin", status_code=403)
        elif request.headers.get("sec-fetch-site", "").lower() in ("cross-site", "same-site"):
            return PlainTextResponse("Cross-origin request blocked", status_code=403)

    path = request.url.path
    exempt = path.startswith("/static/") or path in ("/login", "/setup", "/logout", "/api/health")
    request.state.user = None
    if not exempt:
        if auth.user_count() == 0:
            return RedirectResponse("/setup", status_code=303)
        user = auth.read_session(request.cookies.get(auth.COOKIE_NAME, ""))
        if not user:
            if path.startswith("/api/") or path in ("/docs", "/openapi.json", "/redoc"):
                return JSONResponse({"error": "Authentication required."}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        request.state.user = user
        if not auth.can_access(user["role"], request.method, path):
            if path.startswith("/api/"):
                return JSONResponse({"error": "Your role does not permit this action."}, status_code=403)
            return PlainTextResponse("Forbidden: your role does not permit this action.", status_code=403)

    response = await call_next(request)
    # No scripts allowed at all: log data comes from attackers, so even if something
    # slipped through the escaping, the browser would refuse to run it.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _safe_next(value, default):
    """Only allow redirects to pages on this site."""
    return value if value and value.startswith("/") and not value.startswith("//") else default


# -------------------------------------------------------------- authentication
@app.get("/login")
def login_page(request: Request, error: str = ""):
    if auth.user_count() == 0:
        return RedirectResponse("/setup", status_code=303)
    if auth.read_session(request.cookies.get(auth.COOKIE_NAME, "")):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", "login", error=error)


@app.post("/login")
async def login_submit(request: Request):
    if auth.user_count() == 0:
        return RedirectResponse("/setup", status_code=303)
    client_ip = request.client.host if request.client else "unknown"
    if _login_limited(client_ip):
        return PlainTextResponse("Too many failed sign-in attempts. Wait 15 minutes before trying again.", status_code=429)
    form = await request.form()
    user = auth.authenticate(form.get("username", ""), form.get("password", ""))
    if not user:
        _record_login_failure(client_ip)
        if _login_limited(client_ip):
            return PlainTextResponse("Too many failed sign-in attempts. Wait 15 minutes before trying again.", status_code=429)
        return render(request, "login.html", "login", error="Invalid username or password.")
    _clear_login_failures(client_ip)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(auth.COOKIE_NAME, auth.make_session(user), httponly=True,
                        secure=_cookie_secure(request), samesite="strict",
                        max_age=auth.SESSION_SECONDS, path="/")
    return response


@app.get("/setup")
def setup_page(request: Request, error: str = ""):
    if auth.user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    return render(request, "setup.html", "setup", error=error)


@app.post("/setup")
async def setup_submit(request: Request):
    if auth.user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    username, password, confirm = form.get("username", ""), form.get("password", ""), form.get("confirm", "")
    if password != confirm:
        return render(request, "setup.html", "setup", error="Passwords do not match.")
    try:
        user = auth.create_initial_admin(username, password)
    except ValueError as exc:
        return render(request, "setup.html", "setup", error=str(exc))
    except Exception:
        return render(request, "setup.html", "setup", error="Could not create the initial account. The username may already exist.")
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(auth.COOKIE_NAME, auth.make_session(user), httponly=True,
                        secure=_cookie_secure(request), samesite="strict",
                        max_age=auth.SESSION_SECONDS, path="/")
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.COOKIE_NAME, path="/", httponly=True, samesite="strict")
    return response


@app.get("/users")
def users_page(request: Request, error: str = "", saved: int = 0):
    return render(request, "users.html", "users", users=auth.list_users(), error=error, saved=saved)


@app.post("/users")
async def create_user_page(request: Request):
    form = await request.form()
    try:
        auth.create_user(form.get("username", ""), form.get("password", ""), form.get("role", ""), request.state.user)
    except ValueError as exc:
        from urllib.parse import quote
        return RedirectResponse("/users?error=" + quote(str(exc)), status_code=303)
    except Exception:
        return RedirectResponse("/users?error=Could%20not%20create%20user.%20Username%20may%20already%20exist.", status_code=303)
    return RedirectResponse("/users?saved=1", status_code=303)


@app.post("/users/{user_id}/update")
async def update_user_page(user_id: int, request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    role = str(form.get("role", ""))
    password = str(form.get("password", ""))
    actor = request.state.user or {}
    try:
        changed = auth.update_user(user_id, username, role, password, actor)
    except ValueError as exc:
        from urllib.parse import quote
        return RedirectResponse("/users?error=" + quote(str(exc)), status_code=303)
    except Exception:
        return RedirectResponse("/users?error=Could%20not%20update%20account.%20Username%20may%20already%20exist.", status_code=303)

    if not changed:
        return RedirectResponse("/users?error=User%20not%20found.", status_code=303)

    # Verify the persisted values rather than reporting success merely because
    # the UPDATE statement returned without raising an exception.
    persisted = next((u for u in auth.list_users() if int(u["id"]) == int(user_id)), None)
    if not persisted or persisted["username"] != username or persisted["role"] != role:
        return RedirectResponse("/users?error=Account%20update%20could%20not%20be%20verified.", status_code=303)

    # If the administrator edited their own username or role, the old session
    # no longer matches the database. Issue a fresh session for the updated
    # account and send them to the dashboard, where the new role permissions apply.
    if int(actor.get("id", -1)) == int(user_id):
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(auth.COOKIE_NAME, auth.make_session(persisted), httponly=True,
                            secure=_cookie_secure(request), samesite="strict",
                            max_age=auth.SESSION_SECONDS, path="/")
        return response

    return RedirectResponse("/users?saved=1", status_code=303)


@app.post("/users/{user_id}/disable")
def disable_user(user_id: int, request: Request):
    try:
        changed = auth.set_user_active(user_id, False, request.state.user)
    except ValueError as exc:
        from urllib.parse import quote
        return RedirectResponse("/users?error=" + quote(str(exc)), status_code=303)
    return RedirectResponse("/users?saved=1" if changed else "/users?error=User%20not%20found.", status_code=303)


@app.post("/users/{user_id}/enable")
def enable_user(user_id: int, request: Request):
    changed = auth.set_user_active(user_id, True, request.state.user)
    return RedirectResponse("/users?saved=1" if changed else "/users?error=User%20not%20found.", status_code=303)


@app.get("/audit-logs")
def audit_logs_page(request: Request):
    return render(request, "audit_logs.html", "audit-logs", logs=auth.list_audit_logs(200))


@app.get("/api/audit-logs")
def api_audit_logs(limit: int = 200):
    return auth.list_audit_logs(max(1, min(limit, 1000)))


@app.get("/api/users")
def api_users():
    return auth.list_users()


@app.post("/api/users")
async def api_create_user(request: Request):
    try:
        body = await request.json()
        user = auth.create_user(body.get("username"), body.get("password"), body.get("role"), request.state.user)
        return JSONResponse(user, status_code=201)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception:
        return JSONResponse({"error": "Could not create user. Username may already exist."}, status_code=409)


# ===================================================================== PAGES
@app.get("/")
def overview_page(request: Request):
    data = queries.overview()
    geo_data = queries.geo_overview()
    land = charts.land_path(APP_DIR / "static" / "countries-110m.json")
    return render(request, "overview.html", "overview", refresh=5, d=data,
                  timeline_svg=charts.area_chart(data["timeline"]),
                  donut_svg=charts.donut(data["categories"]),
                  map_svg=charts.world_map(land, geo_data["attackNodes"], geo_data["honeypot"]),
                  geo=geo_data,
                  sparklines={
                      "events": charts.sparkline(data["timeline"], "#fb7185"),
                      "sessions": charts.sparkline(data["timeline"], "#f59e0b"),
                      "actors": charts.sparkline(data["timeline"], "#a78bfa"),
                      "alerts": charts.sparkline(data["timeline"], "#60a5fa"),
                  })


@app.get("/reports/export.html")
def export_html_report(request: Request):
    """Download a standalone HTML snapshot of current SIEM findings."""
    generated = datetime.now(timezone.utc)
    data = queries.overview()
    report_context = {
        "generated_at": generated.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "metrics": data["metrics"],
        "alerts": queries.alerts(limit=100),
        "actors": queries.actors()[:20],
        "sessions": queries.sessions("LATEST", 50),
        "events": queries.events(limit=100),
    }
    filename = "hyshield-security-report-" + generated.strftime("%Y%m%d-%H%M%S") + ".html"
    return templates.TemplateResponse(
        request,
        "report_export.html",
        report_context,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/live")
def live_page(request: Request):
    return render(request, "live.html", "live", refresh=5, events=queries.events(100))


@app.get("/geomap")
def geomap_page(request: Request):
    data = queries.geo_overview()
    land = charts.land_path(APP_DIR / "static" / "countries-110m.json")
    return render(request, "geomap.html", "geomap", refresh=5, d=data,
                  map_svg=charts.world_map(land, data["attackNodes"], data["honeypot"]))


@app.get("/mitre")
def mitre_page(request: Request):
    return render(request, "mitre.html", "mitre", tactics=queries.mitre_matrix())


@app.get("/alerts")
def alerts_page(request: Request, severity: str = "ALL"):
    severity = severity.upper() if severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "ALL"
    return render(request, "alerts.html", "alerts", refresh=5, severity=severity,
                  alerts=queries.alerts(severity))


@app.post("/alerts/{alert_id}/close")
async def close_alert(alert_id: str, request: Request):
    """Close an alert and support both classic forms and background UI requests."""
    try:
        form = await request.form()
        changed = queries.close_alert(alert_id)
    except Exception:
        logging.getLogger("hyshield").exception("Unable to close alert %s", alert_id)
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"ok": False, "error": "The alert could not be closed. Check the application log."}, status_code=500)
        return PlainTextResponse("The alert could not be closed. Check the application log and try again.", status_code=500)
    if not changed:
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"ok": False, "error": "Alert not found."}, status_code=404)
        return PlainTextResponse("Alert not found.", status_code=404)
    auth.record_audit(request.state.user, "alert_closed", alert_id)
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "id": alert_id, "status": "CLOSED"})
    return RedirectResponse(_safe_next(form.get("next"), "/alerts"), status_code=303)


@app.get("/explorer")
def explorer_page(request: Request, q: str = "", category: str = "ALL", auto: int = 0):
    category = category.upper() if category.upper() in ("AUTH", "CMD", "SESS", "INFO") else "ALL"
    return render(request, "explorer.html", "explorer", refresh=5 if auto else 0, q=q[:200],
                  category=category, auto=auto, events=queries.events(500, q[:200], category))


@app.get("/actors")
def actors_page(request: Request, sort: str = "EVENTS"):
    items = queries.actors()
    if sort == "RISK":
        items.sort(key=lambda a: queries.RISK_RANK[a["riskLevel"]], reverse=True)
    return render(request, "actors.html", "actors", sort=sort, actors=items)


@app.get("/sessions")
def sessions_page(request: Request, sort: str = "LATEST"):
    sort = sort if sort in ("LATEST", "THREAT", "EVENTS") else "LATEST"
    return render(request, "sessions.html", "sessions", refresh=5, sort=sort,
                  sessions=queries.sessions(sort))


@app.get("/sessions/{session_id}")
def session_page(request: Request, session_id: str):
    detail = queries.session_detail(session_id)
    if detail is None:
        return PlainTextResponse("Session not found", status_code=404)
    return render(request, "session_detail.html", "sessions", s=detail)



# ------------------------------------------------------------------ settings
def _number(value, default, low, high):
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


@app.get("/settings")
def settings_page(request: Request, tab: str = "global", saved: int = 0, error: str = ""):
    tab = tab if tab in ("global", "response", "intel", "raw", "source") else "global"
    s = cfg.load()
    return render(request, "settings.html", "settings", tab=tab, saved=saved, error=error, s=cfg.public(s),
                  ar_commands=cfg.AR_COMMANDS, raw=cfg.raw_config(s))


@app.post("/settings")
async def save_settings(request: Request):
    form = await request.form()
    tab = form.get("tab")
    s = cfg.load()
    if tab == "global":
        s["alertLevel"] = _number(form.get("alertLevel"), s["alertLevel"], 0, 15)
        s["logRetention"] = _number(form.get("logRetention"), s["logRetention"], 1, 3650)
    elif tab == "response":
        s["arEnabled"] = form.get("arEnabled") == "1"
        if form.get("arCommand") in cfg.AR_COMMANDS:
            s["arCommand"] = form.get("arCommand")
        s["arTimeout"] = _number(form.get("arTimeout"), s["arTimeout"], 1, 86400)
    elif tab == "intel":
        s["vtEnabled"] = form.get("vtEnabled") == "1"
        s["otxEnabled"] = form.get("otxEnabled") == "1"
        if form.get("clearKey") == "1":
            s["vtKey"] = ""
        elif form.get("vtKey"):                       # blank = keep the saved key
            s["vtKey"] = str(form.get("vtKey"))[:200]
    elif tab == "source":
        from urllib.parse import quote
        raw_path = str(form.get("cowrieLogPath", "")).strip()
        try:
            new_path = Path(raw_path).expanduser().resolve(strict=True)
            if not new_path.is_file() or not os.access(new_path, os.R_OK):
                raise ValueError("Choose an existing, readable Cowrie JSON log file.")
            # Do not let a path setting turn the ingestor into a generic local-file
            # reader: require a Cowrie event on the first non-empty line.
            with new_path.open("rb") as stream:
                first_line = stream.readline(256 * 1024 + 1)
            if not first_line or len(first_line) > 256 * 1024:
                raise ValueError("The file must begin with a valid Cowrie JSON event.")
            try:
                first_event = json.loads(first_line)
            except (ValueError, UnicodeDecodeError):
                raise ValueError("The file must begin with a valid Cowrie JSON event.")
            if not isinstance(first_event, dict) or not str(first_event.get("eventid", "")).startswith("cowrie."):
                raise ValueError("The file must begin with a valid Cowrie JSON event.")
        except (OSError, RuntimeError, ValueError):
            return RedirectResponse(
                "/settings?tab=source&error=" + quote("Choose an existing, readable file that begins with a valid Cowrie JSON event."),
                status_code=303,
            )
        s["cowrieLogPath"] = str(new_path)
    cfg.save(s)
    if tab == "source":
        # Switch the tailer immediately. Path changes are serialized with polling,
        # and checkpoints from a different path are not reused.
        app.state.ingestor.set_log_path(new_path)
    
    auth.record_audit(request.state.user, "settings_updated", str(tab or "global"))
    return RedirectResponse(f"/settings?tab={tab if tab in ('global', 'response', 'intel', 'source') else 'global'}&saved=1",
                            status_code=303)


@app.post("/settings/purge")
async def purge(request: Request):
    form = await request.form()
    if form.get("confirm") == "PURGE":
        request.app.state.ingestor.purge()
        auth.record_audit(request.state.user, "database_purged", "SQLite SIEM database")
    return RedirectResponse("/settings?tab=global&saved=1", status_code=303)


# ======================================================================= API
def _is_local_request(request: Request) -> bool:
    """Allow local development and same-origin browser calls through forwarded dev ports.

    Codespaces and similar development proxies do not present the browser as a loopback
    client. For those requests, require an explicit same-origin Origin header; the
    middleware above rejects cross-origin state-changing requests.
    """
    client_host = request.client.host if request.client else ""
    if client_host in ("127.0.0.1", "::1", "localhost", "testclient"):
        return True
    origin = request.headers.get("origin")
    host = request.headers.get("host", "")
    if not origin or not host:
        return False
    try:
        parsed = urlparse(origin)
        return parsed.netloc.lower() == host.lower() and parsed.scheme in ("http", "https")
    except (TypeError, ValueError):
        return False



@app.get("/api/health")
def api_health():
    # Keep the unauthenticated liveness endpoint intentionally low-information.
    return {"status": "ok"}


@app.get("/api/overview/metrics")
def api_overview():
    d = queries.overview()
    return {**d, "categories": [{"name": n, "value": v} for n, v, _ in d["categories"]],
            "timeline": [{"time": t, "events": c} for t, c in d["timeline"]]}


@app.get("/api/overview/refresh")
def api_overview_refresh():
    """Return overview metrics and chart markup from one database read."""
    data = queries.overview()
    return {
        "metrics": data["metrics"],
        "timeline_svg": charts.area_chart(data["timeline"]),
        "donut_svg": charts.donut(data["categories"]),
    }


@app.get("/api/overview/charts")
def api_overview_charts():
    data = queries.overview()
    return {"timeline_svg": charts.area_chart(data["timeline"]),
            "donut_svg": charts.donut(data["categories"])}


@app.get("/api/geo/visual")
def api_geo_visual():
    data = queries.geo_overview()
    land = charts.land_path(APP_DIR / "static" / "countries-110m.json")
    return {"map_svg": charts.world_map(land, data["attackNodes"], data["honeypot"]),
            "stats": data["stats"], "nodes": data["attackNodes"], "countries": data["countries"]}


@app.get("/api/alerts")
def api_alerts(severity: str = "ALL"):
    return queries.alerts(severity.upper())


@app.get("/api/events")
def api_events(q: str = "", category: str = "ALL", limit: int = 500):
    return queries.events(max(1, min(limit, 2000)), q, category.upper())


@app.get("/api/actors")
def api_actors():
    return queries.actors()


@app.get("/api/sessions")
def api_sessions(sort: str = "LATEST"):
    return queries.sessions(sort)


@app.get("/api/sessions/{session_id}")
def api_session(session_id: str):
    detail = queries.session_detail(session_id)
    return detail if detail else JSONResponse({"error": "Session not found"}, status_code=404)


@app.get("/api/geo")
def api_geo():
    return queries.geo_overview()


@app.get("/api/mitre")
def api_mitre():
    return queries.mitre_matrix()



@app.get("/api/settings")
def api_settings():
    return cfg.public(cfg.load())
