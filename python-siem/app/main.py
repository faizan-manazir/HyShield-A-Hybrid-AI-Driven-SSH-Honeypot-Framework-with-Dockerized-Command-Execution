"""
HyShield SIEM - web app (pages + JSON API) in one FastAPI file.

Run it:   python run.py
Open:     http://127.0.0.1:8000        (API docs: http://127.0.0.1:8000/docs)
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import charts, config, db, queries, settings as cfg
from .ingest import Ingestor
from .test_generator import RandomEventGenerator

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=APP_DIR / "templates")   # auto-escapes all {{ values }}


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
    context.update(page=page, refresh=refresh)
    return templates.TemplateResponse(request, template, context)


# ------------------------------------------------------------------ app setup
@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    db.init()
    app.state.ingestor = Ingestor(config.LOG_PATH, config.POLL_SECONDS)
    app.state.ingestor.start()
    app.state.event_generator = RandomEventGenerator(config.LOG_PATH)
    logging.getLogger("hyshield").info("Tailing %s", config.LOG_PATH)
    yield
    app.state.ingestor.stop()


app = FastAPI(title="HyShield SIEM", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


@app.middleware("http")
async def safety(request: Request, call_next):
    # Block other websites from submitting our forms (close alert / purge / settings)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return PlainTextResponse("Cross-origin request blocked", status_code=403)
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


@app.get("/generator")
def generator_page(request: Request):
    return render(request, "generator.html", "generator", generator=app.state.event_generator.status())


# ------------------------------------------------------------------ settings
def _number(value, default, low, high):
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


@app.get("/settings")
def settings_page(request: Request, tab: str = "global", saved: int = 0):
    tab = tab if tab in ("global", "response", "intel", "raw") else "global"
    s = cfg.load()
    return render(request, "settings.html", "settings", tab=tab, saved=saved, s=cfg.public(s),
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
    cfg.save(s)
    return RedirectResponse(f"/settings?tab={tab if tab in ('global', 'response', 'intel') else 'global'}&saved=1",
                            status_code=303)


@app.post("/settings/purge")
async def purge(request: Request):
    form = await request.form()
    if form.get("confirm") == "PURGE":
        request.app.state.ingestor.purge()
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


@app.get("/api/test-generator/status")
def api_test_generator_status():
    return app.state.event_generator.status()


@app.post("/api/test-generator/start")
async def api_test_generator_start(request: Request):
    if not _is_local_request(request):
        return JSONResponse({"error": "The test generator is available only from the local machine."}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        body = {}
    sessions = _number(body.get("sessions", 10), 10, 1, 100) if isinstance(body, dict) else 10
    speed = body.get("speed", "normal") if isinstance(body, dict) else "normal"
    started, status = app.state.event_generator.start(sessions, speed)
    return JSONResponse({**status, "started": started}, status_code=200 if started else 409)


@app.post("/api/test-generator/stop")
def api_test_generator_stop(request: Request):
    if not _is_local_request(request):
        return JSONResponse({"error": "The test generator is available only from the local machine."}, status_code=403)
    return app.state.event_generator.stop()


@app.get("/api/health")
def api_health():
    return {"status": "ok", "ingested": app.state.ingestor.stats}


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
