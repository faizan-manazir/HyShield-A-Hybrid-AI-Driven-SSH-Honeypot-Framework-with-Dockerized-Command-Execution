import json

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import auth, charts, config
from app.main import app, _is_local_request


@pytest.fixture(scope="module")
def client():
    import secrets
    with TestClient(app) as c:                       # runs startup (creates the ingestor thread)
        username = "pytest-" + secrets.token_hex(4)
        admin = auth.create_user(username, "Test-Admin-Password-2026!", "super_admin")
        response = c.post("/login", data={"username": username, "password": "Test-Admin-Password-2026!"}, follow_redirects=False)
        assert response.status_code == 303
        app.state.test_admin = admin
        app.state.test_admin_cookie = c.cookies.get(auth.COOKIE_NAME)
        app.state.ingestor.poll()                    # read the sample log right now
        yield c


PAGES = ["/", "/live", "/geomap", "/mitre", "/alerts", "/alerts?severity=HIGH", "/explorer",
         "/explorer?q=wget&category=CMD", "/actors", "/actors?sort=RISK", "/sessions",
         "/sessions?sort=THREAT",
         "/settings", "/settings?tab=response", "/settings?tab=intel", "/settings?tab=raw", "/settings?tab=source"]


@pytest.mark.parametrize("path", PAGES)
def test_every_page_renders(client, path):
    r = client.get(path)
    assert r.status_code == 200, path
    assert "HYSHIELD" in r.text



def test_live_activity_is_a_dashboard_tab_and_retired_pages_are_removed(client):
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert 'href="/live"' in dashboard.text
    assert "Real-time Attack Map" in dashboard.text
    assert "Investigation priorities" in dashboard.text
    assert "Telemetry Distribution" in dashboard.text
    assert "System Status" in dashboard.text
    assert "Top Source Actors" in dashboard.text
    assert "sparkline" in dashboard.text
    assert "interactive-worldmap" in dashboard.text
    live = client.get("/live")
    assert live.status_code == 200
    assert "Recent telemetry" in live.text
    assert 'data-refresh="5"' in live.text
    for path in ("/fim", "/vulnerabilities", "/api/fim"):
        assert client.get(path).status_code == 404, path
    sidebar = dashboard.text
    assert "File Activity (inferred)" not in sidebar
    assert "Vulnerabilities (demo)" not in sidebar


def test_dashboard_charts_are_interactive(client):
    area = charts.area_chart([("12:00", 2), ("12:01", 5)])
    donut = charts.donut([("AUTH", 3, "#8b5cf6"), ("CMD", 2, "#f97316")])
    assert 'class="dot chart-point"' in area
    assert 'data-chart-tip' not in area
    assert '<title>' not in area
    assert 'class="donut-slice"' in donut
    assert 'data-href="/explorer?category=AUTH"' in donut
    assert "chart-tooltip" not in client.get("/static/app.js?v=4").text
    assert "@keyframes app-start" in client.get("/static/style.css?v=4").text
    assert "#overview-donut .donut" in client.get("/static/style.css?v=12").text

def test_sample_log_was_ingested(client):
    data = client.get("/api/overview/metrics").json()
    assert data["metrics"]["totalEvents"] >= 58  # persistent local DB may contain events from earlier runs
    assert len(client.get("/api/sessions").json()) >= 6


def test_session_page_and_404(client):
    sid = client.get("/api/sessions").json()[0]["id"]
    assert client.get(f"/sessions/{sid}").status_code == 200
    assert client.get("/sessions/nope").status_code == 404
    assert client.get("/api/sessions/nope").status_code == 404


def test_poll_is_idempotent_and_tails_new_lines(client):
    ing = app.state.ingestor
    assert ing.poll() == 0                                   # nothing new
    line = {"eventid": "cowrie.session.connect", "session": "zzz111", "src_ip": "198.51.100.7",
            "timestamp": "2026-10-01T00:00:00.000Z"}
    with open(config.LOG_PATH, "a") as f:
        f.write(json.dumps(line) + "\n")
        f.write('{"half": "written')                         # unfinished line must wait
    assert ing.poll() == 1
    assert ing.poll() == 0
    assert any(s["id"] == "zzz111" for s in client.get("/api/sessions").json())


def test_malicious_log_content_is_escaped(client):
    evil = "<script>alert(1)</script>"
    lines = [{"eventid": "cowrie.session.connect", "session": "xss1", "src_ip": "198.51.100.8", "timestamp": "2026-10-02T00:00:00.000Z"},
             {"eventid": "cowrie.login.success", "session": "xss1", "src_ip": "198.51.100.8", "username": evil, "timestamp": "2026-10-02T00:00:01.000Z"},
             {"eventid": "cowrie.command.input", "session": "xss1", "src_ip": "198.51.100.8", "input": evil, "timestamp": "2026-10-02T00:00:02.000Z"}]
    with open(config.LOG_PATH, "a") as f:
        f.writelines(json.dumps(x) + "\n" for x in lines)
    app.state.ingestor.poll()
    for path in ("/sessions/xss1", "/explorer", "/", "/alerts"):
        assert evil not in client.get(path).text, path
    assert "&lt;script&gt;" in client.get("/sessions/xss1").text


def test_close_alert_and_open_redirect_guard(client):
    alert = client.get("/api/alerts").json()[0]
    r = client.post(f"/alerts/{alert['id']}/close", data={"next": "//evil.example"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/alerts"
    assert next(a for a in client.get("/api/alerts").json() if a["id"] == alert["id"])["status"] == "CLOSED"


def test_close_alert_json_response(client):
    alert = client.get("/api/alerts").json()[0]
    response = client.post(f"/alerts/{alert['id']}/close", headers={"accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["status"] == "CLOSED"


def test_cross_origin_post_is_blocked(client):
    r = client.post("/settings/purge", data={"confirm": "PURGE"}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    assert client.get("/api/overview/metrics").json()["metrics"]["totalEvents"] > 0


def test_loopback_origin_alias_is_allowed_but_external_origin_is_not(client):
    # Browser access via localhost and 127.0.0.1 should work for local development.
    r = client.post("/setup", data={}, headers={
        "origin": "http://localhost:8000", "host": "127.0.0.1:8000"
    }, follow_redirects=False)
    assert r.status_code != 403
    # Different non-loopback hosts must still be blocked.
    r = client.post("/settings/purge", data={"confirm": "PURGE"}, headers={
        "origin": "http://attacker.example:8000", "host": "127.0.0.1:8000"
    }, follow_redirects=False)
    assert r.status_code == 403


def test_csp_allows_only_same_origin_bundled_scripts(client):
    response = client.get("/")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "script-src 'none'" not in response.headers["content-security-policy"]
    assert '<script src="/static/app.js?v=12" defer></script>' in response.text
    assert 'http-equiv="refresh"' not in response.text
    assert 'data-refresh="5"' in response.text


def test_api_key_is_never_echoed(client):
    client.post("/settings", data={"tab": "intel", "vtEnabled": "1", "vtKey": "SECRET-KEY-123"})
    for path in ("/api/settings", "/settings?tab=intel", "/settings?tab=raw"):
        assert "SECRET-KEY-123" not in client.get(path).text, path
    assert client.get("/api/settings").json()["vtKeySet"] is True
    client.post("/settings", data={"tab": "intel", "clearKey": "1"})
    assert client.get("/api/settings").json()["vtKeySet"] is False


def test_mitre_names_match_so_counts_show_up(client):
    matrix = client.get("/api/mitre").json()
    hits = [t for tac in matrix for t in tac["techniques"] if t["count"]]
    assert hits, "sample data should light up at least one technique"


def test_purge_requires_confirmation(client):
    client.post("/settings/purge", data={"confirm": "no"})
    assert client.get("/api/overview/metrics").json()["metrics"]["totalEvents"] > 0
    client.post("/settings/purge", data={"confirm": "PURGE"})
    assert client.get("/api/overview/metrics").json()["metrics"]["totalEvents"] == 0
    assert app.state.ingestor.poll() == 0                    # old lines are not re-read


def test_geo_map_is_interactive_and_displays_coordinate_metadata(client):
    page = client.get("/geomap")
    assert page.status_code == 200
    assert 'id="geo-search"' in page.text
    assert 'id="geo-risk-filter"' in page.text
    assert 'id="geo-copy-coords"' in page.text
    assert 'id="geo-detail-lat"' in page.text
    # Marker coordinate attributes exist when the configured log contains public,
    # geolocatable sources. The page must still render correctly for an empty map.
    if "No public source coordinates are available yet." not in page.text:
        assert 'data-lat="' in page.text and 'data-lng="' in page.text
    assert "not a device’s GPS position" in page.text


def test_geo_visual_api_returns_interactive_source_data(client):
    response = client.get("/api/geo/visual")
    assert response.status_code == 200
    payload = response.json()
    assert "nodes" in payload and "countries" in payload
    assert "interactive-worldmap" in payload["map_svg"]
    if payload["nodes"]:
        node = payload["nodes"][0]
        assert node["ip"] and node["lat"] is not None and node["lng"] is not None
        assert "threatScore" in node and "sessionIds" in node


def test_ip_geolocation_provider_uses_https_and_parses_coordinates(monkeypatch):
    import io
    import json as json_module
    from app import geo
    seen = {}
    payload = {"success": True, "country": "Exampleland", "country_code": "EX",
               "region": "Example Region", "city": "Example City", "latitude": 12.345678,
               "longitude": 98.765432, "connection": {"isp": "Example ISP", "org": "Example Org", "asn": 64500},
               "timezone": {"id": "Etc/UTC"}, "security": {"vpn": False, "proxy": False, "tor": False}}
    def fake_urlopen(request, timeout=0):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return io.BytesIO(json_module.dumps(payload).encode())
    monkeypatch.setattr(geo.urllib.request, "urlopen", fake_urlopen)
    result = geo._fetch("175.29.58.162")
    assert seen["url"].startswith("https://ipwho.is/175.29.58.162?")
    assert result["lat"] == 12.345678 and result["lng"] == 98.765432
    assert result["source"] == "ipwho.is"
    assert result["org"] == "Example Org"



def test_overview_priority_queue_excludes_closed_alerts(client):
    import secrets
    from app import db, queries

    # Create this test's own session and highest-priority alert. Do not rely on
    # whatever sample telemetry or database state happens to exist in CI.
    suffix = secrets.token_hex(6)
    session_id = "pytest-priority-" + suffix
    alert_id = "pytest-alert-" + suffix
    conn = db.connect()
    try:
        conn.execute(
            """INSERT INTO sessions
               (session_id, src_ip, start_time, end_time, is_closed, threat_score,
                risk_level, event_count, summary)
               VALUES (?, ?, ?, NULL, 0, 100, 'CRITICAL', 1, '{}')""",
            (session_id, "198.51.100.254", "9999-12-31T23:59:59Z"),
        )
        conn.execute(
            """INSERT INTO alerts
               (id, session_id, severity, title, reason, mitre, status)
               VALUES (?, ?, 'CRITICAL', 'Pytest priority alert',
                       'Created by regression test', '[]', 'OPEN')""",
            (alert_id, session_id),
        )
        conn.commit()
    finally:
        conn.close()

    try:
        priority_alerts = queries.overview()["priorityAlerts"]
        assert any(item["id"] == alert_id for item in priority_alerts), (
            "test-created critical alert should appear in the overview priority queue"
        )

        assert queries.close_alert(alert_id) is True

        queued = queries.overview()["priorityAlerts"]
        assert all(item["id"] != alert_id for item in queued)
    finally:
        conn = db.connect()
        try:
            conn.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
            conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
            conn.commit()
        finally:
            conn.close()



def test_login_setup_and_role_permissions(client):
    import secrets
    analyst_name = "analyst-" + secrets.token_hex(3)
    auditor_name = "auditor-" + secrets.token_hex(3)
    analyst = auth.create_user(analyst_name, "Test-Analyst-Password-2026!", "analyst")
    auditor = auth.create_user(auditor_name, "Test-Auditor-Password-2026!", "auditor")

    client.cookies.set(auth.COOKIE_NAME, auth.make_session(analyst))
    assert client.get("/").status_code == 200
    assert client.get("/settings").status_code == 403
    assert client.get("/users").status_code == 403
    assert client.post("/alerts/nonexistent/close", data={}).status_code == 404
    assert client.post("/settings/purge", data={"confirm": "PURGE"}).status_code == 403

    client.cookies.set(auth.COOKIE_NAME, auth.make_session(auditor))
    assert client.get("/").status_code == 200
    assert client.get("/audit-logs").status_code == 200
    assert client.get("/settings").status_code == 403
    assert client.get("/users").status_code == 403
    assert client.post("/alerts/nonexistent/close", data={}).status_code == 403
    assert client.post("/api/test-generator/start", json={"sessions": 1}).status_code == 403

    client.cookies.set(auth.COOKIE_NAME, app.state.test_admin_cookie)
    assert client.get("/users").status_code == 200
    assert client.get("/settings").status_code == 200


def test_password_hashing_and_account_disable(client):
    import secrets
    username = "disable-" + secrets.token_hex(3)
    user = auth.create_user(username, "Test-Disable-Password-2026!", "auditor")
    assert auth.authenticate(username, "wrong-password") is None
    assert auth.authenticate(username, "Test-Disable-Password-2026!") is not None
    assert auth.set_user_active(user["id"], False, app.state.test_admin) is True
    assert auth.authenticate(username, "Test-Disable-Password-2026!") is None



def test_protected_routes_require_login_and_setup_closes_after_bootstrap(client):
    # Build an independent client so role-switching cookies from other tests
    # cannot create duplicate cookies with the same name.
    from fastapi.testclient import TestClient
    unauthenticated = TestClient(app)
    unauthenticated.cookies.clear()
    page = unauthenticated.get("/", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"] == "/login"
    api = unauthenticated.get("/api/events")
    assert api.status_code == 401
    setup = unauthenticated.get("/setup", follow_redirects=False)
    assert setup.status_code == 303 and setup.headers["location"] == "/login"




def test_html_report_download_is_standalone_and_contains_security_summary(client):
    response = client.get("/reports/export.html")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers["content-disposition"].startswith("attachment; filename=\"hyshield-security-report-")
    assert response.headers["cache-control"] == "no-store"
    assert "<!doctype html>" in response.text.lower()
    assert "HyShield SIEM Security Report" in response.text
    assert "TOTAL EVENTS" in response.text
    assert "Recent Events" in response.text
    assert "<script" not in response.text.lower()


def test_initial_super_admin_setup_is_one_time(monkeypatch, tmp_path):
    from app import db
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "bootstrap.db")
    db.init()
    user = auth.create_initial_admin("bootstrap-admin", "Bootstrap-Admin-Password-2026!")
    assert user["role"] == "super_admin"
    assert auth.user_count() == 1
    with pytest.raises(ValueError, match="already been completed"):
        auth.create_initial_admin("second-admin", "Second-Admin-Password-2026!")
    assert auth.user_count() == 1


def test_login_throttling_returns_429_after_eight_failures(client):
    from app import main
    main._clear_login_failures("testclient")
    for attempt in range(8):
        response = client.post("/login", data={"username": "not-a-user", "password": "incorrect-password"},
                               follow_redirects=False)
    assert response.status_code == 429
    blocked = client.post("/login", data={"username": "not-a-user", "password": "incorrect-password"},
                          follow_redirects=False)
    assert blocked.status_code == 429
    main._clear_login_failures("testclient")


def test_secure_cookie_can_be_forced_for_tls_terminating_proxy(client, monkeypatch):
    monkeypatch.setattr(config, "COOKIE_SECURE", True)
    response = client.post("/login", data={"username": app.state.test_admin["username"],
                                           "password": "Test-Admin-Password-2026!"},
                           follow_redirects=False)
    assert response.status_code == 303
    cookie = response.headers.get("set-cookie", "")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie


def test_retention_removes_expired_events_but_preserves_sessions_with_recent_events(monkeypatch, tmp_path):
    from app import db
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "retention.db")
    db.init()
    conn = db.connect()
    try:
        conn.execute("INSERT INTO sessions(session_id, start_time) VALUES (?, ?)",
                     ("mixed-age", "2020-01-01T00:00:00Z"))
        conn.execute("INSERT INTO raw_events VALUES (?, ?, ?, ?, ?)",
                     ("old-event", "mixed-age", "2020-01-01T00:00:00Z", "cowrie.old", "{}"))
        conn.execute("INSERT INTO raw_events VALUES (?, ?, ?, ?, ?)",
                     ("new-event", "mixed-age", "2026-10-17T00:00:00Z", "cowrie.new", "{}"))
        conn.execute("INSERT INTO alerts(id, session_id, severity, title) VALUES (?, ?, ?, ?)",
                     ("retention-alert", "mixed-age", "LOW", "test"))
        conn.commit()
    finally:
        conn.close()
    result = db.cleanup_retention(90)
    conn = db.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM raw_events WHERE id='old-event'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM raw_events WHERE id='new-event'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM sessions WHERE session_id='mixed-age'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM alerts WHERE id='retention-alert'").fetchone()[0] == 1
    finally:
        conn.close()
    assert result["events_deleted"] == 1


def test_ingestor_discards_oversized_json_line(monkeypatch, tmp_path):
    from app import db
    from app.ingest import Ingestor, MAX_LINE_BYTES
    log_path = tmp_path / "oversized.json"
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "oversized.db")
    db.init()
    log_path.write_bytes(b"x" * (MAX_LINE_BYTES + 100) + b"\n")
    ingestor = Ingestor(log_path)
    assert ingestor.poll() == 0
    conn = db.connect()
    try:
        row = conn.execute("SELECT eventid, payload FROM raw_events").fetchone()
        assert row["eventid"] == "error.oversized"
        assert "Oversized log line discarded" in row["payload"]
    finally:
        conn.close()


def test_super_admin_can_change_cowrie_log_path_immediately(client, tmp_path):
    from app import settings as cfg
    source = tmp_path / "cowrie-custom.json"
    source.write_text(json.dumps({
        "eventid": "cowrie.session.connect",
        "session": "custom-path-test",
        "src_ip": "198.51.100.77",
        "timestamp": "2026-10-17T00:00:00Z",
    }) + "\n", encoding="utf-8")
    original_path = app.state.ingestor.log_path
    original_setting = cfg.load().get("cowrieLogPath", original_path)
    try:
        response = client.post("/settings", data={"tab": "source", "cowrieLogPath": str(source)},
                               follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/settings?tab=source&saved=1"
        assert app.state.ingestor.log_path == str(source.resolve())
        assert cfg.load()["cowrieLogPath"] == str(source.resolve())
        assert app.state.ingestor.poll() in (0, 1)  # background polling may win the race
        assert any(item["id"] == "custom-path-test" for item in client.get("/api/sessions").json())
    finally:
        app.state.ingestor.set_log_path(original_path)
        cfg.save({**cfg.load(), "cowrieLogPath": original_setting})


def test_cowrie_log_path_rejects_missing_file_and_non_admin(client, tmp_path):
    missing = tmp_path / "does-not-exist.json"
    response = client.post("/settings", data={"tab": "source", "cowrieLogPath": str(missing)},
                           follow_redirects=False)
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert app.state.ingestor.log_path != str(missing)

    analyst = auth.create_user("path-analyst-test", "Test-Path-Password-2026!", "analyst")
    client.cookies.set(auth.COOKIE_NAME, auth.make_session(analyst))
    forbidden = client.post("/settings", data={"tab": "source", "cowrieLogPath": str(missing)},
                            follow_redirects=False)
    assert forbidden.status_code == 403
    client.cookies.set(auth.COOKIE_NAME, app.state.test_admin_cookie)

def test_parse_time_normalizes_naive_and_aware_timestamps():
    from datetime import timezone
    from app.correlation import _parse_time

    naive = _parse_time("2026-10-01T00:00:00")
    aware = _parse_time("2026-10-02T00:00:00Z")

    assert naive is not None
    assert aware is not None
    assert naive.tzinfo is not None
    assert aware.tzinfo is not None
    assert naive.utcoffset() == timezone.utc.utcoffset(naive)
    assert (aware - naive).total_seconds() == 86400
