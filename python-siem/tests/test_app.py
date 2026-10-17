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
         "/settings", "/settings?tab=response", "/settings?tab=intel", "/settings?tab=raw", "/generator"]


@pytest.mark.parametrize("path", PAGES)
def test_every_page_renders(client, path):
    r = client.get(path)
    assert r.status_code == 200, path
    assert "HYSHIELD" in r.text



def test_live_activity_is_a_dashboard_tab_and_retired_pages_are_removed(client):
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert 'href="/live"' in dashboard.text
    assert 'href="/generator"' in dashboard.text
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


def test_generator_allows_same_origin_forwarded_dev_port_requests():
    def make_request(origin):
        return Request({
            "type": "http",
            "method": "POST",
            "path": "/api/test-generator/start",
            "headers": [(b"host", b"codespace.example"), (b"origin", origin.encode())],
            "client": ("10.0.0.8", 12345),
            "server": ("codespace.example", 443),
            "scheme": "https",
            "query_string": b"",
        })

    assert _is_local_request(make_request("https://codespace.example")) is True
    assert _is_local_request(make_request("https://attacker.example")) is False


def test_generator_page_and_status_api(client):
    page = client.get("/generator")
    assert page.status_code == 200
    assert "Test Event Generator" in page.text
    assert "TEST-NET" in page.text
    status = client.get("/api/test-generator/status")
    assert status.status_code == 200
    assert "running" in status.json()

def test_generator_emits_synthetic_cowrie_events(client):
    import time
    response = client.post("/api/test-generator/start", json={"sessions": 1, "speed": "fast"})
    assert response.status_code == 200, response.text
    deadline = time.time() + 3
    status = client.get("/api/test-generator/status").json()
    while status["running"] and time.time() < deadline:
        time.sleep(0.05)
        status = client.get("/api/test-generator/status").json()
    assert not status["running"]
    assert status["completed_sessions"] == 1
    assert status["events_written"] >= 3
    assert app.state.ingestor.poll() >= 3
    events = client.get("/api/events?limit=200").json()
    assert any(e.get("src_ip", "").startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for e in events)


def test_geo_map_is_interactive_and_displays_coordinate_metadata(client):
    page = client.get("/geomap")
    assert page.status_code == 200
    assert 'id="geo-search"' in page.text
    assert 'id="geo-risk-filter"' in page.text
    assert 'id="geo-copy-coords"' in page.text
    assert 'id="geo-detail-lat"' in page.text
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
    from app import queries

    priority_alerts = queries.overview()["priorityAlerts"]
    if not priority_alerts:
        pytest.skip("sample telemetry produced no open priority alerts")

    target = priority_alerts[0]
    assert queries.close_alert(target["id"]) is True

    queued = queries.overview()["priorityAlerts"]
    assert all(item["id"] != target["id"] for item in queued)



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
    saved_cookie = client.cookies.get(auth.COOKIE_NAME)
    client.cookies.delete(auth.COOKIE_NAME)
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"] == "/login"
    api = client.get("/api/events")
    assert api.status_code == 401
    setup = client.get("/setup", follow_redirects=False)
    assert setup.status_code == 303 and setup.headers["location"] == "/login"
    client.cookies.set(auth.COOKIE_NAME, saved_cookie)
