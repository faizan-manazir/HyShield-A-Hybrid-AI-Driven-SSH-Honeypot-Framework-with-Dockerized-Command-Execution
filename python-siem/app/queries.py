"""
Every question the pages ask the database. Used by both the HTML pages and the
JSON API, so there is exactly one copy of each calculation.
"""
from collections import Counter, OrderedDict

from . import config, correlation, db, geo

RISK_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RANK_RISK = {v: k for k, v in RISK_RANK.items()}


def event_category(eventid):
    """AUTH / CMD / SESS / INFO label for an event type."""
    e = (eventid or "").lower()
    if "login" in e:
        return "AUTH"
    if "command" in e:
        return "CMD"
    if "connect" in e or "closed" in e:
        return "SESS"
    return "INFO"


def _rows(sql, args=()):
    conn = db.connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def _one(sql, args=()):
    rows = _rows(sql, args)
    return rows[0] if rows else None


# ------------------------------------------------------------------ overview
def overview():
    totals = _one("""SELECT
        (SELECT COUNT(*) FROM raw_events)                      AS events,
        (SELECT COUNT(*) FROM sessions WHERE is_closed = 0)    AS active,
        (SELECT COUNT(*) FROM alerts WHERE status = 'OPEN')    AS open_alerts,
        (SELECT COUNT(DISTINCT src_ip) FROM sessions)          AS actors""")

    # events per minute, using the newest 1000 events
    buckets = Counter()
    for r in _rows("SELECT timestamp FROM raw_events WHERE timestamp IS NOT NULL ORDER BY timestamp DESC LIMIT 1000"):
        buckets[str(r["timestamp"])[:16]] += 1               # "2026-05-18T21:58"
    recent = sorted(buckets.items())[-20:]
    many_days = len({key[:10] for key, _ in recent}) > 1
    timeline = [(key[5:16].replace("T", " ") if many_days else key[11:16], count) for key, count in recent]

    cat = Counter()
    for r in _rows("SELECT eventid, COUNT(*) AS c FROM raw_events GROUP BY eventid"):
        cat[event_category(r["eventid"])] += r["c"]
    categories = [("AUTH", cat["AUTH"], "#8b5cf6"), ("CMD", cat["CMD"], "#f97316"),
                  ("SESS", cat["SESS"], "#3b82f6"), ("INFO", cat["INFO"], "#6b7280")]

    return {
        "metrics": {"totalEvents": totals["events"], "activeSessions": totals["active"],
                    "openAlerts": totals["open_alerts"], "uniqueActors": totals["actors"]},
        "timeline": timeline,
        "categories": categories,
        "priorityAlerts": alerts(limit=5, status="OPEN", order_by_priority=True),
        "recentAlerts": alerts(limit=5, status="OPEN"),
        "topActors": actors()[:5],
    }


# -------------------------------------------------------------------- alerts
def alerts(severity=None, limit=500, status=None, order_by_priority=False):
    sql = """SELECT a.id, a.session_id, a.severity, a.title, a.reason, a.mitre, a.status,
                    s.src_ip, s.start_time AS timestamp
             FROM alerts a LEFT JOIN sessions s ON s.session_id = a.session_id"""
    conditions, args = [], []
    if severity and severity != "ALL":
        conditions.append("a.severity = ?")
        args.append(severity)
    if status and status != "ALL":
        conditions.append("a.status = ?")
        args.append(status)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    if order_by_priority:
        sql += """ ORDER BY CASE UPPER(COALESCE(a.severity, 'LOW'))
                     WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                     WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,
                     s.start_time DESC, a.id DESC LIMIT ?"""
    else:
        sql += " ORDER BY s.start_time DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in _rows(sql, args)]


def close_alert(alert_id):
    conn = db.connect()
    try:
        cur = conn.execute("UPDATE alerts SET status='CLOSED' WHERE id=? AND status != 'CLOSED'", (alert_id,))
        conn.commit()
        # Treat an already-closed alert as a successful idempotent action.
        if cur.rowcount:
            return True
        return _one("SELECT 1 FROM alerts WHERE id=?", (alert_id,)) is not None
    finally:
        conn.close()


# -------------------------------------------------------------------- events
def events(limit=500, q="", category="ALL"):
    """Return newest events, applying search/category filters before LIMIT."""
    limit = max(1, min(int(limit), 5000))
    needle = (q or "").lower().strip()
    category = (category or "ALL").upper()
    if category not in {"ALL", "AUTH", "CMD", "SESS", "INFO"}:
        category = "ALL"

    sql = """SELECT r.id, r.session_id, r.timestamp, r.eventid, r.payload, s.summary
             FROM raw_events r LEFT JOIN sessions s ON s.session_id = r.session_id"""
    conditions, args = [], []
    category_sql = """CASE
        WHEN LOWER(COALESCE(r.eventid, '')) LIKE '%login%' THEN 'AUTH'
        WHEN LOWER(COALESCE(r.eventid, '')) LIKE '%command%' THEN 'CMD'
        WHEN LOWER(COALESCE(r.eventid, '')) LIKE '%connect%'
          OR LOWER(COALESCE(r.eventid, '')) LIKE '%closed%' THEN 'SESS'
        ELSE 'INFO' END"""
    if category != "ALL":
        conditions.append(f"{category_sql} = ?")
        args.append(category)
    if needle:
        # Filter in SQL before LIMIT so older matching events remain searchable.
        conditions.append("""(LOWER(COALESCE(r.payload, '')) LIKE ?
                              OR LOWER(COALESCE(s.summary, '')) LIKE ?
                              OR LOWER(COALESCE(r.eventid, '')) LIKE ?
                              OR LOWER(COALESCE(r.session_id, '')) LIKE ?)""")
        pattern = f"%{needle}%"
        args.extend([pattern, pattern, pattern, pattern])
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.timestamp DESC LIMIT ?"
    args.append(limit)

    mitre_by_session, out = {}, []
    for r in _rows(sql, args):
        sid = r["session_id"]
        if sid not in mitre_by_session:
            tags = db.jload(r["summary"]).get("mitre", [])
            mitre_by_session[sid] = " | ".join(
                f"{m['id']} {m['name']} {m['tactic']}" for m in tags)
        e = db.jload(r["payload"])
        e.update(id=r["id"], session=sid,
                 timestamp=r["timestamp"] or e.get("timestamp"),
                 eventid=r["eventid"] or e.get("eventid"),
                 mitre_context=mitre_by_session[sid],
                 category=event_category(r["eventid"]))
        out.append(e)
    return out


# -------------------------------------------------------------------- actors
def actors():
    rows = _rows("""SELECT s.src_ip AS ip, MIN(s.start_time) AS first_seen, MAX(s.end_time) AS last_seen,
                           COUNT(*) AS sessions, SUM(s.event_count) AS events,
                           MAX(CASE s.risk_level WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                                                 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS risk
                    FROM sessions s WHERE s.src_ip IS NOT NULL GROUP BY s.src_ip""")
    out = []
    for r in rows:
        risk = RANK_RISK[r["risk"]]
        if risk == "LOW" and r["sessions"] > 5:               # many sessions = at least medium
            risk = "MEDIUM"
        out.append({"ip": r["ip"], "eventCount": r["events"] or 0, "sessionCount": r["sessions"],
                    "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
                    "riskLevel": risk, "location": geo.resolve(r["ip"])})
    return sorted(out, key=lambda a: a["eventCount"], reverse=True)


# ------------------------------------------------------------------ sessions
def _session_row(s):
    summary = db.jload(s["summary"])
    return {"id": s["session_id"], "src_ip": s["src_ip"], "start_time": s["start_time"],
            "end_time": s["end_time"], "is_closed": bool(s["is_closed"]),
            "threatScore": s["threat_score"], "riskLevel": s["risk_level"],
            "eventCount": s["event_count"], "summary": summary.get("summary", {}),
            "mitre": summary.get("mitre", []), "location": geo.resolve(s["src_ip"])}


def sessions(sort="LATEST", limit=500):
    statements = {
        "LATEST": "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?",
        "THREAT": "SELECT * FROM sessions ORDER BY threat_score DESC, start_time DESC LIMIT ?",
        "EVENTS": "SELECT * FROM sessions ORDER BY event_count DESC, start_time DESC LIMIT ?",
    }
    statement = statements.get(sort, statements["LATEST"])
    return [_session_row(s) for s in _rows(statement, (limit,))]


# Cowrie event -> stage name shown in the "attack story"
STAGES = {"cowrie.session.connect": "CONNECTION", "cowrie.client.version": "FINGERPRINT",
          "cowrie.login.failed": "AUTHENTICATION", "cowrie.login.success": "ACCESS",
          "cowrie.session.closed": "FORENSICS"}


def session_detail(session_id):
    s = _one("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    if not s:
        return None
    detail = _session_row(s)
    parsed = db.jload(s["summary"])
    evs = [db.jload(r["payload"]) for r in
           _rows("SELECT payload FROM raw_events WHERE session_id=? ORDER BY timestamp ASC", (session_id,))]
    detail.update(dimensions=parsed.get("dimensions", {}), explanations=parsed.get("explanations", []),
                  events=evs)
    detail["story"] = [{"stage": STAGES.get(e.get("eventid"), "ACTIVITY"),
                        "hot": e.get("eventid") == "cowrie.login.success",
                        "time": e.get("timestamp"),
                        "text": e.get("message") or e.get("input") or e.get("eventid")} for e in evs]
    detail["tty"] = "\n".join(str(e.get("input") or e.get("message") or "") for e in evs
                              if e.get("input") or "command" in str(e.get("eventid")))
    return detail


# ----------------------------------------------------------------------- geo
def geo_overview():
    honeypot = dict(config.HONEYPOT)
    countries, by_ip = OrderedDict(), OrderedDict()
    for s in sessions(limit=5000):
        g, risk = s["location"], s["riskLevel"] or "LOW"
        events = max(1, s["eventCount"] or 1)
        c = countries.setdefault(g["countryCode"], {
            "code": g["countryCode"], "name": g["countryName"], "flag": g["flag"],
            "eventCount": 0, "sessionCount": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        c["eventCount"] += events
        c["sessionCount"] += 1
        c[risk if risk in RISK_RANK else "LOW"] += 1
        if g["lat"] is not None and g["lng"] is not None:
            node = by_ip.setdefault(s["src_ip"], {
                "id": s["id"], "sessionIds": [], "ip": s["src_ip"], "city": g["city"],
                "region": g.get("region", ""), "countryName": g["countryName"], "countryCode": g["countryCode"],
                "flag": g["flag"], "org": g["org"], "source": g.get("source", "unknown"),
                "accuracyRadiusKm": g.get("accuracyRadiusKm"), "lat": g["lat"], "lng": g["lng"],
                "eventCount": 0, "sessionCount": 0, "threatScore": 0, "riskLevel": "LOW",
                "startTime": s["start_time"], "isPrivate": g.get("isPrivate", False),
                "isVpn": g.get("isVpn"), "isProxy": g.get("isProxy"), "isTor": g.get("isTor")})
            node["sessionIds"].append(s["id"])
            node["eventCount"] += events
            node["sessionCount"] += 1
            node["threatScore"] = max(node["threatScore"], int(s["threatScore"] or 0))
            if RISK_RANK.get(risk, 1) > RISK_RANK.get(node["riskLevel"], 1):
                node["riskLevel"] = risk
            if str(s["start_time"] or "") > str(node["startTime"] or ""):
                node["startTime"] = s["start_time"]
    nodes = list(by_ip.values())
    event_total = sum(c["eventCount"] for c in countries.values())
    denominator = event_total or 1
    ranked = sorted(countries.values(), key=lambda c: c["eventCount"], reverse=True)
    for c in ranked:
        c["percentage"] = round(100 * c["eventCount"] / denominator)
    return {"honeypot": honeypot, "countries": ranked, "attackNodes": nodes,
            "stats": {"totalCountries": len(ranked), "mappedNodes": len(nodes), "totalEvents": event_total,
                      "topCountry": f"{ranked[0]['flag']} {ranked[0]['name']}" if ranked else "N/A"}}


# --------------------------------------------------------------------- MITRE
TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access",
                "Discovery", "Command and Control", "Lateral Movement", "Impact"]
TECH_SEVERITY = {"T1078": "HIGH", "T1110": "HIGH", "T1059": "HIGH", "T1204": "CRITICAL",
                 "T1136": "CRITICAL", "T1053": "MEDIUM", "T1070": "CRITICAL", "T1003": "CRITICAL",
                 "T1082": "MEDIUM", "T1049": "MEDIUM", "T1105": "HIGH", "T1021": "CRITICAL",
                 "T1496": "HIGH"}


def mitre_matrix():
    counts = Counter()
    for r in _rows("SELECT summary FROM sessions"):
        for m in db.jload(r["summary"]).get("mitre", []):
            counts[m["id"]] += 1
    matrix = {t: [] for t in TACTIC_ORDER}
    for tid, (name, tactic) in correlation.MITRE.items():
        matrix[tactic].append({"id": tid, "name": name, "count": counts[tid],
                               "severity": TECH_SEVERITY.get(tid, "MEDIUM")})
    return [{"name": t, "techniques": matrix[t]} for t in TACTIC_ORDER if matrix[t]]
