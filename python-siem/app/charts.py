"""
Charts drawn as plain SVG text by Python - no JavaScript chart library needed.
Every text value is escaped, because log data is controlled by attackers.
"""
import json
import math
from html import escape
from pathlib import Path

RISK_COLORS = {"CRITICAL": "#f43f5e", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#38bdf8"}


# ---------------------------------------------------------------- area chart
def area_chart(points, width=720, height=210, color="#06b6d4"):
    """points = [(label, number), ...]"""
    left, right, top, bottom = 38, 12, 12, 30
    if not points:
        return (f'<svg viewBox="0 0 {width} {height}" class="chart"><text x="{width/2}" y="{height/2}" '
                'text-anchor="middle" class="muted-text">No events yet</text></svg>')
    top_value = max(v for _, v in points) or 1
    step = 10 ** max(0, len(str(int(top_value))) - 1)
    top_value = math.ceil(top_value / step) * step
    inner_w, inner_h = width - left - right, height - top - bottom

    def x(i):
        return left + (inner_w * i / (len(points) - 1) if len(points) > 1 else inner_w / 2)

    def y(v):
        return top + inner_h - inner_h * v / top_value

    line = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, (_, v) in enumerate(points))
    area = f"{left},{top + inner_h} {line} {x(len(points) - 1):.1f},{top + inner_h}"
    out = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="Events per minute">',
           f'<defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1">'
           f'<stop offset="5%" stop-color="{color}" stop-opacity=".4"/>'
           f'<stop offset="95%" stop-color="{color}" stop-opacity="0"/></linearGradient></defs>']
    for k in range(5):                                   # horizontal grid + y labels
        value = top_value * k / 4
        out.append(f'<line x1="{left}" x2="{width - right}" y1="{y(value):.1f}" y2="{y(value):.1f}" class="grid"/>'
                   f'<text x="{left - 6}" y="{y(value) + 3:.1f}" text-anchor="end" class="axis">{value:g}</text>')
    shown = {round(i * (len(points) - 1) / 5) for i in range(6)} if len(points) > 1 else {0}
    for i in sorted(shown):                              # x labels (about 6)
        out.append(f'<text x="{x(i):.1f}" y="{height - 8}" text-anchor="middle" class="axis">{escape(points[i][0])}</text>')
    out.append(f'<polygon points="{area}" fill="url(#fill)"/>'
               f'<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2"/>')
    for i, (label, v) in enumerate(points):              # visual data points, no hover tooltip
        out.append(f'<circle cx="{x(i):.1f}" cy="{y(v):.1f}" r="5" class="dot chart-point" aria-hidden="true" pointer-events="none"/>')
    out.append("</svg>")
    return "".join(out)


# --------------------------------------------------------------------- donut
def donut(slices, size=180):
    """slices = [(name, value, color), ...]"""
    total = sum(v for _, v, _ in slices)
    radius, stroke = 74, 24
    circumference = 2 * math.pi * radius
    out = [f'<svg viewBox="0 0 {size} {size}" class="chart donut" role="img" aria-label="Event distribution">',
           f'<circle cx="{size/2}" cy="{size/2}" r="{radius}" fill="none" stroke="#1a1a24" stroke-width="{stroke}"/>']
    offset = 0.0
    for slice_index, (name, value, color) in enumerate(slices):
        if total and value:
            length = circumference * value / total
            href = f"/explorer?category={name}" if name in {"AUTH", "CMD", "SESS", "INFO"} else "/explorer"
            gap = circumference - length
            delay = slice_index * 130
            out.append(f'<circle cx="{size/2}" cy="{size/2}" r="{radius}" fill="none" stroke="{color}" '
                       f'stroke-width="{stroke}" stroke-dasharray="{length:.2f} {gap:.2f}" '
                       f'stroke-dashoffset="{-offset:.2f}" style="--slice-length:{length:.2f}px;--slice-gap:{gap:.2f}px;--slice-offset:{-offset:.2f}px;animation-delay:{delay}ms" '
                       f'transform="rotate(-90 {size/2} {size/2})" '
                       f'class="donut-slice" data-animated="true" tabindex="0" role="link" data-href="{href}" '
                       f'aria-label="Open {escape(name)} events, {value}">' 
                       f'</circle>')
            offset += length
    out.append(f'<text x="{size/2}" y="{size/2 + 2}" text-anchor="middle" class="donut-total">{total:,}</text>'
               f'<text x="{size/2}" y="{size/2 + 20}" text-anchor="middle" class="axis">events</text></svg>')
    return "".join(out)


# ----------------------------------------------------------------- world map
def _decode_topojson(path):
    """Turns the countries-110m.json file into one SVG path string (plain equirectangular)."""
    topo = json.loads(Path(path).read_text())
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    arcs = []
    for arc in topo["arcs"]:                             # arcs are stored as small deltas
        px = py = 0
        points = []
        for dx, dy in arc:
            px += dx
            py += dy
            points.append((px * sx + tx, py * sy + ty))
        arcs.append(points)

    def ring(indexes):
        points = []
        for i in indexes:
            segment = arcs[i] if i >= 0 else arcs[~i][::-1]
            points.extend(segment if not points else segment[1:])
        return points

    parts = []
    for geometry in topo["objects"]["countries"]["geometries"]:
        if geometry.get("properties", {}).get("name") == "Antarctica":
            continue                                     # it is below the visible area
        polygons = {"Polygon": [geometry.get("arcs")],
                    "MultiPolygon": geometry.get("arcs")}.get(geometry["type"], [])
        for polygon in polygons:
            for r in polygon:
                piece, previous = [], None
                for lon, lat in ring(r):
                    if previous is not None and abs(lon - previous) > 180:   # crossed the date line
                        parts.append(_path(piece))
                        piece = []
                    piece.append((lon, lat))
                    previous = lon
                parts.append(_path(piece))
    return "".join(parts)


def _path(points):
    xy = [project(lat, lon) for lon, lat in points]
    return "M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in xy) + "Z" if len(xy) > 2 else ""


def project(lat, lon):
    """lat/lon -> x/y on a 1000x500 canvas."""
    return (lon + 180) / 360 * 1000, (90 - lat) / 180 * 500


_land = None


def land_path(path):
    global _land
    if _land is None:
        _land = _decode_topojson(path)
    return _land


def world_map(land, nodes, honeypot):
    """Interactive SVG world map. Marker metadata is escaped and consumed by app.js."""
    hx, hy = project(honeypot["lat"], honeypot["lng"])
    out = ['<svg viewBox="0 10 1000 410" class="chart worldmap interactive-worldmap" role="img" aria-label="Interactive threat origin map" tabindex="0">',
           f'<path d="{land}" class="land"/>', '<g class="map-arcs">']
    for n in nodes:
        x, y = project(n["lat"], n["lng"])
        mx, my = (x + hx) / 2, min(y, hy) - abs(x - hx) * 0.18 - 12
        color = RISK_COLORS.get(n["riskLevel"], RISK_COLORS["LOW"])
        out.append(f'<path d="M{x:.1f},{y:.1f} Q{mx:.1f},{my:.1f} {hx:.1f},{hy:.1f}" class="arc" stroke="{color}" data-ip="{escape(str(n.get("ip", "")), quote=True)}" data-risk="{escape(str(n.get("riskLevel", "LOW")), quote=True)}"/>')
    out.append('</g><g class="map-nodes">')
    for n in nodes:
        x, y = project(n["lat"], n["lng"])
        color = RISK_COLORS.get(n["riskLevel"], RISK_COLORS["LOW"])
        radius = min(10, 4 + math.log2(max(1, n["eventCount"])))
        lat, lng = float(n["lat"]), float(n["lng"])
        ip = escape(str(n.get("ip", "")), quote=True)
        city = escape(str(n.get("city", "Unknown")), quote=True)
        country = escape(str(n.get("countryName", "Unknown")), quote=True)
        org = escape(str(n.get("org", "Unknown network")), quote=True)
        risk = escape(str(n.get("riskLevel", "LOW")), quote=True)
        source = escape(str(n.get("source", "unknown")), quote=True)
        radius_km = "" if n.get("accuracyRadiusKm") is None else str(n["accuracyRadiusKm"])
        session_ids = escape(",".join(str(v) for v in n.get("sessionIds", [])[:20]), quote=True)
        tip = f'{n.get("ip", "")} · {n.get("city", "Unknown")}, {n.get("countryName", "Unknown")} · {lat:.5f}, {lng:.5f} · {risk} · {n.get("eventCount", 0)} events'
        out.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="{color}" fill-opacity=".82" '
            f'stroke="{color}" class="node geo-node" tabindex="0" role="button" '
            f'aria-label="Inspect source {ip}, {city}, {country}, threat {risk}" '
            f'data-x="{x:.1f}" data-y="{y:.1f}" data-ip="{ip}" data-city="{city}" data-region="{escape(str(n.get("region", "")), quote=True)}" '
            f'data-country="{country}" data-country-code="{escape(str(n.get("countryCode", "")), quote=True)}" data-org="{org}" '
            f'data-lat="{lat:.6f}" data-lng="{lng:.6f}" data-risk="{risk}" data-score="{int(n.get("threatScore", 0))}" '
            f'data-events="{int(n.get("eventCount", 0))}" data-sessions="{int(n.get("sessionCount", 1))}" '
            f'data-session-ids="{session_ids}" data-start-time="{escape(str(n.get("startTime", "")), quote=True)}" '
            f'data-source="{source}" data-radius-km="{radius_km}" data-private="{str(bool(n.get("isPrivate", False))).lower()}" '
            f'data-vpn="{str(n.get("isVpn", "")).lower()}" data-proxy="{str(n.get("isProxy", "")).lower()}" data-tor="{str(n.get("isTor", "")).lower()}" '
            f'></circle>')
    out.append('</g>')
    out.append(f'<circle cx="{hx:.1f}" cy="{hy:.1f}" r="7" class="honeypot" data-x="{hx:.1f}" data-y="{hy:.1f}"></circle>')
    out.append(f'<text x="{hx + 11:.1f}" y="{hy + 4:.1f}" class="map-label">{escape(honeypot["name"])}</text></svg>')
    return "".join(out)

