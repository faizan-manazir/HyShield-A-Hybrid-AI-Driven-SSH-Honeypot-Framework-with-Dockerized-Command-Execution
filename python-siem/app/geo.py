"""
IP -> country / city / coordinates.

Public IPs are looked up through ipwho.is over HTTPS in a background thread and cached in
SQLite, so pages never wait for the internet. Until the answer arrives the IP
shows as "Resolving...". Private IPs (192.168.x.x, 127.0.0.1 ...) have no
location and are displayed as private-network sources.
"""
import ipaddress
import json
import queue
import threading
import time
import urllib.request

from . import config, db

_cache = {}                 # ip -> geo dict (good answers)
_failed_until = {}          # ip -> time when we may retry
_pending = set()
_jobs = queue.Queue()
_worker_started = False
_lock = threading.Lock()


def flag(code):
    """'PK' -> the Pakistan flag emoji."""
    if len(code or "") == 2 and code.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in code.upper())
    return "\U0001F310"


def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _make(ip, code, country, city, lat, lng, org, private=False, region="",
          source="unknown", accuracy_radius_km=None, **extra):
    return {"ip": ip, "isPrivate": private, "countryCode": code, "countryName": country,
            "flag": flag(code), "city": city, "region": region, "lat": lat, "lng": lng,
            "org": org, "source": source, "accuracyRadiusKm": accuracy_radius_km, **extra}


def _fetch(ip):
    """Resolve a public IP over HTTPS. Coordinates are estimates, never GPS-precise."""
    # Canonicalize the address before interpolating it; the hostname and scheme are fixed.
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        raise ValueError("Only globally routable IP addresses can be geolocated")
    url = (f"https://ipwho.is/{address.compressed}"
           "?fields=success,message,ip,continent,country,country_code,region,region_code,city,"
           "latitude,longitude,connection,timezone,security")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "HyShield-SIEM/1.0"})
    with urllib.request.urlopen(request, timeout=7) as resp:  # nosec B310 - fixed HTTPS host and canonical IP literal
        data = json.load(resp)
    if data.get("success") is not True:
        raise ValueError(data.get("message") or "IP geolocation lookup failed")
    connection = data.get("connection") or {}
    timezone = data.get("timezone") or {}
    security = data.get("security") or {}
    return _make(ip, data.get("country_code") or "??", data.get("country") or "Unknown country",
                 data.get("city") or "Unknown city", data.get("latitude"), data.get("longitude"),
                 connection.get("org") or connection.get("isp") or "Unknown network",
                 region=data.get("region") or "", source="ipwho.is",
                 accuracy_radius_km=None, continent=data.get("continent"),
                 asn=connection.get("asn"), isp=connection.get("isp"),
                 timezone=timezone.get("id"), isProxy=security.get("proxy"),
                 isVpn=security.get("vpn"), isTor=security.get("tor"))


def _worker():
    conn = db.connect()
    while True:
        ip = _jobs.get()
        try:
            geo = _fetch(ip)
            _cache[ip] = geo
            conn.execute("INSERT OR REPLACE INTO geo_cache VALUES (?,?)", (ip, json.dumps(geo)))
            conn.commit()
        except Exception:
            _failed_until[ip] = time.time() + 60          # try again in a minute
        finally:
            _pending.discard(ip)
        time.sleep(1.5)       # the free API allows ~45 requests per minute


def _queue_lookup(ip):
    global _worker_started
    with _lock:
        if ip in _pending or _failed_until.get(ip, 0) > time.time():
            return
        if not _worker_started:
            threading.Thread(target=_worker, daemon=True, name="geo").start()
            _worker_started = True
        _pending.add(ip)
    _jobs.put(ip)


def _from_db(ip):
    conn = db.connect()
    try:
        row = conn.execute("SELECT data FROM geo_cache WHERE ip=?", (ip,)).fetchone()
    finally:
        conn.close()
    return db.jload(row["data"]) if row else None


def resolve(ip):
    """Always returns a dict. Never blocks on the network."""
    ip = ip or ""
    if ip == config.ANALYST_LAN_IP:
        return _make(ip, "PK", "Pakistan (Analyst LAN)", "Local Workstation (LAN)",
                     config.HONEYPOT["lat"], config.HONEYPOT["lng"],
                     f"Local Analyst Node ({ip})", private=True, region="Intranet", source="configured-lab")

    if not is_private(ip):
        if ip in _cache:
            return _cache[ip]
        saved = _from_db(ip)
        if saved:
            # Older builds cached HTTP-provider records without a source marker.
            # Return them immediately, but queue a refresh through the HTTPS provider.
            if not saved.get("source") or saved.get("source") == "ip-api.com":
                _queue_lookup(ip)
            _cache[ip] = saved
            return saved
        if config.GEO_LOOKUP:
            _queue_lookup(ip)
        return _make(ip, "??", "Unknown (resolving...)", "Resolving...", None, None, "Resolving live ISP...")


    return _make(ip, "LAN", "Private Network", "Local Area Network", None, None,
                 "Private Address Space", private=True, region="Internal", source="private-network")
