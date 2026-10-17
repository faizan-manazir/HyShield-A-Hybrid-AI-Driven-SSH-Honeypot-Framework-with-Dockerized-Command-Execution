"""All settings in one place. Override any of them with environment variables."""
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("HYSHIELD_DATA", BASE / "data"))
DATA.mkdir(parents=True, exist_ok=True)

# Cowrie JSON log that gets tailed (new lines are picked up automatically)
LOG_PATH = Path(os.environ.get("COWRIE_LOG_PATH", DATA / "cowrie.json"))
DB_PATH = Path(os.environ.get("HYSHIELD_DB", DATA / "hyshield.db"))
SETTINGS_PATH = DATA / "settings.json"

# Safe default: only reachable from this computer
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "2"))

# DEMO_MODE=true gives private/loopback IPs a fake (but stable) country so the map has dots.
DEMO_MODE = os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")
# HYSHIELD_GEO=off stops the app from calling the HTTPS IP geolocation provider.
GEO_LOOKUP = os.environ.get("HYSHIELD_GEO", "on").lower() != "off"

# Where your honeypot physically is (arcs on the map point here)
HONEYPOT = {
    "name": os.environ.get("HONEYPOT_NAME", "HyShield Honeypot Sensor"),
    "lat": float(os.environ.get("HONEYPOT_LAT", "33.6844")),
    "lng": float(os.environ.get("HONEYPOT_LNG", "73.0479")),
    "city": os.environ.get("HONEYPOT_CITY", "Islamabad"),
    "country": os.environ.get("HONEYPOT_COUNTRY", "Pakistan"),
}
# A private IP you want shown as your own analyst/lab machine on the map (optional)
ANALYST_LAN_IP = os.environ.get("ANALYST_LAN_IP", "192.168.100.11")
