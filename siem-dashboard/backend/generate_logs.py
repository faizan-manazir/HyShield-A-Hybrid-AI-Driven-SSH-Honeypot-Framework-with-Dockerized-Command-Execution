import json
import time

log_file = r"C:\Users\Faizan\.gemini\antigravity\scratch\hyshield-siem\backend\cowrie.json"

events = []
for i in range(1, 6):
    events.append({
        "eventid": "cowrie.login.failed",
        "timestamp": f"2026-08-24T10:43:0{i}.123456Z",
        "session": "brute123",
        "src_ip": "192.168.1.100",
        "username": "admin",
        "password": "password"
    })

with open(log_file, "a", encoding="utf-8") as f:
    for ev in events:
        f.write(json.dumps(ev) + "\n")
print("Events written.")
