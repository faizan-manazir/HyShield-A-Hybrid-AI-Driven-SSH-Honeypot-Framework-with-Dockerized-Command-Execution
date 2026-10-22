#!/usr/bin/env python3
"""Seed a fictional, internally consistent web-server filesystem for HyShield.

Run INSIDE the disposable fake-ubuntu container. The script creates only files
that do not already exist, so reruns preserve attacker-created modifications.
All included names, records, and credentials are synthetic.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

FILES: dict[str, tuple[str, int]] = {
    "var/www/html/index.php": ("""<?php
// Fictional landing page for the HyShield decoy web server.
$title = "Northstar Portal";
echo "<!doctype html><html><head><title>" . htmlspecialchars($title) . "</title></head>";
echo "<body><h1>Northstar Operations Portal</h1><p>Internal service portal</p></body></html>";
?>
""", 0o644),
    "var/www/html/login.php": ("""<?php
// Decoy login endpoint. It does not authenticate or store submitted data.
http_response_code(200);
echo "Northstar Portal sign-in";
?>
""", 0o644),
    "var/www/html/robots.txt": ("""User-agent: *
Disallow: /staging/
Disallow: /backup/
Disallow: /internal-status/
""", 0o644),
    "var/www/html/.htaccess": ("""Options -Indexes
ServerSignature Off
""", 0o644),
    "var/www/html/staging/README.txt": ("""Northstar Portal - staging
Deployment checks are performed by the web operations team.
This is a fictional decoy environment; no real customer data is stored here.
""", 0o644),
    "var/www/html/assets/site.css": ("""body { font-family: sans-serif; max-width: 58rem; margin: 3rem auto; color: #263238; }
h1 { color: #24516b; }
""", 0o644),
    "opt/webapp/README.txt": ("""Northstar Portal application notes
---------------------------------
Service: northstar-portal
Runtime: PHP application behind a web server
Owner: deploy
Deployment entry point: /opt/webapp/scripts/deploy.sh
Configuration: /etc/webapp/webapp.conf

This environment and all records are synthetic honeypot artifacts.
""", 0o644),
    "opt/webapp/scripts/deploy.sh": ("""#!/bin/sh
set -eu
printf '%s\\n' 'Deploying Northstar Portal decoy release'
printf '%s\\n' 'Release check complete'
""", 0o750),
    "opt/webapp/scripts/backup.sh": ("""#!/bin/sh
set -eu
printf '%s\\n' 'Starting scheduled decoy backup'
printf '%s\\n' 'Backup simulation complete'
""", 0o750),
    "opt/webapp/backup/README.txt": ("""Backup directory
----------------
Nightly archive names follow: northstar-YYYYMMDD.tar.gz
Archives are intentionally not populated with real data.
""", 0o640),
    "etc/webapp/webapp.conf": ("""# Fictional Northstar Portal service configuration
server_name = web-prod-01
document_root = /var/www/html
application_root = /opt/webapp
log_directory = /var/log/webapp
database_host = db-internal
database_name = northstar_portal
database_user = portal_service
database_password = DECOY_ONLY_NOT_A_REAL_SECRET
""", 0o640),
    "home/deploy/notes.txt": ("""Deployment notes - Northstar Portal
-----------------------------------
- Confirm the maintenance window before publishing a release.
- Check /var/log/webapp/error.log after deployment.
- Staging content is under /var/www/html/staging.
- Database credentials in this environment are synthetic placeholders.
""", 0o640),
    "home/deploy/.bash_history": ("""cd /opt/webapp
ls -la
cat README.txt
./scripts/deploy.sh
tail -n 20 /var/log/webapp/error.log
""", 0o600),
    "home/deploy/deploy.sh": ("""#!/bin/sh
set -eu
/opt/webapp/scripts/deploy.sh
""", 0o750),
    "home/deploy/backup.sh": ("""#!/bin/sh
set -eu
/opt/webapp/scripts/backup.sh
""", 0o750),
    "var/log/webapp/access.log": ("""192.0.2.41 - - [18/Oct/2026:09:12:04 +0000] "GET / HTTP/1.1" 200 418
192.0.2.41 - - [18/Oct/2026:09:12:06 +0000] "GET /assets/site.css HTTP/1.1" 200 112
198.51.100.23 - - [18/Oct/2026:09:18:52 +0000] "GET /robots.txt HTTP/1.1" 200 76
203.0.113.17 - - [18/Oct/2026:09:23:11 +0000] "GET /login.php HTTP/1.1" 200 24
""", 0o640),
    "var/log/webapp/error.log": ("""[Sun Oct 18 09:20:17.000000 2026] [php:notice] [pid 812] Northstar Portal maintenance check started
[Sun Oct 18 09:20:17.100000 2026] [php:notice] [pid 812] Optional analytics endpoint is not configured
""", 0o640),
}

DIRECTORIES = (
    "var/www/html/uploads",
    "var/www/html/assets",
    "var/www/html/staging",
    "opt/webapp/scripts",
    "opt/webapp/config",
    "opt/webapp/backup",
    "home/deploy/projects",
    "var/log/webapp",
    "etc/webapp",
)


def seed(root: Path) -> tuple[int, int]:
    """Create decoy paths under root without overwriting existing files."""
    root = root.resolve()
    created_dirs = 0
    created_files = 0

    for relative in DIRECTORIES:
        directory = root / relative
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            created_dirs += 1

    for relative, (content, mode) in FILES.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            continue
        try:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        created_files += 1

    return created_dirs, created_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        required=True,
        help="Filesystem root to seed. Use / only when running inside fake-ubuntu.",
    )
    args = parser.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        parser.error(f"root must be an existing directory: {root}")
    dirs, files = seed(root)
    print(f"Decoy seed complete: {dirs} directories and {files} new files created.")
    print("Existing files were preserved; all bundled records are synthetic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
