# 🛡️ HyShield

## Hybrid AI-Driven SSH Honeypot with Dockerized Command Execution and Python SIEM Dashboard

HyShield is a research and educational SSH honeypot framework built around [Cowrie](https://github.com/cowrie/cowrie). It routes interactive shell commands through a custom bridge, executes them in a Docker-based Ubuntu environment, sanitizes output, and can optionally use an AI service to refine selected responses. Cowrie records the interactions as telemetry, which the **Python SIEM dashboard** can ingest for triage and investigation.

> **Research prototype:** Use only in an authorized, isolated lab. A Docker container is not equivalent to a virtual machine, and this project should not be exposed to the public Internet without a careful security review. The current implementation does not provide blockchain-based logging or a verified privacy-preserving analytics mechanism.

## What is in the project?

- **Cowrie SSH honeypot** — accepts SSH sessions and records login attempts, commands, and session activity.
- **HyShield bridge** — connects Cowrie's modified LLM backend to the command-processing pipeline over a local TCP socket.
- **Docker executor** — runs commands in the `fake-ubuntu` container rather than directly in the host shell.
- **Output sanitizer** — removes selected container/environment indicators from command output.
- **Optional AI refiner** — uses the configured Groq API/model to refine output when enabled and available.
- **Python SIEM dashboard** — ingests Cowrie JSON-lines logs, stores events and derived session/alert information in SQLite, and provides an authenticated investigation UI.

## Architecture and data flow

```text
                     Authorized test client / SSH activity
                                      |
                                      v
                            Cowrie SSH Honeypot
                                      |
                                      v
                         Modified Cowrie backend (llm.py)
                                      |
                           local TCP: 127.0.0.1:5050
                                      |
                                      v
                               bridge_server.py
                                      |
                                      v
                               docker_executor.py
                                      |
                                      v
                          fake-ubuntu Docker container
                                      |
                                      v
                               sanitizer.py
                                      |
                                      v
                       optional ai_refiner.py (Groq)
                                      |
                                      v
                           response returned to Cowrie
                                      |
                                      v
                         Cowrie JSON-lines log file
                                      |
                                      v
                        Python SIEM log ingestor
                                      |
                                      v
                           SQLite + correlation rules
                                      |
                                      v
                         Authenticated SIEM dashboard
```

The honeypot command-response path and the SIEM are related but distinct components. The SIEM consumes Cowrie telemetry; it does not execute attacker commands.

## Repository layout

```text
HyShield/
├── README.md
├── start.sh
├── update_password.py
├── bridge_server.py
├── docker_executor.py
├── sanitizer.py
├── ai_refiner.py
├── state.py
├── cowrie-modifications/
│   ├── cowrie.cfg
│   └── src/cowrie/llm/llm.py
└── python-siem/
    ├── run.py
    ├── requirements.txt
    ├── app/
    ├── tests/
    └── docs/
        └── PROJECT_DOCUMENTATION.md
```

The **only supported SIEM dashboard in this repository is `python-siem/`**. The retired legacy Node.js/Next.js dashboard has been removed.

## Requirements

For the honeypot, use an Ubuntu Linux host or isolated VM with:

- Git, Python 3, `python3-venv`, and build tools
- Docker Engine
- Network access for initial package installation
- A Groq API key only if AI refinement is used

For the dashboard:

- Python 3.10 or newer, compatible with the dependencies
- Packages in `python-siem/requirements.txt`
- Read access to a Cowrie JSON-lines log and write access to the SIEM data directory

Keep the honeypot and dashboard on a private lab network. Do not reuse real credentials in the decoy environment.

---

# Step-by-step: deploy the honeypot

These instructions describe the repository's intended Ubuntu workflow. Check the actual configuration and file paths in your checkout before running commands; Cowrie versions and local deployments can differ.

## Step 1 — Install system packages

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv python3-dev \
  build-essential libssl-dev libffi-dev docker.io
```

Verify the tools:

```bash
python3 --version
git --version
docker --version
```

Enable Docker:

```bash
sudo systemctl enable --now docker
sudo systemctl status docker
```

If you grant your account Docker-group access, be aware that membership in the Docker group is effectively a high-privilege host permission. Apply it only to a trusted lab account. After adding a user to the group, sign out and back in before testing access.

## Step 2 — Clone HyShield and Cowrie

```bash
cd ~
git clone https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution.git
git clone https://github.com/cowrie/cowrie.git
```

Create and activate Cowrie's virtual environment:

```bash
cd ~/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

Install HyShield's dependencies into the same environment if required by the current root `requirements.txt`:

```bash
pip install -r ~/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/requirements.txt
```

## Step 3 — Create the isolated execution container

The executor expects a container named `fake-ubuntu`. Create it if it does not already exist:

```bash
docker run -dit --name fake-ubuntu ubuntu:22.04 /bin/bash
docker exec fake-ubuntu bash -c "mkdir -p /var/www/html /home/john /home/deploy /root/projects"
docker exec fake-ubuntu bash -c "touch /var/www/html/index.php /var/www/html/wp-login.php /root/deploy.sh /root/backup.sh"
docker ps
```

The decoy content is for controlled honeypot interaction, not a real production application. Do not mount sensitive host directories or the Docker socket into this container. Review container privileges, capabilities, network access, resource limits, and image updates before deployment.

## Step 4 — Install the HyShield bridge components

Copy the current root-level HyShield engine files into the Cowrie checkout:

```bash
cd ~/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution
cp start.sh update_password.py bridge_server.py docker_executor.py sanitizer.py ai_refiner.py state.py ~/cowrie/
```

If your local checkout has a different directory name, replace the path above with the actual cloned directory. Do not overwrite an existing working installation without backing it up first.

## Step 5 — Apply the Cowrie integration files

Back up the files first:

```bash
cp ~/cowrie/etc/cowrie.cfg ~/cowrie/etc/cowrie.cfg.backup
cp ~/cowrie/src/cowrie/llm/llm.py ~/cowrie/src/cowrie/llm/llm.py.backup
```

Copy the project-provided configuration and modified backend:

```bash
cp ~/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/cowrie-modifications/cowrie.cfg ~/cowrie/etc/cowrie.cfg
cp ~/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/cowrie-modifications/src/cowrie/llm/llm.py ~/cowrie/src/cowrie/llm/llm.py
```

Review the resulting configuration before startup. Ensure the SSH listener, bridge address/port, Cowrie backend, JSON logging, and file paths match the current implementation. Do not blindly replace an existing Cowrie configuration if it contains other required settings.

## Step 6 — Configure AI refinement (optional)

The AI refiner uses the Groq client and a configured model. Create a local environment variable in the shell used to launch HyShield:

```bash
export GROQ_API_KEY="paste-your-own-key-here"
```

Use your own provider key and confirm the model identifier supported by your account. Do not hard-code API keys in source files, commit them to Git, or include them in screenshots and logs. If you do not want external AI processing, configure or disable that path according to the current code and test the non-AI behavior.

## Step 7 — Start the honeypot

Make the launcher executable:

```bash
chmod +x ~/cowrie/start.sh
```

Ensure the container is running:

```bash
docker start fake-ubuntu
docker ps
```

Start HyShield from the Cowrie directory:

```bash
cd ~/cowrie
./start.sh
```

The script is intended to prepare the password, launch the local bridge, and start Cowrie. Keep the process terminal open and inspect startup output for errors. If startup fails, stop and diagnose the specific component rather than repeatedly launching additional copies.

## Step 8 — Validate the honeypot and telemetry

From a separate authorized test machine on your lab network, connect to the configured Cowrie SSH port. The supplied configuration uses port `2222`; do not expose or redirect public port 22 until the host firewall, SSH administration access, and isolation have been reviewed.

After a successful test session, inspect the log:

```bash
ls -l ~/cowrie/var/log/cowrie/
tail -n 50 ~/cowrie/var/log/cowrie/cowrie.json
```

Confirm that new events appear and that the log contains one JSON object per line. Try benign commands such as `pwd`, `whoami`, `id`, and `ls` in your authorized test session. Confirm that commands are routed through the bridge and container, and check the terminal output and Cowrie logs for errors.

Useful diagnostics:

```bash
docker ps -a
ss -tulpn | grep 5050
ps aux | grep bridge_server.py
```

Do not test against systems or networks you do not own or have explicit permission to assess.

---

# Step-by-step: start the Python SIEM dashboard

The SIEM is a separate Python application in `python-siem/`. Start it after Cowrie is writing telemetry, or point it to an existing sample/test log. Run it in a separate terminal or service from the honeypot.

## Step 9 — Install SIEM dependencies

On the host/environment where you want to run the dashboard:

```bash
cd ~/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/python-siem
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows PowerShell, use the equivalent commands:

```powershell
Set-Location .\python-siem
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Step 10 — Point the SIEM at Cowrie's JSON log

By default, the SIEM uses a log under its own `data/` directory. Set `COWRIE_LOG_PATH` to the real Cowrie JSON log before starting it. The SIEM process must be able to read that path.

Linux example:

```bash
export COWRIE_LOG_PATH="$HOME/cowrie/var/log/cowrie/cowrie.json"
python run.py
```

Windows PowerShell example (change the path to your actual log location):

```powershell
$env:COWRIE_LOG_PATH = "C:\path\to\cowrie.json"
python run.py
```

If the dashboard is running on a different host or VM from Cowrie, make the log available through a controlled transfer or shared lab path and ensure permissions are appropriate. Do not expose Cowrie logs publicly merely to connect the dashboard.

Optional: disable external geolocation lookups:

```bash
HYSHIELD_GEO=off python run.py
```

## Step 11 — Complete first-run account setup

Open:

- Dashboard: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- API explorer: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

On a fresh database, create the initial Super Admin at the setup page. Then sign in. Protect the SIEM data directory, database, and authentication secret. The default host is localhost; do not bind to `0.0.0.0` or forward the port beyond the intended lab network without appropriate access controls and HTTPS.

## Step 12 — Verify ingestion and investigate

1. Generate a benign test event by using your authorized SSH session against Cowrie.
2. Confirm a new JSON line appears in `cowrie.json`.
3. Confirm the SIEM process can read the file and that the event appears in the dashboard after ingestion.
4. Open Overview and inspect Investigation Priorities and Recent Alerts.
5. Use Event Explorer to search for the test source IP or session.
6. Open the session timeline and compare the displayed data with the original Cowrie log.
7. Treat scores, ATT&CK mappings, and geolocation as investigation aids, not definitive proof or attribution.
8. Test alert closure and other administrative actions only with test data and the appropriate account role.

If no events appear, verify `COWRIE_LOG_PATH`, file permissions, valid newline-terminated JSON records, and the SIEM console output.

## Dashboard pages

The Python SIEM includes the overview, alert queue, event explorer, actor/session investigation, ATT&CK view, map/geolocation, settings, user management, audit logs, and HTML report export. Exact routes and permissions may change; consult the live `/docs` endpoint and the [Python SIEM documentation](python-siem/docs/PROJECT_DOCUMENTATION.md).

## Troubleshooting

| Symptom | What to check |
|---|---|
| Docker permission denied | Docker service status and account permissions; reconnect after group changes. |
| `fake-ubuntu` missing/stopped | `docker ps -a`; create or start the expected container. |
| Bridge cannot bind to port 5050 | Check for an existing process with `ss -tulpn | grep 5050`. |
| Cowrie cannot import the modified backend | Verify `PYTHONPATH`, virtual environment, and the copied `llm.py`. |
| AI refinement errors | Check the API key, network access, provider quota, and model availability; verify fallback behavior. |
| SIEM shows no events | Check `COWRIE_LOG_PATH`, file read permissions, JSON line validity, and SIEM console logs. |
| Dashboard cannot start on port 8000 | Stop the existing process or configure a different `PORT`. |
| Dashboard login/setup issues | Check the active database/data directory and follow the account recovery process in the SIEM guide. |

For the detailed component walkthrough, troubleshooting notes, configuration reference, security considerations, and manual validation checklist, read **[Complete Project Documentation](python-siem/docs/PROJECT_DOCUMENTATION.md)**.

## Security and responsible use

- Use HyShield only in an authorized research lab.
- Keep SSH management access separate from honeypot access.
- Do not expose the Docker daemon/socket or mount sensitive host files into the decoy container.
- Do not assume Docker alone prevents container escape; use least privilege, resource limits, network restrictions, and a dedicated VM/host where possible.
- Keep API keys, active passwords, real credentials, and sensitive logs out of version control.
- Restrict access to Cowrie logs, SIEM database, exports, and settings.
- Disable external geolocation if sharing public IP addresses with a provider is not permitted.
- Preserve original logs separately when they may be forensic evidence.
- Scores and ATT&CK mappings are heuristic; review the underlying session evidence before drawing conclusions.

## Technology stack

Python · Cowrie · Twisted · Docker · Ubuntu · TCP sockets · Groq API (optional) · FastAPI · Jinja · SQLite · pytest

## License

See [LICENSE](LICENSE) for the repository's license terms.

---

**HyShield — deception, isolated command execution, telemetry collection, and SIEM-assisted investigation.**
