# 🛡️ HyShield

### Hybrid AI-Driven SSH Honeypot Framework with Dockerized Command Execution and Privacy-Preserving Telemetry

HyShield is a hybrid AI-driven SSH honeypot prototype built on top of **Cowrie**. It extends a traditional SSH honeypot with a custom command-processing pipeline that executes attacker commands inside an isolated Docker environment, sanitizes the resulting output, optionally refines responses using AI, and returns realistic responses to the attacker through Cowrie.

> **Research and educational project.** HyShield is designed for authorized cybersecurity research, experimentation, deception technology, and honeypot development.

---

## 📌 Architecture

```text
                         ┌──────────────────┐
                         │    Attacker      │
                         │   SSH Session    │
                         └────────┬─────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │     Cowrie Honeypot     │
                    │       SSH Service       │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Modified Cowrie LLM   │
                    │       Backend           │
                    │        llm.py           │
                    └────────────┬────────────┘
                                 │
                                 │ TCP
                                 ▼
                    ┌─────────────────────────┐
                    │    Custom Bridge Server │
                    │   bridge_server.py      │
                    │        Port 5050        │
                    └────────────┬────────────┘
                                 │
                 ┌───────────────┼────────────────┐
                 │               │                │
                 ▼               ▼                ▼
        ┌────────────────┐ ┌──────────────┐ ┌─────────────┐
        │ Docker Executor│ │  Sanitizer   │ │ AI Refiner  │
        │                │ │              │ │             │
        └───────┬────────┘ └──────┬───────┘ └──────┬──────┘
                │                 │                │
                ▼                 └───────┬────────┘
        ┌─────────────────────┐           │
        │ fake-ubuntu Docker  │           │
        │      Container      │◄──────────┘
        └──────────┬──────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ Sanitized / AI  │
          │ Refined Output  │
          └────────┬────────┘
                   │
                   ▼
              Back to Cowrie
                   │
                   ▼
                Attacker
```

---

## ✨ Features

- 🍯 SSH honeypot based on Cowrie
- 🔄 Custom bridge between Cowrie and the HyShield processing engine
- 🐳 Docker-isolated command execution
- 💻 Real command execution inside a controlled fake Linux environment
- 🧹 Output sanitization to reduce Docker/environment fingerprints
- 🤖 AI-assisted command-output refinement
- 🔐 Randomized honeypot password generation
- 🧠 Session and execution state management
- 📡 TCP bridge communication
- 📊 Cowrie attack logging
- 🐧 Realistic Linux command interaction

---

# 🔄 Command Processing Flow

When an attacker enters a command, HyShield processes it through the following pipeline:

```text
Attacker enters command
        │
        ▼
Cowrie receives command
        │
        ▼
Modified llm.py intercepts/forwards request
        │
        ▼
Bridge Server receives request
        │
        ▼
Docker Executor executes command
        │
        ▼
fake-ubuntu container
        │
        ▼
Command output generated
        │
        ▼
Sanitizer removes unwanted traces
        │
        ▼
AI Refiner processes output
        │
        ▼
Response sent back through Bridge
        │
        ▼
Cowrie displays response
        │
        ▼
Attacker receives output
```

---

# 📁 Repository Structure

```text
HyShield/
│
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
│
├── start.sh
├── update_password.py
├── bridge_server.py
├── docker_executor.py
├── sanitizer.py
├── ai_refiner.py
├── state.py
│
└── cowrie-modifications/
    │
    ├── cowrie.cfg
    │
    └── src/
        └── cowrie/
            ├── llm/
            │   └── llm.py
```

---

# 📄 Core Components

## `start.sh`

The main startup script.

It performs the startup workflow for HyShield:

1. Sets the required Python path
2. Randomizes the honeypot password
3. Saves the active password
4. Activates the Cowrie virtual environment
5. Starts the Docker container
6. Starts the bridge server
7. Launches Cowrie

---

## `update_password.py`

Selects a random password from the configured honeypot credentials and updates the active authentication configuration.

The currently selected password is saved to:

```text
active_password.txt
```

Check the active password:

```bash
cat ~/cowrie/active_password.txt
```

---

## `bridge_server.py`

The central communication component of HyShield.

It receives requests from the modified Cowrie backend and coordinates command processing with the custom execution pipeline.

The bridge server runs on the configured local TCP port, currently:

```text
localhost:5050
```

---

## `docker_executor.py`

Executes attacker commands inside the isolated Docker environment.

HyShield uses a container named:

```text
fake-ubuntu
```

This prevents commands from being executed directly on the host system.

---

## `sanitizer.py`

Processes command output before it is returned to the attacker.

Its purpose is to reduce unwanted implementation details and environment fingerprints that could reveal the underlying execution environment.

---

## `ai_refiner.py`

Provides AI-assisted response processing.

The AI component can refine command responses before they are returned through Cowrie.

---

## `state.py`

Manages execution or session state required by the command-processing pipeline.

This helps preserve interaction context across commands.

---

## `cowrie-modifications/cowrie.cfg`

This is the **modified Cowrie configuration from the working HyShield prototype**.

It contains the custom configuration required for the Cowrie-to-HyShield integration.

Do not replace this file with a default Cowrie configuration without reapplying the required modifications.

---

## `cowrie-modifications/src/cowrie/llm/llm.py`

This is the **modified Cowrie LLM backend used by HyShield**.

It is a critical part of the integration between Cowrie and the custom bridge server.

The processing flow depends on this modified file:

```text
Cowrie
   ↓
Modified llm.py
   ↓
HyShield Bridge Server
   ↓
Docker Execution Pipeline
```

Do not replace it with the default Cowrie version unless you intentionally remove the HyShield integration.

---

# 🖥️ System Requirements

- Ubuntu Linux
- Python 3
- Python virtual environment support
- Docker
- Git
- Internet connection for initial package installation
- A valid API configuration if AI refinement is enabled

---

# ⚙️ Installation

## 1. Update Ubuntu

```bash
sudo apt update
sudo apt upgrade -y
```

---

## 2. Install Required System Packages

```bash
sudo apt install -y \
python3 \
python3-pip \
python3-venv \
python3-dev \
git \
docker.io \
build-essential \
libssl-dev \
libffi-dev
```

Verify Python:

```bash
python3 --version
```

Verify Docker:

```bash
docker --version
```

Verify Git:

```bash
git --version
```

---

# 🐳 Docker Setup

Enable and start Docker:

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

Check Docker:

```bash
sudo systemctl status docker
```

Check Docker containers:

```bash
docker ps -a
```

If your user cannot run Docker commands without `sudo`, add the current user to the Docker group:

```bash
sudo usermod -aG docker $USER
```

After running this command, log out and log back in.

You can verify Docker access with:

```bash
docker ps
```

---

# 🍯 Cowrie Installation

## 1. Clone Cowrie

```bash
cd ~
git clone https://github.com/cowrie/cowrie.git
```

Enter the Cowrie directory:

```bash
cd ~/cowrie
```

---

## 2. Create the Python Virtual Environment

```bash
python3 -m venv cowrie-env
```

Activate it:

```bash
source cowrie-env/bin/activate
```

Your terminal should now show the active virtual environment.

---

## 3. Upgrade Pip

```bash
pip install --upgrade pip
```

---

## 4. Install Cowrie Dependencies

```bash
pip install -r requirements.txt
```

Install Cowrie:

```bash
pip install -e .
```

---

## 5. Create Required Runtime Directories

```bash
mkdir -p ~/cowrie/var/log/cowrie
mkdir -p ~/cowrie/var/run
```

---

# 🛡️ Install HyShield

Clone the HyShield repository:

```bash
cd ~
git clone https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution.git
```

Enter the project directory:

```bash
cd ~/HyShield
```

---

# 📦 Install HyShield Dependencies

Activate the Cowrie environment:

```bash
source ~/cowrie/cowrie-env/bin/activate
```

Install the HyShield requirements:

```bash
pip install -r ~/HyShield/requirements.txt
```

---

# 🔧 Install the HyShield Engine Files

Copy the custom HyShield files into the Cowrie directory:

```bash
cp ~/HyShield/bridge_server.py ~/cowrie/
```

```bash
cp ~/HyShield/docker_executor.py ~/cowrie/
```

```bash
cp ~/HyShield/sanitizer.py ~/cowrie/
```

```bash
cp ~/HyShield/ai_refiner.py ~/cowrie/
```

```bash
cp ~/HyShield/state.py ~/cowrie/
```

```bash
cp ~/HyShield/update_password.py ~/cowrie/
```

```bash
cp ~/HyShield/start.sh ~/cowrie/
```

Make the startup script executable:

```bash
chmod +x ~/cowrie/start.sh
```

---

# ⚠️ Apply the Modified Cowrie Configuration

The HyShield repository contains the **working modified configuration**.

First, back up the existing Cowrie configuration:

```bash
cp ~/cowrie/etc/cowrie.cfg ~/cowrie/etc/cowrie.cfg.backup
```

Then copy the HyShield configuration:

```bash
cp ~/HyShield/cowrie-modifications/cowrie.cfg \
~/cowrie/etc/cowrie.cfg
```

---

# ⚠️ Apply the Modified `llm.py`

The modified `llm.py` is required for the Cowrie-to-bridge integration.

Back up the original file:

```bash
cp ~/cowrie/src/cowrie/llm/llm.py \
~/cowrie/src/cowrie/llm/llm.py.backup
```

Copy the HyShield version:

```bash
cp ~/HyShield/cowrie-modifications/src/cowrie/llm/llm.py \
~/cowrie/src/cowrie/llm/llm.py
```

---

# 🔧 Apply `bridge.py` If Included

If your repository contains:

```text
cowrie-modifications/src/cowrie/backend/bridge.py
```

copy it into Cowrie:

```bash
mkdir -p ~/cowrie/src/cowrie/backend
```

```bash
cp ~/HyShield/cowrie-modifications/src/cowrie/backend/bridge.py \
~/cowrie/src/cowrie/backend/bridge.py
```

---

# 🤖 AI Configuration

HyShield can use an AI backend for response refinement.

If the included working configuration requires an API key, configure it according to the code and configuration files in the project.

Do not upload secrets to GitHub.

Recommended approaches include environment variables or a local `.env` file.

For example:

```bash
export YOUR_API_KEY="your-api-key-here"
```

Never commit a real API key:

```text
❌ Do not upload API keys
❌ Do not upload .env files
❌ Do not upload private credentials
```

---

# 🐳 Prepare the Fake Ubuntu Container

HyShield expects the Docker execution environment used by the working prototype.

The container name is:

```text
fake-ubuntu
```

Check whether it exists:

```bash
docker ps -a
```

Look specifically for:

```text
fake-ubuntu
```

Start the container:

```bash
docker start fake-ubuntu
```

Verify that it is running:

```bash
docker ps
```

Expected output should include the container:

```text
fake-ubuntu
```

---

# 🚀 Starting HyShield

Go to the Cowrie directory:

```bash
cd ~/cowrie
```

Run:

```bash
./start.sh
```

The expected startup flow is:

```text
┌─────────────────────────────┐
│      HyShield start.sh      │
└──────────────┬──────────────┘
               │
               ▼
     Update Random Password
               │
               ▼
      Save Active Password
               │
               ▼
    Activate Cowrie Environment
               │
               ▼
     Start fake-ubuntu Docker
               │
               ▼
       Start Bridge Server
               │
               ▼
    Open Separate Cowrie Terminal
               │
               ▼
          Start Cowrie
```

---

# 🖥️ Manual Startup

If you want to start every component manually, follow the sequence below.

## Terminal 1 — Start Docker

Check the container:

```bash
docker ps -a
```

Start it:

```bash
docker start fake-ubuntu
```

Verify it:

```bash
docker ps
```

---

## Terminal 2 — Start Bridge Server

```bash
cd ~/cowrie
```

Activate the virtual environment:

```bash
source cowrie-env/bin/activate
```

Set the Python path:

```bash
export PYTHONPATH=~/cowrie/src
```

Start the bridge:

```bash
python3 bridge_server.py
```

The bridge server should remain running.

---

## Terminal 3 — Start Cowrie

```bash
cd ~/cowrie
```

Activate the environment:

```bash
source cowrie-env/bin/activate
```

Set the Python path:

```bash
export PYTHONPATH=~/cowrie/src
```

Start Cowrie:

```bash
twistd -n cowrie
```

---

# 🔐 Check the Active Honeypot Password

The startup script generates/selects the active password.

Check it with:

```bash
cat ~/cowrie/active_password.txt
```

The output displays the password currently configured for the honeypot.

---

# 📡 Check the Bridge Server

Check whether port `5050` is listening:

```bash
ss -tulpn | grep 5050
```

Check for the bridge process:

```bash
ps aux | grep bridge_server.py
```

---

# 🐳 Check Docker

View running containers:

```bash
docker ps
```

View all containers:

```bash
docker ps -a
```

Enter the fake environment:

```bash
docker exec -it fake-ubuntu bash
```

Stop the container:

```bash
docker stop fake-ubuntu
```

Restart the container:

```bash
docker restart fake-ubuntu
```

---

# 📊 View Cowrie Logs

Follow the attack log in real time:

```bash
tail -f ~/cowrie/var/log/cowrie/cowrie.json
```

View the latest 50 events:

```bash
tail -n 50 ~/cowrie/var/log/cowrie/cowrie.json
```

Search for login attempts:

```bash
grep "login" ~/cowrie/var/log/cowrie/cowrie.json
```

Search for commands:

```bash
grep "command" ~/cowrie/var/log/cowrie/cowrie.json
```

---

# 🧪 Testing HyShield

After starting the system, connect to the configured SSH honeypot from an authorized test environment.

The expected interaction flow is:

```text
SSH Connection
     │
     ▼
Cowrie Login
     │
     ▼
Authentication Attempt
     │
     ▼
Command Entered
     │
     ▼
Modified llm.py
     │
     ▼
Bridge Server
     │
     ▼
Docker Execution
     │
     ▼
Output Sanitization
     │
     ▼
AI Refinement
     │
     ▼
Response Displayed
```

Try normal Linux commands after logging into the honeypot, such as:

```text
pwd
```

```text
whoami
```

```text
ls
```

```text
uname -a
```

```text
id
```

Observe:

1. Cowrie receives the command
2. The bridge processes the request
3. The Docker environment executes the command
4. The output is sanitized
5. AI refinement is applied when configured
6. The response is returned to the SSH session

---

# 🛠️ Troubleshooting

## Docker Permission Denied

If you see a Docker permission error:

```bash
sudo usermod -aG docker $USER
```

Then log out and log in again.

---

## `fake-ubuntu` Container Not Found

Check available containers:

```bash
docker ps -a
```

If the expected container is missing, recreate the Docker environment used by your working HyShield prototype before starting the project.

---

## Bridge Server Does Not Start

Check whether the port is already occupied:

```bash
ss -tulpn | grep 5050
```

Find the old bridge process:

```bash
ps aux | grep bridge_server.py
```

Stop old bridge processes if required:

```bash
pkill -f bridge_server.py
```

Start the bridge again:

```bash
cd ~/cowrie
source cowrie-env/bin/activate
export PYTHONPATH=~/cowrie/src
python3 bridge_server.py
```

---

## Cowrie Cannot Import Custom Modules

Make sure the Python path is set:

```bash
export PYTHONPATH=~/cowrie/src
```

Then activate the environment:

```bash
source ~/cowrie/cowrie-env/bin/activate
```

Start Cowrie:

```bash
cd ~/cowrie
twistd -n cowrie
```

---

## Cowrie Stops Immediately

Run it manually to see the error:

```bash
cd ~/cowrie
```

```bash
source cowrie-env/bin/activate
```

```bash
export PYTHONPATH=~/cowrie/src
```

```bash
twistd -n cowrie
```

Read the terminal output before making further changes.

---

## Check the Modified Files

Verify that the HyShield configuration was copied:

```bash
ls -l ~/cowrie/etc/cowrie.cfg
```

Check the modified LLM backend:

```bash
ls -l ~/cowrie/src/cowrie/llm/llm.py
```

Compare with backups if created:

```bash
diff ~/cowrie/etc/cowrie.cfg \
~/cowrie/etc/cowrie.cfg.backup
```

```bash
diff ~/cowrie/src/cowrie/llm/llm.py \
~/cowrie/src/cowrie/llm/llm.py.backup
```

---

# 🔒 Security Considerations

HyShield is designed to isolate attacker command execution from the host system.

The intended security boundary is:

```text
Host System
    │
    ├── Cowrie Honeypot
    │
    ├── HyShield Bridge Server
    │
    └── Docker Isolation Layer
            │
            ▼
      fake-ubuntu Container
            │
            ▼
      Attacker Commands
```

However, Docker containers are not equivalent to complete virtual-machine isolation. Deploy honeypots carefully and avoid exposing sensitive host resources.

Recommended practices:

- Run the project on a dedicated machine or isolated environment
- Do not mount sensitive host directories into the honeypot container
- Do not expose Docker sockets to the container
- Do not store API keys in the repository
- Monitor Cowrie logs
- Restrict unnecessary network access
- Use the project only in authorized environments

---

# 📚 Technologies Used

- **Python**
- **Cowrie**
- **Docker**
- **Twisted**
- **Linux**
- **TCP Socket Communication**
- **Groq / AI API integration**
- **SSH Honeypot Technology**

---

# 🎯 Project Purpose

HyShield explores a more dynamic approach to SSH honeypot interaction.

Traditional honeypots often rely heavily on static or predefined command responses. HyShield introduces a processing pipeline where commands can be handled by an isolated execution environment and then processed before the response is returned.

The goal is to combine:

```text
Honeypot Deception
        +
Container Isolation
        +
Dynamic Command Execution
        +
Output Sanitization
        +
AI-Assisted Refinement
        =
       HyShield
```

---

# ⚠️ Ethical Use

This project is intended for:

- Authorized cybersecurity research
- Academic research
- Honeypot experimentation
- Security training
- Controlled laboratory environments
- Defensive security research

Do not use this project to access systems without authorization.

---

# 🙏 Acknowledgments

HyShield is built around the Cowrie honeypot framework and extends it with custom components for bridge-based command processing, Docker execution, sanitization, session state handling, and AI-assisted response refinement.

Special thanks to the open-source communities behind:

- Cowrie
- Docker
- Python
- Twisted
- Groq

---

# 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>🛡️ HyShield</b><br>
  Hybrid AI-Driven SSH Honeypot Framework
</p>
