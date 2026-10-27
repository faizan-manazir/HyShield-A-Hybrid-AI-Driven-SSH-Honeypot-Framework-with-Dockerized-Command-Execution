# HyShield Docker Execution and Shell-State Fixes

## Purpose

This note records the deployment and interactive-shell issues addressed while bringing up the HyShield Cowrie integration in an isolated Ubuntu VM. It is a troubleshooting and validation record, not a claim that the honeypot is production-hardened.

## Environment used

- Ubuntu Server VM (VirtualBox)
- Python virtual environment under `~/cowrie/venv`
- Cowrie checkout at `~/cowrie`
- Docker container expected by the executor: `fake-ubuntu`
- Container image: `ubuntu:22.04`
- Local command bridge: `127.0.0.1:5050`
- Cowrie test SSH port: `2222`

Actual paths and versions can differ between machines. Confirm them before applying commands.

## Fixes and configuration

### 1. Docker command execution permissions

The executor invokes Docker using the absolute binary path `/usr/bin/docker` and non-interactive sudo (`sudo -n`). This avoids a command handler hanging while waiting for an interactive password prompt.

A host-specific sudoers entry was configured in `/etc/sudoers.d/hyshield-docker`:

```sudoers
faizan ALL=(root) NOPASSWD: /usr/bin/docker
```

Use `visudo` to edit and validate sudoers files. Confirm the actual username and Docker binary path on the target VM. The rule is intentionally **not** shipped as an automatic installer because it grants powerful access.

Validation command:

```bash
sudo -n /usr/bin/docker ps
```

The expected result is a container listing without an interactive authentication prompt.

**Security warning:** Permission to run Docker as root is effectively host-root-equivalent. Keep this on a dedicated, isolated lab VM, protect the account, and do not expose the Docker socket or mount it inside the decoy container. Do not make the Docker socket world-writable.

### 2. Container availability

The executor expects a running container named `fake-ubuntu`. Verify it with:

```bash
sudo -n /usr/bin/docker ps
```

If the container is absent or stopped, inspect it with `sudo -n /usr/bin/docker ps -a` before creating or starting anything. Avoid creating duplicate containers with the same intended role.

### 3. Python import / source-path troubleshooting

The Cowrie integration had an import/startup issue involving the `backend_pool` module. The required module was copied from the HyShield Cowrie source tree into the active Cowrie checkout under `src/backend_pool`. The active checkout and virtual environment must be consistent; do not assume that a successful import in one checkout proves another checkout is configured correctly.

When diagnosing imports, confirm the active interpreter and working tree:

```bash
which python
python -c "import sys; print(sys.executable); print(sys.path)"
```

Run these inside the same virtual environment used to launch Cowrie. Avoid adding broad, permanent `PYTHONPATH` exports until the exact missing module and intended source directory are confirmed.

### 4. Docker executor command handling

The executor was adjusted to:
- use non-interactive sudo for Docker execution;
- preserve a working-directory value between separate SSH commands;
- intercept only simple `cd` commands, allowing compound shell commands such as `cd / && pwd && cd bin && pwd` to run through Bash;
- retain command history handling and the existing output filtering for `ls`;
- capture the final working directory from the same shell execution, rather than running the requested command a second time.

The executor still uses a fixed container name and a command denylist. A substring denylist is not a complete security boundary; it must not be treated as safe isolation against a determined attacker.

### 5. Bridge and Cowrie integration

The command path is:

```text
SSH test client -> Cowrie -> modified llm.py -> 127.0.0.1:5050
  -> bridge_server.py -> docker_executor.py -> fake-ubuntu
  -> output sanitizer -> optional AI refiner -> Cowrie response
```

The bridge should remain bound to loopback unless a deliberate, reviewed architecture requires otherwise. Keep Cowrie, bridge, and container logs available during tests.

### 6. Host configuration is not repository configuration

The following are local VM state and should be configured manually or through a reviewed deployment script, not committed as live host state:
- sudoers entries;
- running Docker containers;
- virtual-environment contents;
- exported secrets or API keys;
- runtime process state.

Never commit a real API key. If a key was previously committed or shared, rotate it and load the replacement from an environment variable or secret store.

## Validation record

The following behaviors were observed during interactive testing in the VM before this documentation was prepared:

| Test | Observed result |
|---|---|
| `sudo -n /usr/bin/docker ps` | Listed the running `fake-ubuntu` container without prompting |
| `cd /tmp`, followed by a separate `pwd` | `/tmp` |
| `echo $HOME` | `/root` |
| `whoami` | `root` |
| `printf 'FIRST\\nSECOND\\n'` | Printed `FIRST` and `SECOND` on separate lines |
| `cd / && pwd && cd bin && pwd` | Displayed the root and `/bin` paths; output formatting was not fully polished |
| `echo $USER` | Empty output; still requires investigation |

The updated repository implementation must be re-tested in the target VM after pulling this branch. The table above records what was observed in the interactive VM; it is not a substitute for running the full validation checklist below against the exact checkout.

## Re-test checklist

Run one test at a time inside an authorized SSH session to Cowrie:

1. `pwd`
2. `cd /tmp`
3. `pwd` — expected: `/tmp`
4. `echo $HOME` — expected: `/root` in this container setup
5. `whoami` — expected: `root` in this container setup
6. `echo $USER` — investigate if empty; do not assume it is set merely because `whoami` works
7. `printf 'FIRST\\nSECOND\\n'` — check multiline output
8. `cd / && pwd && cd bin && pwd` — check compound commands and output formatting
9. Check Cowrie logs for the same command sequence and any exceptions.

On the host, also run:

```bash
cd ~/cowrie
python3 -m py_compile docker_executor.py bridge_server.py
sudo -n /usr/bin/docker ps
ss -tulpn | grep 5050
```

If the shell output, current directory, or telemetry differs from expectations, record the exact command and output before making further changes.

## Known limitations / follow-up

- The empty `$USER` result is unresolved.
- Prompt text and actual working-directory state may not always match; validate with `pwd`.
- Bridge session tracking should be reviewed: keying sessions by client IP can cause different sessions from the same IP to share executor state. Use a stable per-session identifier before relying on session isolation.
- Review output sanitization and optional AI refinement separately; AI-generated shell output must not be treated as authoritative system output.
- Test command execution, failure paths, timeouts, and concurrent sessions before any broader deployment.
- Keep the honeypot isolated from production networks and real credentials.


### 8. Preserve command error output

The executor redirects each command's standard error to standard output before printing the internal working-directory marker. This prevents errors such as `bash: ko: command not found` from being placed after the marker by Python's separate stdout/stderr capture and then discarded during marker parsing.

Validation performed through the active SSH honeypot:
- Unknown commands `koo` and `xyz123` displayed Bash's `command not found` error.
- `ls --invalid-option` displayed its option error and help hint.
- `cat /nonexistent-file-123.txt` displayed the expected missing-file error.

The relevant executor command string uses `{command} 2>&1;` before the working-directory marker. Re-run these tests after pulling the PR branch to verify behavior in the exact checkout.

### 7. Responsive SSH terminal width and `ls` formatting

The interactive Cowrie protocol reads the negotiated PTY size from `self.user.windowSize`, whose shape is `(height, width)`. It passes the width to `LLMClient.get_response(..., terminal_width=width)`. The LLM bridge client sends a small metadata header before the command:

```text
__HYSHIELD_WIDTH__=134
ls
```

`bridge_server.py` parses this header, clamps the width to 20–500 columns, and sets `executor.term_cols` for the command. The executor defaults to 80 columns when no width is available and formats `ls` using the smaller of the reported width and 120 columns to avoid excessively wide output. The terminal width is not hardcoded to a single client size.

**Cowrie checkout integration:** In the active Cowrie checkout, update the interactive shell call in `src/cowrie/llm/protocol.py` (inside `_process_command_with_llm`) to pass the PTY width:

```python
width = getattr(self.user, "windowSize", (24, 80))[1]
d: defer.Deferred[str] = self.llm_client.get_response(
    prompt, terminal_width=width
)
```

This protocol file is not currently tracked in this repository's `cowrie-modifications` snapshot, so apply and validate that change in the active Cowrie checkout as part of deployment.

#### Terminal-width validation record

During the VM test, the bridge logged width 134 for a narrower terminal and 271 for a maximized terminal. The output was then checked in both window sizes; the final screenshots showed aligned columns in narrow and full-screen modes. After the local edits, the user reported the test suite result as **294 passed, 27 warnings, and 5 subtests passed in 10.69 seconds**. This is the reported local result; rerun tests in the exact checkout before release.

Recommended manual check:
1. Run `ls` over the Cowrie SSH session with a narrow terminal.
2. Maximize the terminal and run `ls` again.
3. Resize it again and repeat; verify columns remain readable and adjust.
4. Check the bridge log for the reported `WIDTH` value for each command.
5. Run syntax checks and the project test suite after pulling the PR branch.
