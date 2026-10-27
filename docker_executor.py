import subprocess
import os

DOCKER_BIN = "/usr/bin/docker"
CONTAINER = "fake-ubuntu"

BLOCKED_COMMANDS = [
    "shutdown", "reboot", "halt",
    "poweroff", "rm -rf /", "mkfs",
    "dd if=/dev/zero", ":(){:|:&};:"
]

# Files to hide that reveal this is not a real production server
HIDDEN_FILES = {
    "[", "helpztags", "lcf", "savelog", "tempfile",
    "gnome-shell", "gnome-session", "gnome-keyring",
    "gnome-calendar", "gnome-clocks", "gnome-calculator",
    "gnome-characters", "gnome-control-center", "gnome-disks",
    "gnome-extensions", "gnome-font-viewer", "gnome-help",
    "gnome-keyring-3", "gnome-keyring-daemon",
    "gnome-language-selector", "gnome-logs",
    "gnome-service-client", "gnome-session-inhibit",
    "gnome-session-quit", "gnome-shell-extension-tool",
    "gnome-shell-test-tool", "gnome-text-editor",
    "gnome-thumbnail-font", "gnome-www-browser",
    "docker", "docker-init",
    "nautilus", "nautilus-autorun-software", "nautilus-sendto",
    "deja-dup", "thunderbird", "yelp",
    "xdg-user-dir", "xdg-user-dirs-update",
    "xrandr", "xrdb", "xrefresh", "xset", "xsetmode",
    "xsetpointer", "xsetroot", "xstdcmap", "xsubpp",
    "xvidtune", "xviinfo", "xwininfo",
    "gcr-viewer", "gjs", "gjs-console", "glycin-thumbnailer",
    "gmake", "glib-compile-schemas",
    "nm-connection-editor", "nm-online",
    "hp-align", "hp-check", "hp-clean", "hp-colorcal",
    "hp-config_usb_printer", "hp-doctor", "hp-firmware",
    "hp-info", "hp-levels", "hp-logcapture", "hp-makeuri",
    "hp-pkservice", "hp-plugin", "hp-plugin-ubuntu",
    "hp-probe", "hp-query", "hp-scan", "hp-setup",
    "hp-testpage", "hp-timedate",
    "hd", "hciattool", "hciconfig", "hcitool",
    "hex2hcd", "hexdump", "hiperdcode",
    "py3clean", "py3compile", "py3versions",
    "pydoc3", "pydoc3.10", "pygettext3", "pygettext3.10",
    "python3.10", "pybabel", "pybabel-python3",
    "pygmentize", "pyserial-miniterm", "pyserial-ports",
    "pzstd", "qmi-firmware-update", "qmi-network",
    "qmicli", "qpdldecode", "quirks-handler",
    "newgrp", "cvtsudoers.ws",
}


def run_docker(cmd, cwd="/root", cols=220):
    """Run a command in the Docker container."""
    full_cmd = f"cd {cwd} && COLUMNS={cols} TERM=xterm-256color {cmd}"
    result = subprocess.run(
        ["sudo", "-n", DOCKER_BIN, "exec", "-i", CONTAINER, "bash", "-c", full_cmd],
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout + result.stderr


def filter_ls_output(raw_output):
    """Remove hidden files from ls output lines."""
    filtered = []
    for line in raw_output.split("\n"):
        # Each line may have multiple space-separated items (from ls -C)
        items = line.split()
        kept = [item for item in items if item not in HIDDEN_FILES]
        if kept:
            filtered.append("  ".join(kept))
    return "\n".join(filtered)


class DockerExecutor:

    def __init__(self):
        self.current_directory = "/root"
        self.history = []
        # Get terminal width dynamically
        self.term_cols = 220

    def execute(self, command):
        command = command.strip()
        if not command:
            return ""

        for blocked in BLOCKED_COMMANDS:
            if blocked in command:
                return "Operation not permitted\\n"

        # Intercept only simple cd commands. Compound commands must run in bash
        # so sequences such as "cd / && pwd && cd bin && pwd" work naturally.
        has_shell_operators = any(token in command for token in (
            "&&", "||", ";", "|", "$(", "`"
        ))
        if command == "cd" or (command.startswith("cd ") and not has_shell_operators):
            output = self._handle_cd(command)
            self.history.append(command)
            return output

        if command == "history":
            return self._handle_history()

        if command == "ls" or command.startswith("ls "):
            return self._handle_ls(command)

        # Run the requested command once and capture its final working directory
        # from the same shell process.
        marker = "__HYSHIELD_CWD__"
        full_cmd = (
            f"cd '{self.current_directory}' && "
            f"COLUMNS={self.term_cols} TERM=xterm-256color {command}; "
            f"printf '\\n{marker}%s\\n' \"$PWD\""
        )
        result = subprocess.run(
            ["sudo", "-n", DOCKER_BIN, "exec", "-i", CONTAINER, "bash", "-c", full_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        self.history.append(command)
        combined = result.stdout + result.stderr

        # Remove the internal marker from the output shown to the SSH client.
        if marker in combined:
            before, after = combined.rsplit(marker, 1)
            self.current_directory = after.strip().splitlines()[0] if after.strip() else self.current_directory
            combined = before.rstrip("\\n")
            if combined:
                combined += "\\n"

        return combined

    def _handle_ls(self, command):
        """
        Let Docker handle ls formatting natively with correct terminal width.
        Filter out unrealistic files afterward.
        """
        parts = command.split(maxsplit=1)
        args = parts[1] if len(parts) > 1 else ""

        # Resolve path
        if args and not args.startswith("-"):
            path = args
            if not path.startswith("/"):
                path = f"{self.current_directory.rstrip('/')}/{path}"
            ls_cmd = f"ls --color=never '{path}'"
        else:
            ls_cmd = f"ls --color=never {args}"

        # Run with full terminal width so Docker formats columns correctly
        full_cmd = (
            f"cd {self.current_directory} && "
            f"COLUMNS={self.term_cols} TERM=xterm-256color {ls_cmd}"
        )

        result = subprocess.run(
            ["sudo", "-n", DOCKER_BIN, "exec", "-i", CONTAINER, "bash", "-c", full_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )

        self.history.append(command)
        raw = result.stdout + result.stderr

        # Filter line by line
        lines = raw.split("\n")
        filtered_lines = []
        for line in lines:
            if not line.strip():
                filtered_lines.append(line)
                continue
            # Split by 2+ spaces to get individual filenames
            items = [
                item.strip() for item in line.split("  ")
                if item.strip() and item.strip() not in HIDDEN_FILES
            ]
            if items:
                filtered_lines.append("  ".join(items))

        return "\n".join(filtered_lines)

    def _handle_cd(self, command):
        parts = command.split(maxsplit=1)
        target = "/root" if len(parts) == 1 else parts[1]

        if not target.startswith("/"):
            base = self.current_directory.rstrip("/")
            target = f"{base}/{target}"

        target = target.replace("//", "/")

        result = subprocess.run(
            ["sudo", "-n", DOCKER_BIN, "exec", "-i", CONTAINER,
             "bash", "-c", f"cd '{target}' && pwd"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            self.current_directory = result.stdout.strip()
            return ""
        else:
            return (
                result.stderr
                or f"bash: cd: {target}: No such file or directory\n"
            )

    def _handle_history(self):
        return "\n".join(
            f"  {i+1}  {cmd}"
            for i, cmd in enumerate(self.history)
        ) + "\n"
