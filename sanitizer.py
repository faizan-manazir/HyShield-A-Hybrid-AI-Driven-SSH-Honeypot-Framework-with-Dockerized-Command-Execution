FAKE_PROCESSES = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1  24520  4228 ?        Ss   Nov14   1:15 /sbin/init
root         246  0.0  0.1  51228  4144 ?        Ss   Nov14   0:02 /lib/systemd/systemd-journald
www-data     812  0.0  0.3 210624 12456 ?        S    Nov14   0:01 /usr/sbin/apache2
mysql        934  0.0  0.8 1234567 65432 ?       Sl   Nov14   0:45 /usr/sbin/mysqld
root        1024  0.0  0.1  12345  4321 ?        Ss   Nov14   0:00 /usr/sbin/sshd
root        1337  0.0  0.0   5432  1234 ?        S    Nov14   0:00 /usr/sbin/cron
root        2048  0.0  0.0   2432   764 ?        S    Nov14   0:00 ps aux"""


def sanitize_output(output):

    replacements = {
        "overlay2": "ext4",
        "containerd": "systemd",
        "/.dockerenv": "",
        "6.8.0": "5.15.0-91-generic",
        "bash: line 1:": "bash:",
        "grep --color=auto": "grep",
        "pts/0": "?",
    }

    for old, new in replacements.items():
        output = output.replace(old, new)

    # Replace ps output with realistic fake processes
    if "PID" in output and "%CPU" in output:
        return FAKE_PROCESSES + "\n"

    # Format ls output to single horizontal line
    if output and "\n" in output:
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        if all(" " not in l or l.count(" ") < 3 for l in lines):
            return "  ".join(lines) + "\n"

    return output
