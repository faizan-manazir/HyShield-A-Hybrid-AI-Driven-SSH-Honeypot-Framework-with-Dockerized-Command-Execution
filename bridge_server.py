import socket
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from docker_executor import DockerExecutor
from sanitizer import sanitize_output
from ai_refiner import refine_output

HOST = "127.0.0.1"
PORT = 5050

# Store one executor per attacker session (keyed by port)
sessions = {}
sessions_lock = threading.Lock()


def handle_client(conn, addr):
    print(f"[+] New session from {addr}")

    # Get or create executor for this session
    session_key = addr[0]  # use port as unique session key
    with sessions_lock:
        if session_key not in sessions:
            sessions[session_key] = DockerExecutor()
        executor = sessions[session_key]

    try:
        conn.settimeout(5)
        data = conn.recv(4096)
        if data:
            message = data.decode("utf-8", errors="replace").strip()
            terminal_width = 80
            if message.startswith("__HYSHIELD_WIDTH__="):
                metadata, _, command = message.partition("\n")
                try:
                    terminal_width = max(20, min(int(metadata.split("=", 1)[1]), 500))
                except ValueError:
                    terminal_width = 80
                executor.term_cols = terminal_width
                command = command.strip()
            else:
                command = message

            if command:
                print(f"[*] [{addr}] WIDTH: {terminal_width} CMD: {command}")

                raw_output = executor.execute(command)
                clean_output = sanitize_output(raw_output)

                # Only refine if output is non-empty to save time
                if clean_output.strip():
                    final_output = refine_output(command, clean_output)
                else:
                    final_output = clean_output

                if final_output and not final_output.endswith("\n"):
                    final_output += "\n"

                conn.sendall(final_output.encode("utf-8"))

    except Exception as e:
        print(f"[-] Session error {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Session closed {addr}")


def cleanup_sessions():
    """Remove old sessions periodically"""
    import time
    while True:
        time.sleep(300)  # every 5 minutes
        with sessions_lock:
            if len(sessions) > 100:
                sessions.clear()
                print("[*] Session store cleared")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    print(f"[+] Bridge server listening on {HOST}:{PORT}")

    # Start cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_sessions, daemon=True
    )
    cleanup_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        )
        thread.start()


if __name__ == "__main__":
    start_server()
