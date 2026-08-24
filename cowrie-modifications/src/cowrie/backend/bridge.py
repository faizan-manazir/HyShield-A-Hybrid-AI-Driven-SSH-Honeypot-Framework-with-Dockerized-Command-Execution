"""
Cowrie Bridge Backend Plugin
Place at: ~/cowrie/src/cowrie/backend/bridge.py

This replaces Cowrie's shell with the Docker+AI hybrid engine.
No monkey-patching — uses Cowrie's clean backend interface.
"""

import socket
from cowrie.core.config import CowrieConfig


BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 5050


class HoneyPotBridgeServer:
    """
    Drop-in backend that forwards commands to the hybrid engine.
    Cowrie calls runCommand() — we forward to bridge and return output.
    """

    def __init__(self, protocol, user):
        self.protocol = protocol
        self.user = user
        self.hostname = CowrieConfig.get(
            "honeypot", "hostname", fallback="web-prod-01"
        )

    def runCommand(self, command):
        """Called by Cowrie for every command the attacker types"""
        output = self._send_to_bridge(command)
        if output:
            self.protocol.writeToChannel(output)

    def _send_to_bridge(self, command):
        """Forward command to bridge server and get response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((BRIDGE_HOST, BRIDGE_PORT))
            sock.sendall((command + "\n").encode("utf-8"))

            response = b""
            sock.settimeout(5)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()
            return response.decode("utf-8", errors="replace")

        except ConnectionRefusedError:
            return f"bash: {command.split()[0] if command.split() else command}: command not found\n"
        except Exception as e:
            return ""
