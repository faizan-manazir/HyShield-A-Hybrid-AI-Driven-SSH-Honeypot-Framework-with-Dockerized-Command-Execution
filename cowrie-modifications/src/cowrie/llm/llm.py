# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
import socket
import urllib.parse
from typing import TYPE_CHECKING, Any

from twisted.internet import defer, protocol, reactor
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.endpoints import HostnameEndpoint
from twisted.internet.threads import deferToThread
from twisted.python import failure as tw_failure
from twisted.python import log
from twisted.web.client import (
    Agent,
    HTTPConnectionPool,
    ProxyAgent,
    _HTTP11ClientFactory,
)
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer, IResponse
from zope.interface import implementer

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Generator


@implementer(IBodyProducer)
class StringProducer:
    def __init__(self, body: str) -> None:
        self.body = body.encode("utf-8")
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self) -> None:
        pass

    def resumeProducing(self) -> None:
        pass

    def stopProducing(self) -> None:
        pass


class SimpleResponseReceiver(protocol.Protocol):
    def __init__(self, status_code: int, d: defer.Deferred) -> None:
        self.status_code = status_code
        self.buf = b""
        self.d = d

    def dataReceived(self, data: bytes) -> None:
        self.buf += data

    def connectionLost(
        self, reason: tw_failure.Failure = protocol.connectionDone
    ) -> None:
        self.d.callback((self.status_code, self.buf))


class QuietHTTP11ClientFactory(_HTTP11ClientFactory):
    noisy = False


class LLMClient:
    def __init__(self) -> None:
        self._conn_pool = HTTPConnectionPool(reactor)
        self._conn_pool._factory = QuietHTTP11ClientFactory

        self.api_key = CowrieConfig.get("llm", "api_key", fallback="")
        self.model = CowrieConfig.get("llm", "model", fallback="gpt-4o-mini")
        self.host = CowrieConfig.get(
            "llm", "host", fallback="https://api.openai.com"
        )
        self.path = CowrieConfig.get(
            "llm", "path", fallback="/v1/chat/completions"
        )
        self.max_tokens = CowrieConfig.getint("llm", "max_tokens", fallback=500)
        self.temperature = CowrieConfig.getfloat(
            "llm", "temperature", fallback=0.7
        )
        self.debug = CowrieConfig.getboolean("llm", "debug", fallback=False)

        self.bridge_host = CowrieConfig.get(
            "bridge", "host", fallback="127.0.0.1"
        )
        self.bridge_port = CowrieConfig.getint("bridge", "port", fallback=5050)

        proxy_url = (
            os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy")
            or os.environ.get("HTTP_PROXY")
        )

        self.agent: Agent | ProxyAgent
        if proxy_url:
            parsed = urllib.parse.urlparse(proxy_url)
            proxy_endpoint = HostnameEndpoint(
                reactor, parsed.hostname or "localhost", parsed.port or 8080
            )
            self.agent = ProxyAgent(
                proxy_endpoint, reactor, pool=self._conn_pool
            )
        else:
            self.agent = Agent(reactor, pool=self._conn_pool)

        self.is_anthropic = "anthropic.com" in self.host

    def _build_headers(self) -> Headers:
        if self.is_anthropic:
            return Headers(
                {
                    b"Content-Type": [b"application/json"],
                    b"x-api-key": [self.api_key.encode()],
                    b"anthropic-version": [b"2023-06-01"],
                }
            )
        return Headers(
            {
                b"Content-Type": [b"application/json"],
                b"Authorization": [f"Bearer {self.api_key}".encode()],
            }
        )

    def _format_request_body(self, prompt: list[str]) -> dict:
        system_prompt = prompt[0] if prompt else ""
        messages = []
        for message in prompt[1:]:
            if message.startswith("User:"):
                messages.append(
                    {"role": "user", "content": message[5:].strip()}
                )
            elif message.startswith("System:"):
                messages.append(
                    {"role": "assistant", "content": message[7:].strip()}
                )
            else:
                messages.append({"role": "user", "content": message})

        if self.is_anthropic:
            return {
                "model": self.model,
                "system": system_prompt,
                "messages": messages or [{"role": "user", "content": ""}],
                "max_tokens": self.max_tokens,
            }

        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                *messages,
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

    def _handle_response_body(
        self, response: IResponse
    ) -> Deferred[tuple[int, bytes]]:
        d: Deferred[tuple[int, bytes]] = defer.Deferred()
        response.deliverBody(SimpleResponseReceiver(response.code, d))
        return d

    def _handle_connection_error(
        self, err: tw_failure.Failure
    ) -> tuple[int, bytes]:
        err.trap(Exception)
        return (500, err.getErrorMessage().encode("utf-8"))

    def _send_to_bridge(self, command: str) -> str:
        """Forward command to bridge using fresh connection each time."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.bridge_host, self.bridge_port))
            sock.sendall((command + "\n").encode("utf-8"))

            response = b""
            sock.settimeout(2)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()
            result = response.decode("utf-8", errors="replace")
            return result

        except Exception as e:
            log.err(f"Bridge error: {e}")
            cmd = command.split()[0] if command.split() else command
            return f"bash: {cmd}: command not found\n"

    @inlineCallbacks
    def get_response(
        self, prompt: list[str]
    ) -> Generator[Deferred[Any], Any, str]:
        """
        Extract command from prompt and forward to hybrid Docker+AI bridge.
        """
        command = ""
        for message in reversed(prompt):
            if message.startswith("User:"):
                command = message[5:].strip()
                break
            elif (
                not message.startswith("System:")
                and message not in prompt[:1]
            ):
                command = message.strip()
                break

        if not command:
            return ""

        result = yield deferToThread(self._send_to_bridge, command)

        return result

        yield  # Required for inlineCallbacks
