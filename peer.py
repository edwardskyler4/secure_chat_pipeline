#!/usr/bin/env python3
"""Run a listener or connector for an encrypted two-peer terminal conversation."""

from __future__ import annotations

import argparse
import math
import queue
import socket
import sys
import threading
import time
from collections.abc import Callable

try:
    from secure_channel import PeerDisconnected, ProtocolError, SecureChannel
except ModuleNotFoundError as exc:
    if exc.name and exc.name.startswith("cryptography"):
        print(
            "Missing cryptography dependency. Run: python -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    raise


MAX_TEXT_LENGTH = 8_000
REQUEST_TYPES = {"SEND", "PING", "QUIT"}
HELP = (
    "Type a message to send it. Commands: /ping, /quit (end session), "
    "/exit (stop program), /help."
)
_output_lock = threading.Lock()


def emit(text: str) -> None:
    with _output_lock:
        print(text, flush=True)


def display_text(text: str) -> str:
    """Keep remote text from inserting terminal escape/control sequences."""
    return "".join(
        char if char.isprintable() else f"\\u{ord(char):04x}" for char in text
    )


class Console:
    """One input thread survives reconnects; network events never wait for Enter."""

    def __init__(self) -> None:
        self.lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._read, name="console", daemon=True).start()

    def _read(self) -> None:
        for line in sys.stdin:
            self.lines.put(line.rstrip("\r\n"))
        self.lines.put(None)


class PeerSession:
    """Dispatch requests and correlate replies while the main thread reads input."""

    def __init__(self, channel: SecureChannel, output: Callable[[str], None] = emit):
        self.channel = channel
        self.output = output
        self.stopped = threading.Event()
        self.failed = False
        self._pending: dict[int, str] = {}
        self._pending_lock = threading.Lock()
        self._next_id = 1
        self._receiver = threading.Thread(
            target=self._receive, name="peer-receiver", daemon=True
        )

    def start(self) -> None:
        self._receiver.start()

    def request(self, kind: str, payload: str | None = None) -> None:
        if kind not in REQUEST_TYPES:
            raise ValueError("Unknown request type.")
        if kind == "SEND":
            if not isinstance(payload, str) or not 0 < len(payload) <= MAX_TEXT_LENGTH:
                raise ValueError(f"Messages must contain 1 to {MAX_TEXT_LENGTH} characters.")
        elif payload is not None:
            raise ValueError("PING and QUIT require a null payload.")
        with self._pending_lock:
            request_id = self._next_id
            self._next_id += 1
            self._pending[request_id] = kind
        self.channel.send({"type": kind, "payload": payload, "id": request_id})

    def _handle(self, message: dict) -> None:
        kind = message.get("type")
        request_id = message.get("id")
        valid_id = type(request_id) is int and 0 < request_id < 2**63
        if kind in ("RESPONSE", "ERROR"):
            if not valid_id or not isinstance(message.get("payload"), str):
                raise ProtocolError("Invalid response fields.")
            with self._pending_lock:
                expected = self._pending.pop(request_id, None)
            if expected is None or message.get("request") != expected:
                raise ProtocolError("Response does not match a pending request.")
            if kind == "RESPONSE" and expected == "PING" and message["payload"] != "PONG":
                raise ProtocolError("Expected PONG in the ping response.")
            if kind == "ERROR":
                self.output(f"Peer error: {display_text(message['payload'])}")
            elif expected == "PING":
                self.output("Peer: PONG")
            elif expected == "SEND":
                self.output(f"Message delivered (#{request_id}).")
            if expected == "QUIT":
                self.stopped.set()
            return

        error = None
        if not valid_id:
            error = "Requests require a positive integer id."
        elif not isinstance(kind, str) or kind not in REQUEST_TYPES:
            error = "Supported request types are SEND, PING, and QUIT."
        elif "payload" not in message:
            error = "Requests require a payload field."
        elif kind == "SEND":
            payload = message["payload"]
            if not isinstance(payload, str) or not 0 < len(payload) <= MAX_TEXT_LENGTH:
                error = f"SEND payload must contain 1 to {MAX_TEXT_LENGTH} characters."
        elif message["payload"] is not None:
            error = "PING and QUIT require a null payload."

        if error:
            self.channel.send(
                {
                    "type": "ERROR",
                    "id": request_id if valid_id else None,
                    "request": kind if isinstance(kind, str) else None,
                    "payload": error,
                }
            )
            return

        if kind == "SEND":
            self.output(f"Peer: {display_text(message['payload'])}")
            reply = "Message received."
        elif kind == "PING":
            self.output("Peer sent PING.")
            reply = "PONG"
        else:
            self.output("Peer ended the session.")
            reply = "Goodbye."
        self.channel.send(
            {"type": "RESPONSE", "id": request_id, "request": kind, "payload": reply}
        )
        if kind == "QUIT":
            self.stopped.set()

    def _receive(self) -> None:
        try:
            while not self.stopped.is_set():
                self._handle(self.channel.receive())
        except PeerDisconnected:
            if not self.stopped.is_set():
                self.output("Peer disconnected.")
        except (OSError, ProtocolError) as exc:
            if not self.stopped.is_set():
                self.failed = True
                self.output(f"Session error: {exc}")
        finally:
            self.stopped.set()
            self.channel.close()

    def close(self) -> None:
        self.stopped.set()
        self.channel.close()
        if self._receiver.is_alive():
            self._receiver.join(timeout=1)


def interact(session: PeerSession, console: Console, quit_timeout: float) -> bool:
    """Return True when /exit or EOF requests that the entire program stop."""
    exit_program = False
    quit_deadline = None
    session.start()
    try:
        while not session.stopped.is_set():
            if quit_deadline is not None:
                if time.monotonic() >= quit_deadline:
                    emit("Timed out waiting for QUIT acknowledgement; closing session.")
                    session.failed = True
                    break
                session.stopped.wait(0.1)
                continue
            try:
                line = console.lines.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None or line.strip() in ("/quit", "/exit"):
                exit_program = line is None or line.strip() == "/exit"
                session.request("QUIT")
                quit_deadline = time.monotonic() + quit_timeout
            elif not line.strip():
                continue
            elif line.strip() == "/help":
                emit(HELP)
            elif line.strip() == "/ping":
                session.request("PING")
            elif line.startswith("/"):
                emit("Unknown command. Use /help for commands.")
            else:
                try:
                    session.request("SEND", line)
                except ValueError as exc:
                    emit(str(exc))
    except (OSError, ProtocolError) as exc:
        if not session.stopped.is_set():
            session.failed = True
            emit(f"Session error: {exc}")
    finally:
        session.close()
    return exit_program


def idle_exit(console: Console) -> bool:
    """Process console input while listening, including shutdown without a peer."""
    while True:
        try:
            line = console.lines.get_nowait()
        except queue.Empty:
            return False
        if line is None or line.strip() in ("/quit", "/exit"):
            return True
        if line.strip():
            emit(HELP if line.strip() == "/help" else "No peer connected yet.")


def serve(args: argparse.Namespace, console: Console) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(1)
        listener.settimeout(0.2)
        emit(f"Listening on {args.host}:{listener.getsockname()[1]}. /exit stops the server.")
        while not idle_exit(console):
            try:
                sock, address = listener.accept()
            except socket.timeout:
                continue
            with sock:
                emit(f"Connected from {address[0]}:{address[1]}; starting handshake.")
                try:
                    channel = SecureChannel.establish(sock, "server", args.timeout)
                except (OSError, ProtocolError, PeerDisconnected) as exc:
                    emit(f"Handshake failed: {exc}")
                    continue
                emit("Encrypted session established.")
                emit(HELP)
                if interact(PeerSession(channel), console, args.timeout):
                    return 0
            emit("Waiting for another peer.")
    return 0


def connect(args: argparse.Namespace, console: Console) -> int:
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        channel = SecureChannel.establish(sock, "client", args.timeout)
        # The timeout bounds connection/handshake operations, not user thinking time.
        sock.settimeout(None)
        emit("Encrypted session established.")
        emit(HELP)
        session = PeerSession(channel)
        interact(session, console, args.timeout)
        return int(session.failed)


def port_number(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535.")
    return port


def positive_timeout(value: str) -> float:
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("Timeout must be a positive, finite number.")
    return timeout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--host", default="127.0.0.1", help="IPv4 address (default: %(default)s)")
    parser.add_argument("--port", default=7878, type=port_number, help="TCP port (default: %(default)s)")
    parser.add_argument(
        "--timeout", default=10.0, type=positive_timeout,
        help="Connection, handshake I/O, and QUIT wait timeout in seconds (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    console = Console()
    try:
        return serve(args, console) if args.mode == "server" else connect(args, console)
    except KeyboardInterrupt:
        emit("\nPeer stopped.")
        return 0
    except (OSError, ProtocolError, PeerDisconnected) as exc:
        print(f"Connection error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
