"""Exercise real CLI processes over loopback TCP, including listener recovery."""

from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

from secure_channel import send_frame


ROOT = Path(__file__).resolve().parents[1]


class RunningPeer:
    def __init__(self, mode, port):
        self.process = subprocess.Popen(
            [sys.executable, "-u", "peer.py", mode, "--port", str(port), "--timeout", "0.5"],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.lines = []
        self.changed = threading.Condition()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            with self.changed:
                self.lines.append(line.rstrip())
                self.changed.notify_all()

    def send(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def expect(self, text, after=0):
        deadline = time.monotonic() + 5
        with self.changed:
            while not any(text in line for line in self.lines[after:]):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"Missing {text!r} in output: {self.lines}")
                self.changed.wait(remaining)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=3)
        self.reader.join(timeout=1)
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        self.process.stdout.close()


class CliTests(unittest.TestCase):
    def setUp(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]

    def peer(self, mode):
        peer = RunningPeer(mode, self.port)
        self.addCleanup(peer.close)
        return peer

    def test_bidirectional_chat_and_listener_recovers_from_disconnects(self):
        server = self.peer("server")
        server.expect("Listening on")

        # An invalid handshake must not take down the listener.
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            send_frame(sock, b"incompatible protocol")
            server.expect("Handshake failed")

        client = self.peer("client")
        client.expect("Encrypted session established")
        server.expect("Encrypted session established")
        # The connection timeout must not become an idle conversation timeout.
        time.sleep(0.6)
        client.send("Hello from client 🌎")
        client.send("/ping")
        server.expect("Peer: Hello from client 🌎")
        client.expect("Message delivered")
        client.expect("Peer: PONG")

        server.send("Hello from server")
        server.send("/ping")
        client.expect("Peer: Hello from server")
        server.expect("Message delivered")
        server.expect("Peer: PONG")

        client.send("/quit")
        self.assertEqual(client.process.wait(timeout=3), 0)
        server.expect("Waiting for another peer")
        self.assertIsNone(server.process.poll())

        second_marker = len(server.lines)
        second = self.peer("client")
        second.expect("Encrypted session established")
        server.expect("Encrypted session established", after=second_marker)
        second.process.kill()
        second.process.wait(timeout=3)
        server.expect("Peer disconnected", after=second_marker)
        server.expect("Waiting for another peer", after=second_marker)

        third_marker = len(server.lines)
        third = self.peer("client")
        third.expect("Encrypted session established")
        server.expect("Encrypted session established", after=third_marker)
        server.send("/exit")
        self.assertEqual(server.process.wait(timeout=3), 0)
        # Remote QUIT must release the client without requiring another input line.
        self.assertEqual(third.process.wait(timeout=3), 0)

    def test_stalled_handshake_times_out_and_listener_accepts_next_client(self):
        server = self.peer("server")
        server.expect("Listening on")
        with socket.create_connection(("127.0.0.1", self.port), timeout=2):
            server.expect("Handshake failed")
        client = self.peer("client")
        client.expect("Encrypted session established")
        client.process.stdin.close()
        self.assertEqual(client.process.wait(timeout=3), 0)
        server.expect("Waiting for another peer")
        server.send("/exit")
        self.assertEqual(server.process.wait(timeout=3), 0)

    def test_listener_can_exit_while_waiting_for_a_connection(self):
        server = self.peer("server")
        server.expect("Listening on")
        server.send("/exit")
        self.assertEqual(server.process.wait(timeout=3), 0)

    def test_bad_arguments_and_connection_refusal_are_readable_errors(self):
        for arguments, status, message in (
            (["client", "--port", "70000"], 2, "Port must be"),
            (["server", "--timeout", "nan"], 2, "Timeout must be"),
            (["client", "--port", str(self.port)], 1, "Connection error:"),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [sys.executable, "peer.py", *arguments],
                    cwd=ROOT, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, status)
                self.assertIn(message, result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
