import concurrent.futures
import socket
import threading
import unittest

from peer import MAX_TEXT_LENGTH, PeerSession
from secure_channel import SecureChannel


class PeerSessionTests(unittest.TestCase):
    def setUp(self):
        left, right = socket.socketpair()
        for sock in (left, right):
            sock.settimeout(2)
            self.addCleanup(sock.close)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            server = executor.submit(SecureChannel.establish, right, "server")
            self.client = SecureChannel.establish(left, "client")
            self.output = []
            self.session = PeerSession(server.result(timeout=2), self.output.append)
        self.session.start()
        self.addCleanup(self.session.close)

    def exchange(self, message):
        self.client.send(message)
        return self.client.receive()

    def test_send_ping_and_quit(self):
        reply = self.exchange({"type": "SEND", "id": 1, "payload": "Hello 🌎"})
        self.assertEqual(reply["type"], "RESPONSE")
        self.assertEqual(reply["id"], 1)
        self.assertIn("Peer: Hello 🌎", self.output)
        reply = self.exchange({"type": "PING", "id": 2, "payload": None})
        self.assertEqual(reply["payload"], "PONG")
        reply = self.exchange({"type": "QUIT", "id": 3, "payload": None})
        self.assertEqual(reply["payload"], "Goodbye.")
        self.assertTrue(self.session.stopped.wait(1))

    def test_malformed_requests_get_errors_and_session_remains_usable(self):
        requests = [
            {"type": "UNKNOWN", "id": 1, "payload": None},
            {"type": [], "id": 2, "payload": None},
            {"type": "SEND", "id": 3, "payload": 42},
            {"type": "SEND", "id": 4, "payload": ""},
            {"type": "SEND", "id": 5, "payload": "x" * (MAX_TEXT_LENGTH + 1)},
            {"type": "PING", "id": 6, "payload": "unexpected"},
            {"type": "QUIT", "id": 7},
            {"type": "PING", "payload": None},
            {"type": "PING", "id": True, "payload": None},
        ]
        for request in requests:
            with self.subTest(request_type=request["type"]):
                self.assertEqual(self.exchange(request)["type"], "ERROR")
        self.assertEqual(
            self.exchange({"type": "PING", "id": 8, "payload": None})["payload"],
            "PONG",
        )

    def test_remote_terminal_control_characters_are_escaped(self):
        self.exchange({"type": "SEND", "id": 1, "payload": "hello\x1b[2J\nworld"})
        self.assertNotIn("\x1b", self.output[0])
        self.assertNotIn("\n", self.output[0])

    def test_maximum_length_unicode_message_is_delivered(self):
        payload = "🌎" * MAX_TEXT_LENGTH
        reply = self.exchange({"type": "SEND", "id": 1, "payload": payload})
        self.assertEqual(reply["type"], "RESPONSE")
        self.assertIn(f"Peer: {payload}", self.output)

    def test_abrupt_disconnect_stops_receiver(self):
        self.client.close()
        self.assertTrue(self.session.stopped.wait(1))
        self.assertIn("Peer disconnected.", self.output)

    def test_unmatched_response_closes_session(self):
        self.client.send(
            {"type": "RESPONSE", "request": "PING", "id": 99, "payload": "PONG"}
        )
        self.assertTrue(self.session.stopped.wait(1))
        self.assertTrue(self.session.failed)

    def test_invalid_ping_response_is_not_reported_as_pong(self):
        self.session.request("PING")
        request = self.client.receive()
        self.client.send(
            {"type": "RESPONSE", "request": "PING", "id": request["id"], "payload": "wrong"}
        )
        self.assertTrue(self.session.stopped.wait(1))
        self.assertTrue(self.session.failed)
        self.assertNotIn("Peer: PONG", self.output)

    def test_simultaneous_requests_in_both_directions(self):
        received = threading.Event()
        output = []

        def collect(line):
            output.append(line)
            if line == "Peer: PONG":
                received.set()

        other = PeerSession(self.client, collect)
        self.addCleanup(other.close)
        other.start()
        self.session.request("SEND", "from server")
        other.request("SEND", "from client")
        other.request("PING")
        self.assertTrue(received.wait(1))
        self.assertIn("Peer: from client", self.output)
        self.assertIn("Peer: from server", output)


if __name__ == "__main__":
    unittest.main()
