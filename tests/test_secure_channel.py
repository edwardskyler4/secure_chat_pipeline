import concurrent.futures
import socket
import struct
import unittest

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from secure_channel import (
    MAX_FRAME,
    PROTOCOL,
    PeerDisconnected,
    ProtocolError,
    SecureChannel,
    receive_frame,
    send_frame,
)


class RecordingSocket:
    """Record actual transmitted bytes and force small reads to exercise TCP framing."""

    def __init__(self, sock):
        self.socket = sock
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)
        self.socket.sendall(data)

    def recv(self, size):
        return self.socket.recv(min(size, 3))

    def __getattr__(self, name):
        return getattr(self.socket, name)


class SecureChannelTests(unittest.TestCase):
    def sockets(self):
        left, right = socket.socketpair()
        for sock in (left, right):
            sock.settimeout(2)
            self.addCleanup(sock.close)
        return left, right

    def channels(self):
        left, right = (RecordingSocket(sock) for sock in self.sockets())
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            server = executor.submit(SecureChannel.establish, right, "server", 1)
            client = SecureChannel.establish(left, "client", 1)
            return client, server.result(timeout=2), left, right

    def test_handshake_and_bidirectional_encryption_with_fragmented_reads(self):
        client, server, left, right = self.channels()
        message = {"type": "SEND", "id": 1, "payload": "Private hello 🌎"}
        client.send(message)
        server.send(message)
        self.assertEqual(server.receive(), message)
        self.assertEqual(client.receive(), message)
        self.assertNotIn(b"Private hello", b"".join(left.sent + right.sent))
        # Separate directional keys prevent nonce reuse when both counters match.
        self.assertNotEqual(left.sent[-1], right.sent[-1])

    def test_back_to_back_records_and_unique_nonces(self):
        client, server, left, _ = self.channels()
        message = {"type": "PING", "id": 1, "payload": None}
        client.send(message)
        client.send(message)
        self.assertEqual(server.receive(), message)
        self.assertEqual(server.receive(), message)
        self.assertNotEqual(left.sent[-1], left.sent[-2])

    def test_each_handshake_generates_fresh_public_keys(self):
        _, _, first, _ = self.channels()
        _, _, second, _ = self.channels()
        self.assertNotEqual(first.sent[0], second.sent[0])

    def test_tampered_ciphertext_is_rejected(self):
        left, right = self.sockets()
        key = ChaCha20Poly1305.generate_key()
        receiver = SecureChannel(right, key, key)
        encrypted = ChaCha20Poly1305(key).encrypt(bytes(12), b'{"type":"PING"}', PROTOCOL)
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        send_frame(left, tampered)
        with self.assertRaisesRegex(ProtocolError, "authentication"):
            receiver.receive()

    def test_replayed_record_is_rejected(self):
        client, server, left, _ = self.channels()
        client.send({"type": "PING"})
        server.receive()
        left.sendall(left.sent[-1])
        with self.assertRaisesRegex(ProtocolError, "authentication"):
            server.receive()

    def test_invalid_json_and_non_object_records_are_rejected(self):
        for plaintext in (
            b"not json", b"[]", b'{"value":NaN}', b"\xff",
            '{"value":1}'.encode("utf-16-le"),
        ):
            with self.subTest(plaintext=plaintext):
                left, right = self.sockets()
                key = ChaCha20Poly1305.generate_key()
                encrypted = ChaCha20Poly1305(key).encrypt(bytes(12), plaintext, PROTOCOL)
                send_frame(left, encrypted)
                with self.assertRaises(ProtocolError):
                    SecureChannel(right, key, key).receive()

    def test_oversized_and_empty_frames_are_rejected_before_reading_body(self):
        for length in (0, MAX_FRAME + 1):
            with self.subTest(length=length):
                left, right = self.sockets()
                left.sendall(struct.pack("!I", length))
                with self.assertRaisesRegex(ProtocolError, "length"):
                    receive_frame(right)

    def test_disconnect_at_frame_boundary_and_mid_frame(self):
        for data, error in (
            (b"", PeerDisconnected),
            (b"\x00\x00", ProtocolError),
            (struct.pack("!I", 5), ProtocolError),
            (struct.pack("!I", 5) + b"hi", ProtocolError),
        ):
            with self.subTest(data=data):
                left, right = self.sockets()
                left.sendall(data)
                left.shutdown(socket.SHUT_WR)
                with self.assertRaises(error):
                    receive_frame(right)

    def test_invalid_handshakes(self):
        for hello in (
            b"wrong version",
            PROTOCOL + b"S" + bytes(32),  # Same role as the listener.
            PROTOCOL + b"C" + bytes(32),  # Invalid low-order public key.
        ):
            with self.subTest(hello=hello):
                left, right = self.sockets()
                send_frame(left, hello)
                with self.assertRaises(ProtocolError):
                    SecureChannel.establish(right, "server", 0.2)

    def test_handshake_timeout(self):
        _, right = self.sockets()
        with self.assertRaises(TimeoutError):
            SecureChannel.establish(right, "server", 0.05)

    def test_encrypted_confirmation_is_required(self):
        left, right = self.sockets()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(SecureChannel.establish, right, "server", 0.2)
            server_hello = receive_frame(left)
            send_frame(left, PROTOCOL + b"C" + server_hello[-32:])
            # A public-key exchange alone must not be reported as a ready session.
            send_frame(left, b"bogus encrypted confirmation")
            with self.assertRaises(ProtocolError):
                future.result(timeout=1)


if __name__ == "__main__":
    unittest.main()
