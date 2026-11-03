"""Framed TCP transport with an ephemeral, unauthenticated encrypted handshake.

Each connection gets fresh X25519 keys. HKDF derives separate traffic keys for
each direction; ChaCha20-Poly1305 authenticates every subsequent JSON record.
This protocol does not verify the identity of the remote peer.
"""

from __future__ import annotations

import json
import socket
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL = b"CSE310-PEER-v1\x00"
MAX_PLAINTEXT = 64 * 1024
MAX_FRAME = MAX_PLAINTEXT + 16  # The authentication tag occupies 16 bytes.
MAX_SEQUENCE = 2**64


class ProtocolError(Exception):
    """The peer sent invalid, incompatible, or unauthentic data."""


class PeerDisconnected(ConnectionError):
    """The peer closed its side of the connection."""


def receive_exact(sock: socket.socket, size: int) -> bytes:
    """Read a complete field even when TCP delivers it in several pieces."""
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            if result:
                raise ProtocolError("Peer disconnected in the middle of a frame.")
            raise PeerDisconnected("Peer disconnected.")
        result.extend(chunk)
    return bytes(result)


def send_frame(sock: socket.socket, data: bytes) -> None:
    if not 0 < len(data) <= MAX_FRAME:
        raise ProtocolError("Frame length is outside the allowed range.")
    sock.sendall(struct.pack("!I", len(data)) + data)


def receive_frame(sock: socket.socket, limit: int = MAX_FRAME) -> bytes:
    size = struct.unpack("!I", receive_exact(sock, 4))[0]
    if not 0 < size <= limit:
        raise ProtocolError("Frame length is outside the allowed range.")
    try:
        return receive_exact(sock, size)
    except PeerDisconnected as exc:
        raise ProtocolError("Peer disconnected before sending the frame body.") from exc


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-JSON numeric constant: {value}")


class SecureChannel:
    """One receiving thread and any number of serialized sending threads.

    Counters supply unique 96-bit nonces under each directional traffic key.
    Receivers expect exactly the next counter, rejecting modified/replayed data.
    A failed send or receive is fatal: callers must close the channel.
    """

    def __init__(self, sock: socket.socket, send_key: bytes, receive_key: bytes):
        self.socket = sock
        self._sender = ChaCha20Poly1305(send_key)
        self._receiver = ChaCha20Poly1305(receive_key)
        self._send_sequence = 0
        self._receive_sequence = 0
        self._send_lock = threading.Lock()

    @classmethod
    def establish(
        cls, sock: socket.socket, role: str, timeout: float = 10.0
    ) -> SecureChannel:
        """Exchange versioned public keys and confirm both derived traffic keys."""
        if role not in ("client", "server"):
            raise ValueError("Role must be client or server.")
        previous_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            role_byte = b"C" if role == "client" else b"S"
            hello = PROTOCOL + role_byte + public_key
            send_frame(sock, hello)
            remote_hello = receive_frame(sock, limit=len(hello))
            expected_role = b"S" if role == "client" else b"C"
            if (
                len(remote_hello) != len(hello)
                or not remote_hello.startswith(PROTOCOL + expected_role)
            ):
                raise ProtocolError("Incompatible handshake version or peer role.")

            remote_public = remote_hello[-32:]
            try:
                shared_secret = private_key.exchange(
                    X25519PublicKey.from_public_bytes(remote_public)
                )
            except ValueError as exc:
                raise ProtocolError("Invalid peer public key.") from exc

            # Both sides bind the same ordered handshake transcript into HKDF.
            transcript = hello + remote_hello if role == "client" else remote_hello + hello
            keys = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=transcript,
            ).derive(shared_secret)
            client_key, server_key = keys[:32], keys[32:]
            if role == "client":
                channel = cls(sock, client_key, server_key)
            else:
                channel = cls(sock, server_key, client_key)

            channel.send({"type": "READY", "role": role})
            remote_role = "server" if role == "client" else "client"
            if channel.receive() != {"type": "READY", "role": remote_role}:
                raise ProtocolError("Encrypted handshake confirmation failed.")
            return channel
        finally:
            sock.settimeout(previous_timeout)

    def send(self, message: dict) -> None:
        try:
            plaintext = json.dumps(
                message, separators=(",", ":"), allow_nan=False, ensure_ascii=False
            ).encode("utf-8")
        except (ValueError, TypeError, RecursionError) as exc:
            raise ProtocolError("Message cannot be encoded as JSON.") from exc
        if len(plaintext) > MAX_PLAINTEXT:
            raise ProtocolError("Encoded message exceeds the 64 KiB limit.")
        with self._send_lock:
            if self._send_sequence >= MAX_SEQUENCE:
                raise ProtocolError("Session message limit reached; reconnect.")
            nonce = self._send_sequence.to_bytes(12, "big")
            ciphertext = self._sender.encrypt(nonce, plaintext, PROTOCOL)
            # Never reuse this nonce, including when sendall fails partway.
            self._send_sequence += 1
            send_frame(self.socket, ciphertext)

    def receive(self) -> dict:
        ciphertext = receive_frame(self.socket)
        if self._receive_sequence >= MAX_SEQUENCE:
            raise ProtocolError("Session message limit reached; reconnect.")
        nonce = self._receive_sequence.to_bytes(12, "big")
        try:
            plaintext = self._receiver.decrypt(nonce, ciphertext, PROTOCOL)
        except InvalidTag as exc:
            raise ProtocolError("Message authentication failed.") from exc
        self._receive_sequence += 1
        try:
            message = json.loads(plaintext.decode("utf-8"), parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ProtocolError("Expected a UTF-8 JSON object.") from exc
        if not isinstance(message, dict):
            raise ProtocolError("Expected a JSON object.")
        return message

    def close(self) -> None:
        """Unblock a waiting receiver and release the socket; safe to repeat."""
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()
