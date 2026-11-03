# Overview

This project is a command-line secure peer communication program written in Python. It allows two peers to establish a TCP connection, complete a public-key handshake, derive a shared encryption key, and exchange encrypted requests and responses.

## Setup

Use Python 3.10 or newer. From the project directory, create a virtual environment and install the dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Activate the same environment in each terminal you use to run a peer.

To use the program, start one peer in server mode:

```bash
python peer.py server
```

Then start a second peer in client mode from another terminal:

```bash
python peer.py client
```

The server peer listens on `127.0.0.1:7878`. After the client connects, the peers exchange public keys and establish an encrypted session. They can then send supported requests such as messages, ping requests, and quit requests. The listener handles a peer disconnecting and remains available for another connection.

## Commands

Either peer can type a message and press Enter to send it. Incoming messages and acknowledgements appear while the user types.

| Input | Action |
| --- | --- |
| Any text without a leading `/` | Send a message (up to 8,000 characters) |
| `/ping` | Ask the other peer to respond with `PONG` |
| `/quit` | End this session; the server waits for another peer and the client exits |
| `/exit` | End the session and stop this local program |
| `/help` | Show the commands |
| Ctrl+C or end of input (Ctrl+D on Ubuntu) | Stop this local program |

When the server is waiting for a connection, `/quit` also stops the program. End of input sends `QUIT` when a session is active; Ctrl+C closes the connection immediately.

The defaults work on one computer. To connect across a trusted local network, choose the listener's interface and give the client that computer's IPv4 address, for example:

```bash
python peer.py server --host 0.0.0.0 --port 7878
python peer.py client --host 192.168.1.10 --port 7878
```

Replace `192.168.1.10` with the server's actual address and allow the chosen TCP port through its firewall. `--timeout` sets the connection/handshake I/O timeout and the maximum wait for a quit acknowledgement (10 seconds by default). Established conversations can remain idle.

The purpose of this project is to develop a deeper understanding of how network connections work beneath higher-level frameworks. It provides practice with TCP sockets, connection lifecycles, serialization, public-key cryptography, symmetric encryption, and request/response protocols.

Software Demo Video: not yet recorded.

# Network Communication

The program uses a direct peer-to-peer architecture. One peer initially acts as the listener, while the other peer acts as the connector. The listener accepts the connection, but both peers can send and receive messages after the connection is established.

The peers communicate using TCP. The listener binds to `127.0.0.1` on port `7878`. TCP was selected because the project requires reliable, ordered delivery of handshake data, requests, and responses.

The application uses JSON objects as its logical message format. Example requests include:

```json
{"type": "SEND", "payload": "Hello from the other peer", "id": 1}
```

```json
{"type": "PING", "payload": null, "id": 2}
```

```json
{"type": "QUIT", "payload": null, "id": 3}
```

The program adds positive integer request IDs automatically. Replies use `RESPONSE` (or `ERROR` for an invalid request), echo the ID and request type, and carry a text payload:

```json
{"type": "RESPONSE", "id": 2, "request": "PING", "payload": "PONG"}
```

Every wire record starts with a four-byte unsigned big-endian length. The receiver reads exactly that many bytes, handling fragmented and combined TCP packets. Encrypted JSON is limited to 64 KiB before the 16-byte authentication tag; invalid lengths and truncated records close the session.

Before normal requests are exchanged, each peer generates a fresh X25519 public/private key pair. The first framed record contains a protocol/version marker, the client/server role, and the 32-byte public key. Both peers derive the same shared secret from their own private key and the remote public key. HKDF-SHA256 binds the ordered handshake transcript and derives separate keys for client-to-server and server-to-client traffic. These primitives follow the [cryptography X25519 documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/).

Requests and responses are encrypted with [ChaCha20-Poly1305 authenticated encryption](https://cryptography.io/en/latest/hazmat/primitives/aead/). Each direction uses an independent increasing counter as its 12-byte nonce, with the protocol marker as authenticated associated data. A nonce is never reused under a traffic key. Both peers exchange an encrypted `READY` record to confirm the handshake before accepting commands. Modified or replayed ciphertext fails authentication and closes the session.

The server does not implement or invent cryptographic algorithms. It uses established cryptographic primitives provided by the Python `cryptography` library. The handshake provides encryption for the session, but the initial version does not provide a full trusted identity system; therefore, it should be treated as a learning project rather than production-secure messaging software.

# Development Environment

The software was developed on Ubuntu using a terminal-based workflow. The program can be run with Python 3 and tested by starting the listener and connector in separate terminal windows on the same computer.

The project uses:

* Python 3
* The standard-library `socket` module for TCP networking
* The standard-library `threading` module for handling incoming communication while the user types outgoing messages
* The standard-library `json` module for serializing requests and responses
* The `cryptography` library for public-key key exchange and authenticated encryption
* Neovim and the terminal for editing, running, and debugging the program

# Project Files and Tests

* `peer.py`: command-line options, console input, request/response handling, and connection lifecycle.
* `secure_channel.py`: bounded message framing, public-key handshake, key derivation, and authenticated encryption.
* `requirements.txt`: the cryptography dependency; all other modules are from the Python standard library.
* `tests/`: automated transport, protocol, and real TCP command-line tests.

With the virtual environment active, run:

```bash
python -m unittest discover -v
```

Tests cover bidirectional messaging, ping/quit acknowledgements, fresh keys, tampered and replayed ciphertext, fragmented frames, malformed requests, failed/timed-out handshakes, abrupt disconnects, and reconnecting to the same listener. Command-line tests start local peers on an available loopback port; they do not require an external service.

# Useful Websites

* [This ChatGPT Project Discussion](https://chatgpt.com/)
* [Python Socket Documentation](https://docs.python.org/3/library/socket.html)
* [Python Threading Documentation](https://docs.python.org/3/library/threading.html)
* [Python JSON Documentation](https://docs.python.org/3/library/json.html)
* [Python Cryptography Documentation](https://cryptography.io/en/latest/)
* [MDN: An Overview of HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview)

# Future Work

* Add support for multiple simultaneous peer connections instead of supporting one active connection at a time.
* Add a central discovery or rendezvous server so peers can find one another without manually entering an IP address and port.
* Add peer identity verification, such as trusted public-key fingerprints, to reduce the risk of a man-in-the-middle attack during the handshake.
* Add encrypted message-history storage using a local file or database.
* Add rate limiting and stricter deadlines for peers that send a record very slowly.
* Add TLS as an additional layer of transport encryption and compare it with application-level end-to-end encryption.
