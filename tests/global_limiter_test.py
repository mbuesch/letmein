#!/usr/bin/env python3
"""
Exercise letmeind's global-connection limiter on a local test server.

The script sends a valid, basic-authenticated UDP Knock from each source IP,
but deliberately does not send the challenge response.
The daemon therefore keeps each connection until `control-timeout`.
Once `--slots` have been held, one more Knock should reach the global limiter.

Example (the key, user and resource must exist in the test server config):

    python3 global_limiter_test.py --mode unauth
    python3 global_limiter_test.py --mode auth --key <64-hex-digit-key> --user 00000000 --resource 00000022

With the default `letmeind --num-connections 64`, server stderr should contain
`Too many simultaneous connections (global limit). Dropping connection.`
"""

import argparse
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import sys
import time
from collections.abc import Iterable

MAGIC = 0x3B1B_B719
OP_KNOCK = 0
OP_CHALLENGE = 1
SALT_SIZE = 8
AUTH_SIZE = 32
MSG_SIZE = 4 + 4 + 4 + 4 + SALT_SIZE + AUTH_SIZE
MAX_LOOPBACK_SOURCES = 254**3

def parse_hex_u32(value: str) -> int:
    """
    Parse the eight-digit hexadecimal identifiers used by letmein.
    """
    try:
        parsed = int(value, 16)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Not a hexadecimal integer: {value!r}") from e
    if not 0 <= parsed <= 0xFFFF_FFFF:
        raise argparse.ArgumentTypeError(f"Out of range for u32: {value!r}")
    return parsed

def parse_key(value: str) -> bytes:
    """
    Parse a 64-hex-digit key used by letmein.
    """
    try:
        key = bytes.fromhex(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("Key must be hexadecimal") from e
    if len(key) != AUTH_SIZE:
        raise argparse.ArgumentTypeError(f"Key must be {AUTH_SIZE} bytes")
    return key

def loopback_sources(count: int) -> Iterable[str]:
    """
    Yield `count` unique usable IPv4 loopback addresses.
    Start at 127.1.1.1 to avoid the usual server destination, 127.0.0.1.
    """
    if not 1 <= count <= MAX_LOOPBACK_SOURCES:
        raise ValueError(f"source count must be between 1 and {MAX_LOOPBACK_SOURCES}")
    for index in range(count):
        first, remainder = divmod(index, 254 * 254)
        second, third = divmod(remainder, 254)
        yield f"127.{first + 1}.{second + 1}.{third + 1}"

def make_knock(key: bytes, user: int, resource: int) -> bytes:
    """
    Build a basic-authenticated `Operation::Knock` message.

    The server authenticates this first packet and waits for the challenge response.
    The caller deliberately never sends that response.
    """
    header = struct.pack("!IIII", MAGIC, OP_KNOCK, user, resource)
    salt = os.urandom(SALT_SIZE)
    auth = hmac.new(
        key,
        struct.pack("!III", OP_KNOCK, user, resource) + salt + bytes(AUTH_SIZE),
        hashlib.sha3_256,
    ).digest()
    message = header + salt + auth
    assert len(message) == MSG_SIZE
    return message

def open_udp_sender(source_ip: str, target: tuple[str, int]) -> socket.socket:
    """
    Open a UDP sender socket bound to `source_ip` and connected to `target`.
    Returns the connected socket.
    """
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind((source_ip, 0))
    sender.connect(target)
    return sender

def receive_packet(sender: socket.socket, timeout: float) -> bytes | None:
    """
    Return one packet, or None if no packet arrives before `timeout`.
    """
    sender.settimeout(timeout)
    try:
        return sender.recv(MSG_SIZE)
    except TimeoutError:
        return None
    except OSError as e:
        print(f"UDP receive failed: {e}", file=sys.stderr)
        return None
    finally:
        sender.settimeout(None)

def is_challenge(packet: bytes | None) -> bool:
    """
    Return whether `packet` is a letmein Challenge header.
    """
    return (
        packet is not None
        and len(packet) == MSG_SIZE
        and struct.unpack("!II", packet[:8]) == (MAGIC, OP_CHALLENGE)
    )

def await_unexpected_challenge(sender: socket.socket, timeout: float) -> bool:
    """
    Return true when the overflow UDP connection was incorrectly admitted.
    """
    packet = receive_packet(sender, timeout)
    if packet is None:
        return False
    print(
        f"Overflow connection received {len(packet)} bytes"
        f"{' (Challenge)' if is_challenge(packet) else ''}; it was admitted instead of "
        "being rejected (check --slots against letmeind --num-connections)",
        file=sys.stderr,
    )
    return is_challenge(packet)

def run_authenticated_hold(args: argparse.Namespace, target: tuple[str, int]) -> int:
    """
    Run an authenticated hold test.
    """
    assert args.key is not None
    senders: list[socket.socket] = []
    overflow: socket.socket | None = None
    try:
        sources = iter(loopback_sources(args.slots + 1))
        for _ in range(args.slots):
            sender = open_udp_sender(next(sources), target)
            sender.send(make_knock(args.key, args.user, args.resource))
            senders.append(sender)

        # Let the daemon run the BasicAuth step and begin waiting for the
        # response before sending the overflow connection.
        time.sleep(args.settle)
        for index, sender in enumerate(senders, start=1):
            if not is_challenge(receive_packet(sender, args.observe)):
                print(
                    f"Held connection {index} did not receive a Challenge; verify --key, "
                    "--user, --resource, UDP enablement, and --slots.",
                    file=sys.stderr,
                )
                return 2

        overflow = open_udp_sender(next(sources), target)
        overflow.send(make_knock(args.key, args.user, args.resource))
        print(
            f"Sent {args.slots} held UDP Knocks and one overflow Knock to "
            f"{target[0]}:{target[1]}."
        )
        print(
            "EXPECTED SERVER LOG:\n"
            "    Client '::ffff:127.1.1.65': ERROR: Too many simultaneous connections (global limit). Dropping connection.\n"
            "    Client '...' ERROR: RX communication with peer timed out\n"
            "    ..."
        )

        admitted = await_unexpected_challenge(overflow, args.observe)
        time.sleep(args.hold)
        return 1 if admitted else 0
    finally:
        if overflow is not None:
            overflow.close()
        for sender in senders:
            sender.close()

def run_unauthenticated_eviction(args: argparse.Namespace, target: tuple[str, int]) -> int:
    """
    Exercise the limiter's force-close path with a UDP overflow attempt.

    TCP is used only to create reliably idle *unauthenticated* sessions.  This
    avoids relying on scheduling races: a UDP connection necessarily starts
    with a datagram, which the protocol would otherwise consume immediately.
    """
    holders: list[socket.socket] = []
    overflow: socket.socket | None = None
    try:
        sources = iter(loopback_sources(args.slots + 1))
        for _ in range(args.slots):
            holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            holder.bind((next(sources), 0))
            holder.settimeout(args.connect_timeout)
            holder.connect(target)
            holder.settimeout(None)
            holders.append(holder)

        time.sleep(args.settle)
        overflow = open_udp_sender(next(sources), target)
        # A full-size packet is required by UdpDispatcher.  Its contents do
        # not matter here: the global limiter acts before Protocol::run().
        overflow.send(bytes(MSG_SIZE))
        print(
            f"Opened {args.slots} idle TCP sessions and sent one UDP overflow "
            f"packet to {target[0]}:{target[1]}."
        )
        print(
            "EXPECTED SERVER LOG:\n"
            "    WARNING: Force-closed oldest unauthenticated connection ::ffff:127.1.1.1 due to global limiter.\n"
            "    Client '...' ERROR: Disconnected.\n"
            "    Client '...' ERROR: Deserialize: Invalid magic code.\n"
            "    ..."
        )
        time.sleep(args.hold)
        return 0
    finally:
        if overflow is not None:
            overflow.close()
        for holder in holders:
            holder.close()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="IP address of letmeind")
    parser.add_argument("--port", type=int, default=5800, help="letmeind TCP/UDP control port")
    parser.add_argument("--slots", type=int, default=64, help="Must match letmeind --num-connections")
    parser.add_argument("--key", type=parse_key, help="Hexadecimal key")
    parser.add_argument("--user", type=parse_hex_u32, help="Hexadecimal user ID")
    parser.add_argument("--resource", type=parse_hex_u32, help="Hexadecimal resource ID")
    parser.add_argument("--settle", type=float, default=0.25, help="Seconds to let the held sessions reach the server")
    parser.add_argument("--observe", type=float, default=0.5, help="Seconds to check whether the overflow connection gets a Challenge")
    parser.add_argument("--hold", type=float, default=0.25, help="Seconds to retain the test sockets after the overflow attempt")
    parser.add_argument("--connect-timeout", type=float, default=2.0, help="TCP connect timeout")
    parser.add_argument("--mode", choices=("auth", "unauth"), default="auth", help="Global-limit rejection test or unauthenticated force-close test")
    args = parser.parse_args()

    try:
        address = ipaddress.ip_address(args.host)
    except ValueError as e:
        parser.error(f"--host must be a numeric IPv4 loopback address: {e}")
    if address.version != 4 or not address.is_loopback:
        parser.error("refusing a non-loopback target; use a disposable local letmeind instance")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 1 <= args.slots <= MAX_LOOPBACK_SOURCES - 1:
        parser.error(f"--slots must be between 1 and {MAX_LOOPBACK_SOURCES - 1}")
    for option in ("settle", "observe", "hold", "connect_timeout"):
        if getattr(args, option) < 0:
            parser.error(f"--{option.replace('_', '-')} must not be negative")
    if args.mode == "auth":
        missing = [name for name in ("key", "user", "resource") if getattr(args, name) is None]
        if missing:
            parser.error("auth mode requires " + ", ".join(f"--{name}" for name in missing))
    return args

def main() -> int:
    args = parse_args()
    target = (args.host, args.port)
    if args.mode == "auth":
        return run_authenticated_hold(args, target)
    elif args.mode == "unauth":
        return run_unauthenticated_eviction(args, target)
    else:
        assert False

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)

# vim: ts=4 sw=4 expandtab
