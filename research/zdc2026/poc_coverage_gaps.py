#!/usr/bin/env python3
"""
Close the two reachable branches that measured coverage showed were never
exercised by the earlier fuzzing and PoCs.

Measured with gcov on a Debug+ASAN build (see NOTES.md §4.15):
parse_client_handshake_packet() reached 87.7% of its executable lines, and of
the sixteen misses all but one pair were branches independently established as
unreachable on this target (--skip-grant-tables, require_secure_transport,
and the MPVIO_EXT::RESTART cache-set block that needs a non-native account).
The exceptions were:

  1. sslaccept() failure -- `return packet_error` after a rejected TLS
     handshake. Every TLS case so far completed its handshake successfully, so
     the error path, and with it ssl_acceptor_stats_update(ssl_ret) and the
     teardown of a half-built SSL object, had never run.

  2. net_realloc()'s ER_NET_PACKET_TOO_LARGE branch. Nothing sent so far ever
     declared more than max_allowed_packet, because a single packet's length
     field caps at 0xFFFFFF, one byte below the 16 MB limit. Reaching it needs
     a multi-packet whose continuation pushes `helping = len + where_b` to or
     past max_packet_size.

Both are pre-auth reachable from an unauthenticated socket.
"""

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, CLIENT_LONG_PASSWORD, CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION, CLIENT_SSL, CLIENT_TRANSACTIONS,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3308
MAXP = 0xFFFFFF

SSL_CAPS = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
            CLIENT_SECURE_CONNECTION | CLIENT_TRANSACTIONS | CLIENT_SSL)


def ssl_request_packet(caps=SSL_CAPS):
    return (struct.pack("<I", caps) + struct.pack("<I", 0x01000000) +
            bytes([45]) + b"\x00" * 19 + struct.pack("<I", 0))


def read_reply(c):
    try:
        resp = c.read_packet()
    except OSError as exc:
        return f"io:{exc}"
    if resp is None:
        return "closed"
    if resp[:1] == b"\xff":
        return f"err{struct.unpack('<H', resp[1:3])[0]}: " + \
               resp[9:].decode("latin1", "replace")[:48]
    return "other:" + resp[:8].hex()


def group_failed_sslaccept():
    """CLIENT_SSL, then something that is not a valid TLS ClientHello."""
    print("1  sslaccept() failure path")
    cases = {
        "random bytes":        bytes((i * 37 + 11) & 0xff for i in range(64)),
        "truncated hello":     bytes.fromhex("160303002a0100"),
        "tls alert fatal":     bytes.fromhex("150303000202save".replace("save", "28")),
        "bogus record type":   b"\xff\xff\xff\xff" + b"A" * 32,
        "sslv2-ish":           b"\x80\x2e\x01\x00\x02" + b"B" * 40,
        "http request":        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "immediate close":     None,
        "one byte":            b"\x16",
        "zero length record":  bytes.fromhex("1603030000"),
        "huge record length":  bytes.fromhex("160303ffff") + b"C" * 16,
    }
    for name, payload in cases.items():
        try:
            c = Conn(HOST, PORT, timeout=15.0)
            if c.read_greeting() is None:
                print(f"   {name:20s} -> no greeting")
                continue
            c.send_packet(ssl_request_packet())
            if payload is None:
                c.sock.shutdown(socket.SHUT_WR)
                res = "wrote FIN"
            else:
                c.sock.sendall(payload)
                res = read_reply(c)
            c.close()
        except OSError as exc:
            res = f"io:{exc}"
        print(f"   {name:20s} -> {res}")
        if not server_alive(HOST, PORT, 15.0):
            print(f"   [!!] SERVER DEAD after '{name}'")
            return False
    return True


def group_packet_too_large():
    """Multi-packet whose continuation exceeds max_allowed_packet.

    my_net_read_packet_reallen() treats a 0xFFFFFF packet as the first fragment
    and keeps reading; my_real_read() then computes
    helping = MY_MAX(len, complen) + net->where_b and calls net_realloc(),
    which refuses length >= net->max_packet_size (16 MB here).
    """
    print("2  net_realloc() ER_NET_PACKET_TOO_LARGE path")
    for label, second in (("0xffffff + 0xffffff", MAXP),
                          ("0xffffff + 0x800000", 0x800000),
                          ("0xffffff + 0x000002", 2),
                          ("0xffffff + 0x000001", 1)):
        try:
            c = Conn(HOST, PORT, timeout=60.0)
            if c.read_greeting() is None:
                print(f"   {label:22s} -> no greeting")
                continue
            # first fragment: exactly MAX_PACKET_LENGTH
            c.sock.sendall(struct.pack("<I", MAXP)[:3] + bytes([c.seq]) +
                           b"A" * MAXP)
            # continuation header declaring `second` bytes, then as much body
            # as the server will take before it refuses
            c.sock.sendall(struct.pack("<I", second)[:3] + bytes([(c.seq + 1) & 0xff]))
            try:
                c.sock.sendall(b"B" * min(second, 1 << 16))
            except OSError:
                pass
            res = read_reply(c)
            c.close()
        except OSError as exc:
            res = f"io:{exc}"
        print(f"   {label:22s} -> {res}")
        if not server_alive(HOST, PORT, 20.0):
            print(f"   [!!] SERVER DEAD after '{label}'")
            return False
    return True


def main():
    print(f"target {HOST}:{PORT}")
    if not server_alive(HOST, PORT, 15.0):
        print("server not reachable")
        return 2
    ok = group_failed_sslaccept() and group_packet_too_large()
    print(f"\nserver alive at end: {server_alive(HOST, PORT, 20.0)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
