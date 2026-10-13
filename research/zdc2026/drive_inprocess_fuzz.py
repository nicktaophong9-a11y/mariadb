#!/usr/bin/env python3
"""
Driver for the in-process handshake re-parse hook.

The hook (see NOTES.md §4.16) is compiled into the instrumented build behind
MARIADB_PREAUTH_FUZZ_HOOK and enabled at runtime by MARIADB_FUZZ_HANDSHAKE=N.
When it is on, every connection's first handshake packet is re-parsed N times
against mutated copies of itself, using the real THD/NET/ACL state. So the job
of this driver is only to supply a wide variety of *seed* packets, each of which
the server then expands into N parses.

Each packet is kept at or below the hook's 8192-byte cap, and above
MIN_HANDSHAKE_SIZE, so the hook always engages.

Usage: python3 -I drive_inprocess_fuzz.py [host] [port] [connections]
"""

import os
import random
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, lenenc_int, BASE_CAPS,
    CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_ATTRS,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_SECURE_CONNECTION,
    CLIENT_PROTOCOL_41, CLIENT_INTERACTIVE, CLIENT_IGNORE_SPACE, CLIENT_MYSQL,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3307
NCONN = int(sys.argv[3]) if len(sys.argv) > 3 else 500

CHARSETS = [1, 8, 11, 12, 13, 18, 19, 24, 28, 30, 33, 38, 45, 46, 63, 65,
            84, 85, 86, 87, 88, 89, 91, 95, 96, 97, 98, 192, 223, 254, 255, 0]
PLUGINS = [b"mysql_native_password", b"mysql_old_password", b"unix_socket",
           b"ed25519", b"", b"\xff\xfe", b"z" * 200]


def nonzero(rnd, n):
    return bytes(rnd.randrange(1, 256) for _ in range(n))


def seed_packet(c, rnd):
    caps = BASE_CAPS | CLIENT_PLUGIN_AUTH
    for bit in (CLIENT_CONNECT_WITH_DB, CLIENT_CONNECT_ATTRS,
                CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_INTERACTIVE,
                CLIENT_IGNORE_SPACE):
        if rnd.random() < 0.5:
            caps |= bit
    if rnd.random() < 0.15:
        caps &= ~CLIENT_SECURE_CONNECTION
    if rnd.random() < 0.08:
        caps &= ~CLIENT_PROTOCOL_41
    if rnd.random() < 0.5:
        caps &= ~CLIENT_MYSQL
    return c.build_handshake_response(
        caps=caps,
        ext_caps=rnd.choice([0, 0xffffffff, rnd.getrandbits(32)]),
        max_packet=rnd.choice([0, 1, 0x01000000, 0xffffffff]),
        charset=rnd.choice(CHARSETS),
        user=rnd.choice([b"demo", b"root", b"mariadb.sys", b"healthcheck",
                         b"'q'", nonzero(rnd, rnd.randrange(1, 200)),
                         b"\xc3\xa9" * rnd.randrange(1, 60)]),
        auth_data=nonzero(rnd, rnd.choice([0, 1, 19, 20, 21, 255])),
        auth_len_encoding=rnd.choice([None, 1, 3, 4, 9]),
        db=rnd.choice([b"demo", b"", nonzero(rnd, rnd.randrange(1, 300))]),
        plugin=rnd.choice(PLUGINS),
        attrs=rnd.choice([lenenc_int(0),
                          lenenc_int(0xffff) + nonzero(rnd, 16),
                          lenenc_int(0xffffffffffffffff, force=9),
                          nonzero(rnd, rnd.randrange(1, 48))]),
        truncate=rnd.choice([None, None, 31, 32, 33, 34, 40, 64,
                             rnd.randrange(6, 200)]),
    )


def main():
    if not server_alive(HOST, PORT, 15.0):
        print("server not reachable")
        return 2
    n_env = os.environ.get("MARIADB_FUZZ_HANDSHAKE", "?")
    print(f"target {HOST}:{PORT}  connections={NCONN}  "
          f"server-side iterations/connection={n_env}")
    rnd = random.Random(int(os.environ.get("SEED", 20261013)))
    t0 = time.time()
    sent = 0
    for i in range(1, NCONN + 1):
        try:
            c = Conn(HOST, PORT, timeout=120.0)
            if c.read_greeting() is None:
                c.close()
                continue
            pkt = seed_packet(c, rnd)
            if len(pkt) > 8192:
                pkt = pkt[:8192]
            c.send_packet(pkt)
            try:
                c.read_packet()
            except OSError:
                pass
            c.close()
            sent += 1
        except OSError:
            pass
        if i % 50 == 0:
            alive = server_alive(HOST, PORT, 20.0)
            el = time.time() - t0
            print(f"  {i}/{NCONN} seeds  {el:6.0f}s  alive={alive}")
            if not alive:
                print("  [!!] SERVER DEAD")
                return 1
    print(f"\nseeds delivered={sent}  elapsed={time.time()-t0:.0f}s")
    print(f"server alive at end: {server_alive(HOST, PORT, 30.0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
