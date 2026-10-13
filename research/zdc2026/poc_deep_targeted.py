#!/usr/bin/env python3
"""
Targeted pre-auth stress tests for the claims made by hand in NOTES.md.

Random fuzzing never sent these shapes: it capped packets at a few hundred KB,
used a short charset list, and never aimed at a specific buffer boundary. Each
group below drives one piece of arithmetic that was verified only on paper.

  A  err_conv() / net_send_error_packet()
     A database field of non-printable bytes makes copy_with_error() raise
     ER_INVALID_CHARACTER_STRING, which builds an ErrConvString over the raw
     bytes with my_charset_bin. err_conv()'s binary branch expands each
     non-printable byte to "\\xNN", so the 512-byte err_buffer fills four times
     faster than the input; set_strq() then writes err_buffer[len+1] and
     [len+2]. The message is then converted again into converted_err[512] and
     copied into buff[2+1+SQLSTATE_LENGTH+MYSQL_ERRMSG_SIZE] in
     net_send_error_packet(). Lengths are chosen to land on 509/510/511/512 and
     on the four-byte escape boundary.

  B  copy_and_convert() + Well_formed_prefix() on the username
     user_buff is USERNAME_LENGTH+1 = 385 bytes, copy_and_convert() is given
     384, and after the leading-quote chop user_len is reduced by 2 before
     user[user_len] = '\\0'. Lengths straddle 383/384/385, with and without the
     surrounding quotes, and with multi-byte sequences deliberately truncated
     at the cut point.

  C  net_realloc() and the 48 MB copy_fix() allocation
     max_allowed_packet is 16 MB and net_buffer_length 16 KB, so these are the
     only packet shapes that exercise the realloc path and the
     mbmaxlen * src_length sizing in THD::copy_fix(). Includes the one legal
     pre-auth multi-packet sequence (0xffffff followed by 0).

  D  charset sweep
     Every collation id 0..255, each with adversarially truncated multi-byte
     sequences in both the username and the database field, to exercise each
     mb_wc decoder's bound checks at the end of the buffer.

Run against an ASAN build; any report is the finding.
"""

import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, lenenc_int,
    CLIENT_LONG_PASSWORD, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
    CLIENT_TRANSACTIONS, CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
)

BASE = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION |
        CLIENT_TRANSACTIONS)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3307

fails = []


def send(caps, charset, user, auth, db, plugin=None, attrs=None,
         lenenc=None, timeout=30.0):
    """One handshake response; returns a short description of the reply."""
    try:
        c = Conn(HOST, PORT, timeout=timeout)
    except OSError as exc:
        return f"connect-failed: {exc}"
    try:
        if c.read_greeting() is None:
            return "no-greeting"
        pkt = c.build_handshake_response(
            caps=caps, charset=charset, user=user, auth_data=auth,
            auth_len_encoding=lenenc, db=db, plugin=plugin, attrs=attrs)
        c.send_packet(pkt)
        resp = c.read_packet()
        if resp is None:
            return "closed"
        if resp[:1] == b"\xff":
            return f"err{struct.unpack('<H', resp[1:3])[0]}"
        if resp[:1] == b"\x00":
            return "OK"
        if resp[:1] == b"\xfe":
            return "auth-switch"
        return "other:" + resp[:8].hex()
    except OSError as exc:
        return f"io:{exc}"
    finally:
        c.close()


def check(label):
    if server_alive(HOST, PORT, timeout=20.0):
        return True
    print(f"  [!!] SERVER DEAD after {label}")
    fails.append(label)
    return False


def group_a():
    print("A  err_conv / net_send_error_packet pressure")
    caps = BASE | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH
    # 0x80..0xff are both non-printable for err_conv's binary branch and
    # invalid as utf8, so copy_with_error() fails and the error path runs.
    for n in (1, 2, 3, 100, 126, 127, 128, 129, 169, 170, 171,
              254, 255, 256, 508, 509, 510, 511, 512, 513, 1000, 4096, 65535):
        db = bytes(0x80 + (i % 0x7f) for i in range(n))
        r = send(caps, 45, b"nosuchuser_A", b"", db)
        print(f"   db={n:<6} non-printable -> {r}")
        if not check(f"A/db={n}"):
            return
    # And the same through the quoting helper's worst case: a db whose escaped
    # form lands exactly on the 4-byte escape boundary inside err_buffer.
    for n in (127, 128):
        db = b"\x01" * n
        r = send(caps, 45, b"nosuchuser_A2", b"", db)
        print(f"   db={n:<6} 0x01 repeated  -> {r}")
        if not check(f"A2/db={n}"):
            return


def group_b():
    print("B  username boundary: copy_and_convert + Well_formed_prefix")
    caps = BASE | CLIENT_PLUGIN_AUTH
    for cs in (33, 45, 13, 1, 12, 97, 28, 19, 95, 8, 63):
        for n in (127, 128, 129, 382, 383, 384, 385, 386, 390, 512):
            for quoted in (False, True):
                for tail in (b"A", b"\xc3", b"\xe4\xb8", b"\xf0\x9f\x98",
                             b"\x81", b"\x8f\xa1"):
                    body = b"u" * max(0, n - len(tail)) + tail
                    user = (b"'" + body + b"'") if quoted else body
                    r = send(caps, cs, user, b"", None)
                    if r.startswith(("connect-failed", "closed", "no-greeting")):
                        print(f"   cs={cs} n={n} quoted={quoted} tail={tail.hex()} -> {r}")
            if not check(f"B/cs={cs}/n={n}"):
                return
        print(f"   cs={cs:<4} swept lengths 127..512, quoted and bare, 6 tails  OK")


def group_c():
    print("C  net_realloc and the copy_fix allocation")
    caps = BASE | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH
    MAXP = 0xFFFFFF

    # Single packets straddling net_buffer_length and the allocator's rounding.
    for total in (16383, 16384, 16385, 16392, 20480, 65536, 1 << 20):
        head = (struct.pack("<I", caps) + struct.pack("<I", 0x01000000) +
                bytes([45]) + b"\x00" * 19 + struct.pack("<I", 0))
        pkt = head + b"deep_c\x00" + b"\x00"
        db = b"d" * (total - len(pkt) - 1 - len(b"mysql_native_password") - 1)
        pkt += db + b"\x00" + b"mysql_native_password" + b"\x00"
        try:
            c = Conn(HOST, PORT, timeout=60.0)
            c.read_greeting()
            c.send_packet(pkt)
            resp = c.read_packet()
            tag = ("err%d" % struct.unpack('<H', resp[1:3])[0]
                   if resp and resp[:1] == b"\xff" else str(resp and resp[:4].hex()))
            c.close()
        except OSError as exc:
            tag = f"io:{exc}"
        print(f"   single packet len={total:<9} -> {tag}")
        if not check(f"C/single={total}"):
            return

    # A ~16 MB database field: THD::copy_fix() sizes its allocation as
    # mbmaxlen * src_length, i.e. about 48 MB for one connection.
    head = (struct.pack("<I", caps) + struct.pack("<I", 0x01000000) +
            bytes([45]) + b"\x00" * 19 + struct.pack("<I", 0))
    pkt = head + b"deep_c2\x00" + b"\x00"
    db = b"d" * (MAXP - len(pkt) - 2 - len(b"mysql_native_password"))
    pkt += db + b"\x00" + b"mysql_native_password" + b"\x00"
    print(f"   max single packet len={len(pkt)} (db={len(db)})")
    try:
        c = Conn(HOST, PORT, timeout=180.0)
        c.read_greeting()
        c.send_packet(pkt)
        resp = c.read_packet()
        print("     ->", "err%d" % struct.unpack('<H', resp[1:3])[0]
              if resp and resp[:1] == b"\xff" else resp and resp[:4].hex())
        c.close()
    except OSError as exc:
        print("     -> io:", exc)
    if not check("C/max-single"):
        return

    # The one legal pre-auth multi-packet sequence: 0xffffff then a zero-length
    # continuation. Anything non-zero in the second packet is refused by
    # net_realloc() against max_allowed_packet.
    try:
        c = Conn(HOST, PORT, timeout=180.0)
        c.read_greeting()
        body = (head + b"deep_c3\x00" + b"\x00" +
                b"d" * (MAXP - len(head) - 9 - 22) + b"\x00" +
                b"mysql_native_password" + b"\x00")
        body = body[:MAXP]
        c.sock.sendall(struct.pack("<I", MAXP)[:3] + bytes([c.seq]) + body)
        c.sock.sendall(struct.pack("<I", 0)[:3] + bytes([(c.seq + 1) & 0xff]))
        resp = c.read_packet()
        print("   multi-packet 0xffffff+0 ->",
              "err%d" % struct.unpack('<H', resp[1:3])[0]
              if resp and resp[:1] == b"\xff" else resp and resp[:4].hex())
        c.close()
    except OSError as exc:
        print("   multi-packet 0xffffff+0 -> io:", exc)
    check("C/multi-packet")


def group_d():
    print("D  charset sweep over every collation id 0..255")
    caps = BASE | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH
    # Lead bytes with no trail, truncated 3- and 4-byte sequences, SS2/SS3
    # introducers, and bytes that are valid lead bytes in several encodings.
    evil = [b"\x8f", b"\x8e", b"\xa1", b"\xfe\xfe", b"\xf0\x9f", b"\xe4",
            b"\xc3", b"\x81\x40", b"\xff\xff\xff", b"\x8f\xa1"]
    bad = 0
    for cs in range(256):
        for e in evil:
            r = send(caps, cs, b"sweep" + e, b"", b"db" + e)
            if r.startswith(("connect-failed", "closed", "no-greeting")):
                print(f"   cs={cs} seq={e.hex()} -> {r}")
                bad += 1
        if cs % 64 == 63:
            print(f"   ... through id {cs}")
            if not check(f"D/cs={cs}"):
                return
    print(f"   swept 256 ids x {len(evil)} sequences, anomalies={bad}")
    check("D/end")


def main():
    print(f"target {HOST}:{PORT}")
    if not server_alive(HOST, PORT):
        print("server not reachable")
        return 2
    t0 = time.time()
    for g in (group_a, group_b, group_c, group_d):
        g()
        if fails:
            break
    print(f"\nelapsed {time.time()-t0:.0f}s  dead-after: {fails or 'none'}")
    print(f"server alive at end: {server_alive(HOST, PORT, timeout=20.0)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
