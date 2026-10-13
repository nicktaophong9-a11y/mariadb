#!/usr/bin/env python3
"""
Pre-auth handshake fuzzer for MariaDB (ZeroDay Cloud 2026 research).

Drives mariadb_preauth.Conn through the pre-authentication state machine with
randomised/edge-case field values and watches for server death. Intended to be
pointed at a server built with ASAN so that any out-of-bounds access aborts the
process and is caught by the liveness check.

Targets the paths reachable before authentication succeeds:
  * parse_client_handshake_packet() field layout and length encodings
  * the pkt_len == 31/32/33 boundary where `end = read_pos + 32` reaches the
    network layer's guaranteed NUL terminator
  * read_client_connect_attrs() length-encoding handling
  * the auth-switch round trip, with a second packet large enough to force
    net_realloc() while cached pointers into net->buff may still be live
  * username selection, which find_mpvio_user() hashes to pick a *real* ACL
    account for unknown users, so different accounts (and therefore different
    server-side auth plugins) get exercised

Usage:  python3 -I preauth_fuzz.py [host] [port] [iterations]
"""

import os
import random
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, lenenc_int, BASE_CAPS,
    CLIENT_CONNECT_WITH_DB, CLIENT_PROTOCOL_41, CLIENT_SSL,
    CLIENT_SECURE_CONNECTION, CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_ATTRS,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_INTERACTIVE,
    CLIENT_IGNORE_SPACE, CLIENT_COMPRESS, CLIENT_MULTI_STATEMENTS,
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS, CLIENT_MYSQL,
)

# Charsets the server accepts pre-auth. is_supported_parser_charset() rejects
# ucs2/utf16/utf32, so the interesting survivors are the multi-byte ones.
CHARSETS = [8, 33, 45, 46, 63, 1,        # latin1, utf8mb3, utf8mb4, binary
            28, 24, 95, 97, 13, 30, 38,  # gbk, gb2312, cp932, eucjpms, sjis
            192, 248, 249,               # gb18030 family
            0, 255, 254, 100, 160]       # invalid / edge ids

PLUGINS = [b"mysql_native_password", b"mysql_old_password", b"unix_socket",
           b"ed25519", b"client_ed25519", b"auth_gssapi_client",
           b"sha256_password", b"caching_sha2_password", b"", b"A" * 300,
           b"\xff\xfe\xfd", b"dialog", b"mysql_clear_password"]

USERS = [b"demo", b"root", b"mysql", b"healthcheck", b"mariadb.sys", b"",
         b"'quoted'", b"\xc3\xa9" * 100, b"\xff" * 200, b"A" * 400,
         b"\x81\x40" * 150, b"\xfe\xfe\xfe\xfe"]


def rnd_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def nonzero_bytes(n):
    return bytes(random.randrange(1, 256) for _ in range(n))


def make_attrs():
    """Connection-attribute blobs, including malformed length prefixes."""
    pick = random.randrange(8)
    if pick == 0:
        return lenenc_int(0)
    if pick == 1:                                 # declares more than it holds
        return lenenc_int(0xffff) + rnd_bytes(random.randrange(0, 32))
    if pick == 2:                                 # 8-byte huge length
        return lenenc_int(0xffffffffffffffff, force=9)
    if pick == 3:                                 # right at the 64k cap
        n = random.choice([65534, 65535, 65536, 65537])
        return lenenc_int(n) + nonzero_bytes(min(n, 300))
    if pick == 4:                                 # truncated prefix only
        return random.choice([b"\xfc", b"\xfd", b"\xfe", b"\xfb"])
    if pick == 5:                                 # well-formed k/v pairs
        blob = b""
        for _ in range(random.randrange(1, 6)):
            k = nonzero_bytes(random.randrange(1, 20))
            v = nonzero_bytes(random.randrange(1, 20))
            blob += lenenc_int(len(k)) + k + lenenc_int(len(v)) + v
        return lenenc_int(len(blob)) + blob
    if pick == 6:                                 # Connector/NET sniff path
        blob = b"\x0c_client_name\x13mysql-connector-net"
        return lenenc_int(len(blob)) + blob
    return nonzero_bytes(random.randrange(1, 40))


def one_case(host, port, rec):
    """Run a single fuzz case; returns True if the case completed cleanly."""
    try:
        c = Conn(host, port, timeout=4.0)
    except OSError as exc:
        rec["error"] = f"connect: {exc}"
        return False
    try:
        if c.read_greeting() is None:
            rec["error"] = "no greeting"
            return False

        caps = BASE_CAPS
        for bit in (CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH,
                    CLIENT_CONNECT_ATTRS, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
                    CLIENT_INTERACTIVE, CLIENT_IGNORE_SPACE,
                    CLIENT_MULTI_STATEMENTS, CLIENT_COMPRESS,
                    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS):
            if random.random() < 0.5:
                caps |= bit
        if random.random() < 0.15:
            caps &= ~CLIENT_SECURE_CONNECTION
        if random.random() < 0.10:
            caps &= ~CLIENT_PROTOCOL_41
        # MariaDB reads the 4 extended-capability bytes only when CLIENT_MYSQL
        # is clear, so flip that too.
        if random.random() < 0.5:
            caps &= ~CLIENT_MYSQL
        else:
            caps |= CLIENT_MYSQL

        auth_len = random.choice([0, 1, 19, 20, 21, 32, 255, 300, 4096])
        pkt = c.build_handshake_response(
            caps=caps,
            ext_caps=random.choice([0, 0xffffffff, random.getrandbits(32)]),
            max_packet=random.choice([0, 1, 0x01000000, 0xffffffff]),
            charset=random.choice(CHARSETS),
            user=random.choice(USERS),
            auth_data=nonzero_bytes(auth_len),
            auth_len_encoding=random.choice([None, 1, 3, 4, 9]),
            db=random.choice([b"demo", b"", nonzero_bytes(random.randrange(1, 80)),
                              b"B" * 300]),
            plugin=random.choice(PLUGINS),
            attrs=make_attrs(),
            raw_tail=random.choice([None, b"", nonzero_bytes(random.randrange(1, 64))]),
            truncate=random.choice([None, None, None, 31, 32, 33, 34, 30, 5, 2,
                                    random.randrange(2, 120)]),
        )
        rec["caps"] = caps
        rec["pkt_len"] = len(pkt)
        rec["pkt"] = pkt.hex()

        split = random.choice([None, None, None, 16, 64])
        c.send_packet(pkt, split_at=split)

        # The server may answer with an auth-switch request. Replying with a
        # body larger than net_buffer_length (16k) forces net_realloc() while
        # the connection is still unauthenticated.
        for _ in range(random.randrange(0, 3)):
            resp = c.read_packet()
            if resp is None:
                break
            if resp[:1] == b"\xff":          # error packet, handshake over
                break
            big = random.random() < 0.5
            size = random.choice([20, 0, 17000, 70000, 300000]) if big else \
                random.choice([0, 20, 21])
            rec.setdefault("replies", []).append(size)
            c.send_packet(nonzero_bytes(size))
        return True
    except OSError as exc:
        rec["error"] = f"io: {exc}"
        return True
    finally:
        c.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3306
    iters = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
    seed = int(os.environ.get("FUZZ_SEED", time.time()))
    random.seed(seed)
    print(f"[*] target {host}:{port}  iterations={iters}  seed={seed}")

    if not server_alive(host, port):
        print("[!] server not reachable at start")
        return 2

    outdir = os.environ.get("FUZZ_OUT", "/tmp/claude-0/preauth-crashes")
    os.makedirs(outdir, exist_ok=True)

    for i in range(1, iters + 1):
        rec = {"iter": i, "seed": seed}
        one_case(host, port, rec)
        if i % 250 == 0:
            alive = server_alive(host, port)
            print(f"[*] {i}/{iters} alive={alive}")
            if not alive:
                path = os.path.join(outdir, f"crash-{seed}-{i}.txt")
                with open(path, "w") as fh:
                    fh.write(repr(rec) + "\n")
                print(f"[!!] SERVER DEAD after iteration {i} -> {path}")
                return 1
    print(f"[*] done; server alive={server_alive(host, port)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
