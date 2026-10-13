#!/usr/bin/env python3
"""
Concurrent pre-authentication stress, plus leak detection by RSS sampling.

Everything up to this point was single-connection: one socket at a time, each
one finishing before the next started. That leaves the whole concurrency axis
untested, which matters because the two write-shaped bugs found so far are both
of that shape -- set_user_salt_if_needed() indexing a shared ACL row with a
stale index (NOTES §4.8), and the cached pointers into net->buff (§4.5).

Shared state that unauthenticated connections touch, and that this exercises
from many threads at once:

  * acl_cache->lock and the acl_users array, via find_mpvio_user() and
    set_user_salt_if_needed(); hammering the *same* username maximises the
    contention on a single ACL row, hammering distinct usernames spreads the
    find_mpvio_user() hash across every row
  * ssl_acceptor_stats and LOCK_ssl_refresh, via concurrent sslaccept()
  * the connection and host-error counters
  * the per-connection net->buff realloc path, driven concurrently

RSS is sampled throughout: a per-connection allocation into a global root (as
opposed to the THD mem_root, which is released when the connection ends) shows
up as monotonic growth that does not come back down.

Usage: python3 -I preauth_concurrent.py [host] [port] [threads] [seconds]
"""

import os
import random
import ssl
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, lenenc_int, BASE_CAPS,
    CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_ATTRS,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_SSL, CLIENT_SECURE_CONNECTION,
    CLIENT_PROTOCOL_41, CLIENT_MYSQL,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3307
NTHREAD = int(sys.argv[3]) if len(sys.argv) > 3 else 32
SECONDS = int(sys.argv[4]) if len(sys.argv) > 4 else 180

MAXP = 0xFFFFFF
stop = threading.Event()
counts = {"ok": 0, "err": 0}
lock = threading.Lock()

# A fixed username keeps every thread on one ACL row; the rest spread the
# find_mpvio_user() hash over all of them.
HOT_USER = b"hammer_one_row"


def nonzero(n):
    return bytes(random.randrange(1, 256) for _ in range(n))


def server_pid():
    import subprocess
    try:
        out = subprocess.run(["pgrep", "-f", os.environ.get("SRV_MATCH", "build-asan/sql/mariadbd")],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.split():
            return int(line)
    except Exception:                                    # noqa: BLE001
        return None
    return None


def rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def one_round(rnd):
    """One pre-auth connection, shape chosen at random."""
    shape = rnd.randrange(10)
    c = Conn(HOST, PORT, timeout=20.0)
    try:
        g = c.read_greeting()
        if g is None:
            return False

        # TLS upgrade on a slice of the connections, so sslaccept() and
        # ssl_acceptor_stats get hit concurrently.
        if shape in (6, 7) and (g["capabilities"] & CLIENT_SSL):
            try:
                c.start_tls()
            except Exception:                            # noqa: BLE001
                return True
        elif shape == 8 and (g["capabilities"] & CLIENT_SSL):
            # Half-open TLS: make sslaccept() fail while others succeed.
            c.send_packet(struct.pack("<I", BASE_CAPS | CLIENT_SSL) +
                          struct.pack("<I", 0x01000000) + bytes([45]) +
                          b"\x00" * 19 + struct.pack("<I", 0))
            c.sock.sendall(nonzero(48))
            return True

        caps = BASE_CAPS | CLIENT_PLUGIN_AUTH
        if rnd.random() < 0.5:
            caps |= CLIENT_CONNECT_WITH_DB
        if rnd.random() < 0.4:
            caps |= CLIENT_CONNECT_ATTRS
        if rnd.random() < 0.3:
            caps |= CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        if rnd.random() < 0.5:
            caps &= ~CLIENT_MYSQL

        # Half the connections pile onto one ACL row, half spread out.
        user = HOT_USER if rnd.random() < 0.5 else \
            b"u%d_%d" % (rnd.randrange(1 << 30), os.getpid())

        pkt = c.build_handshake_response(
            caps=caps,
            charset=rnd.choice([45, 33, 8, 63, 13, 28, 12, 97, 95, 19, 1]),
            user=user,
            auth_data=nonzero(rnd.choice([0, 20, 255])),
            db=rnd.choice([b"demo", nonzero(rnd.randrange(1, 64)), b"d" * 300]),
            plugin=rnd.choice([b"mysql_native_password", b"ed25519",
                               b"unix_socket", b"x" * 100]),
            attrs=rnd.choice([lenenc_int(0), lenenc_int(0xffff) + nonzero(8),
                              nonzero(24)]),
            truncate=rnd.choice([None, None, None, 31, 32, 33]),
        )

        if shape == 9:
            # Oversized multi-packet: exercises net_realloc()'s refusal path
            # from many threads at once.
            c.sock.sendall(struct.pack("<I", MAXP)[:3] + bytes([c.seq]) +
                           b"A" * MAXP)
            c.sock.sendall(struct.pack("<I", 1)[:3] + bytes([(c.seq + 1) & 0xff]) + b"B")
        elif shape == 5:
            c.send_packet(pkt, seq=(c.seq + 1) & 0xff)   # desynced sequence
        else:
            c.send_packet(pkt)

        resp = c.read_packet()
        # Some shapes get an auth-switch; reply big enough to force net_realloc.
        if resp is not None and resp[:1] == b"\xfe" and rnd.random() < 0.5:
            c.send_packet(nonzero(rnd.choice([20, 17000, 40000])))
            c.read_packet()
        return True
    finally:
        c.close()


def worker(idx):
    rnd = random.Random(0xC0FFEE ^ (idx * 2654435761))
    while not stop.is_set():
        try:
            one_round(rnd)
            with lock:
                counts["ok"] += 1
        except OSError:
            with lock:
                counts["err"] += 1
        except Exception:                                # noqa: BLE001
            with lock:
                counts["err"] += 1


def main():
    if not server_alive(HOST, PORT, 15.0):
        print("server not reachable")
        return 2
    pid = server_pid()
    print(f"target {HOST}:{PORT}  threads={NTHREAD}  seconds={SECONDS}  "
          f"server pid={pid}")
    base = rss_kb(pid) if pid else None
    print(f"RSS baseline: {base} kB")

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(NTHREAD)]
    for t in threads:
        t.start()

    samples = []
    t0 = time.time()
    while time.time() - t0 < SECONDS:
        time.sleep(15)
        r = rss_kb(pid) if pid else None
        with lock:
            done = counts["ok"]
            errs = counts["err"]
        samples.append((int(time.time() - t0), r, done))
        alive = server_alive(HOST, PORT, 15.0)
        print(f"  t={int(time.time()-t0):4d}s  RSS={r} kB  rounds={done}  "
              f"ioerr={errs}  alive={alive}")
        if not alive:
            print("  [!!] SERVER DEAD")
            stop.set()
            return 1

    stop.set()
    for t in threads:
        t.join(timeout=20)

    final = rss_kb(pid) if pid else None
    print(f"\nrounds={counts['ok']}  ioerr={counts['err']}")
    print(f"RSS {base} -> {final} kB  (delta {None if not (base and final) else final-base} kB)")
    if samples and base:
        growth = [s[1] - base for s in samples if s[1]]
        print(f"RSS growth samples: {growth}")
    print(f"server alive at end: {server_alive(HOST, PORT, 20.0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
