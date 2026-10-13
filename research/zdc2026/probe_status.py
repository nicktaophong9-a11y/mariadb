#!/usr/bin/env python3
"""Minimal authenticated client over the unix socket: reads status variables.

Used only to read MariaDB's own live-memory accounting (Memory_used), which is
independent of RSS and therefore of the ASAN allocator's high-water behaviour.
"""
import hashlib, socket, struct, sys

def sha1(b): return hashlib.sha1(b).digest()
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))

def native(pw, salt):
    if not pw: return b""
    s1 = sha1(pw)
    return xor(s1, sha1(salt + sha1(s1)))

class C:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(20); self.s.connect(path); self.seq = 0
    def send(self, p):
        self.s.sendall(struct.pack("<I", len(p))[:3] + bytes([self.seq]) + p)
        self.seq = (self.seq + 1) & 0xff
    def recv(self):
        h = self._n(4)
        ln = h[0] | h[1] << 8 | h[2] << 16
        self.seq = (h[3] + 1) & 0xff
        return self._n(ln)
    def _n(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c: raise EOFError
            b += c
        return b
    def close(self): self.s.close()

def lenenc(buf, i):
    v = buf[i]
    if v < 0xfb: return v, i + 1
    if v == 0xfb: return None, i + 1
    if v == 0xfc: return struct.unpack("<H", buf[i+1:i+3])[0], i + 3
    if v == 0xfd: return int.from_bytes(buf[i+1:i+4], "little"), i + 4
    return struct.unpack("<Q", buf[i+1:i+9])[0], i + 9

def lenstr(buf, i):
    n, i = lenenc(buf, i)
    if n is None: return None, i
    return buf[i:i+n], i + n

def login(path, user, pw):
    c = C(path)
    g = c.recv()
    i = g.index(b"\0", 1) + 1 + 4          # proto, version string, thread id
    salt1 = g[i:i+8]; i += 8 + 1
    caps_lo = struct.unpack("<H", g[i:i+2])[0]; i += 2 + 1 + 2
    caps_hi = struct.unpack("<H", g[i:i+2])[0]; i += 2
    alen = g[i]; i += 1 + 6 + 4
    salt2 = g[i:i+max(12, alen - 9)][:12]
    salt = (salt1 + salt2)[:20]
    caps = 0x0001 | 0x0004 | 0x0200 | 0x2000 | 0x8000 | 0x80000
    ar = native(pw.encode(), salt)
    p = (struct.pack("<I", caps) + struct.pack("<I", 0x1000000) + bytes([45]) +
         b"\0" * 19 + struct.pack("<I", 0) +
         user.encode() + b"\0" + bytes([len(ar)]) + ar +
         b"mysql_native_password\0")
    c.send(p)
    r = c.recv()
    if r[0] == 0xff:
        raise SystemExit(f"login failed: {r[3:].decode('utf8','replace')}")
    if r[0] == 0xfe:
        raise SystemExit("server asked for auth switch (wrong plugin/password)")
    return c

def query(c, sql):
    c.seq = 0                      # each command restarts the sequence
    c.send(b"\x03" + sql.encode())
    first = c.recv()
    if first[0] == 0xff: raise SystemExit("query error: " + first[3:].decode("utf8","replace"))
    ncol, _ = lenenc(first, 0)
    for _ in range(ncol): c.recv()
    rows = []
    pending = c.recv()
    if pending[0] == 0xfe and len(pending) < 9:
        pending = None                 # consumed the column-def EOF; rows follow
    while True:
        p = c.recv() if pending is None else pending
        pending = None
        if p[0] == 0xfe and len(p) < 9: break
        i = 0; row = []
        for _ in range(ncol):
            v, i = lenstr(p, i); row.append(v)
        rows.append(row)
    return rows

if __name__ == "__main__":
    path = sys.argv[1]
    pw = sys.argv[2] if len(sys.argv) > 2 else "zerodaycloud1!"
    c = login(path, "root", pw)
    for r in query(c, "SHOW GLOBAL STATUS LIKE 'Memory_used%'"):
        print(f"{r[0].decode()} = {int(r[1]):,}")
    for r in query(c, "SELECT user,host FROM mysql.global_priv ORDER BY user,host"):
        print(f"  acct {r[0].decode()!r}@{r[1].decode()!r}")
    c.close()
