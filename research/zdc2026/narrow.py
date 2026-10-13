#!/usr/bin/env python3
"""
Hunt the bug class that actually produced a finding here.

NOTES 4.25 is a bound defeated by a pointer difference going negative and
converting to an unsigned parameter:

    safe_net_field_length_ll((uchar**)&passwd,
                             net->read_pos + pkt_len - (uchar*)passwd)
    my_ulonglong safe_net_field_length_ll(uchar **packet, size_t packet_len);

I found that by accident. Two sibling shapes can go wrong the same way, so this
enumerates both across the pre-auth sources:

  DIFF   a pointer/length difference used as an argument -- negative becomes
         huge when the parameter is unsigned
  CAST   a narrowing or sign-changing cast applied to a length

Usage: narrow.py <source-root> <file> [file ...]
"""
import re, sys

root = sys.argv[1].rstrip("/")
files = sys.argv[2:]

# a difference that involves something length- or pointer-shaped, passed as an
# argument (i.e. preceded by '(' or ',' on the same argument position)
DIFF = re.compile(
    r"[,(]\s*([A-Za-z_][\w.\->\[\]]*(?:\s*\+\s*[\w.\->\[\]]+)?\s*-\s*"
    r"\(?[A-Za-z_][\w.\->\[\]()]*)\s*[,)]")
LENISH = re.compile(r"len|length|size|pos|end|ptr|buff|packet|remain|where_b")
CAST = re.compile(r"\((?:uint|uint32|uint16|int|short|ulong|uchar|u_int32_t)\)\s*"
                  r"\(?\s*([A-Za-z_][\w.\->\[\]]*(?:\s*[-+]\s*[\w.\->\[\]]+)*)")

for f in files:
    path = f"{root}/{f}"
    try:
        lines = open(path, errors="replace").read().split("\n")
    except OSError as e:
        print(f"!! {f}: {e}")
        continue
    hits = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith(("*", "//", "/*")):
            continue
        for m in DIFF.finditer(line):
            expr = m.group(1).strip()
            if "-" in expr and LENISH.search(expr.lower()):
                hits.append((i, "DIFF", expr))
        for m in CAST.finditer(line):
            expr = m.group(1).strip()
            if ("-" in expr or "+" in expr) and LENISH.search(expr.lower()):
                hits.append((i, "CAST", expr))
    if hits:
        print(f"\n===== {f}  ({len(hits)})")
        for i, kind, expr in hits:
            print(f"  {i:6d}  {kind}  {expr[:92]}")
