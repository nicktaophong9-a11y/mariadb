#!/usr/bin/env python3
"""
Exhaustively verify MariaDB's charset conversion tables against the index
ranges its lookup helpers actually use.

Motivation: the pre-auth handshake path converts attacker-controlled bytes in
both directions with an attacker-chosen charset. parse_client_handshake_packet()
runs copy_and_convert() over the username and copy_with_error() over the
database name with `thd->charset()`, and net_send_error_packet() runs
convert_error_message() into `thd->variables.character_set_results` -- and
thd_init_client_charset() sets all three charsets from the single collation-id
byte at offset 8 of the handshake response, so the client picks both ends.

The decoders and encoders themselves bound-check against the buffer end, but
each one then indexes a static conversion table. Those tables are declared with
an inferred size (`tab_x[] = {...}`) and indexed as `tab_x[code - LOW]` after an
`if (code >= LOW && code <= HIGH)` guard, so a table shorter than HIGH-LOW+1, or
a guard whose LOW disagrees with the subtracted offset, is an out-of-bounds read
driven directly by the client's bytes.

This script parses every such guard/lookup pair out of the charset sources,
counts the real number of initializer entries for the table it names, and
reports any table that is too short or whose offset does not match its guard.
It is a static check: no server needed.

Usage: python3 -I verify_charset_tables.py [path/to/mariadb/strings]
"""

import os
import re
import sys

# Charsets reachable pre-auth that use the range-guarded table idiom.
# is_supported_parser_charset() requires mbminlen == 1, which excludes
# ucs2/utf16/utf32; gb18030 is not compiled into the official image.
FILES = ["ctype-big5.c", "ctype-gbk.c", "ctype-euc_kr.c", "ctype-gb2312.c"]

# if ((code>=0xLOW)&&(code<=0xHIGH)) return(TABLE[code-0xOFF]);
GUARD = re.compile(
    r"code\s*>=\s*(0x[0-9A-Fa-f]+)\s*\)\s*&&\s*\(\s*code\s*<=\s*(0x[0-9A-Fa-f]+)"
    r"\s*\)\s*\)\s*return\s*\(\s*([A-Za-z_0-9]+)\s*\[\s*code\s*-\s*(0x[0-9A-Fa-f]+)\s*\]")


def count_entries(src, table):
    """Return (declared_size_or_None, number_of_initializer_entries)."""
    m = re.search(r"\b" + re.escape(table) + r"\s*\[\s*([0-9]*)\s*\]\s*=\s*\{", src)
    if not m:
        return None, None
    declared = m.group(1).strip()
    i = m.end() - 1
    depth = 0
    j = i
    while j < len(src):
        if src[j] == '{':
            depth += 1
        elif src[j] == '}':
            depth -= 1
            if depth == 0:
                break
        j += 1
    body = re.sub(r"/\*.*?\*/", "", src[i + 1:j], flags=re.S)
    entries = [x.strip() for x in body.split(',')]
    return (int(declared) if declared else None), len([x for x in entries if x])


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "strings"
    checked = problems = 0
    for name in FILES:
        path = os.path.join(root, name)
        if not os.path.exists(path):
            print(f"=== {name}: not found under {root}")
            continue
        src = open(path, encoding="utf-8", errors="replace").read()
        print(f"=== {name} ===")
        seen = set()
        for mo in GUARD.finditer(src):
            low, high = int(mo.group(1), 16), int(mo.group(2), 16)
            table, off = mo.group(3), int(mo.group(4), 16)
            if (table, low, high) in seen:
                continue
            seen.add((table, low, high))
            need = high - low + 1
            _, n = count_entries(src, table)
            checked += 1
            if n is None:
                print(f"  {table:22s} initializer NOT FOUND")
                problems += 1
                continue
            ok = (off == low) and (n >= need)
            if not ok:
                problems += 1
            print(f"  {table:22s} range[{low:#06x}..{high:#06x}] "
                  f"need={need:6d} entries={n:6d} off={off:#06x} "
                  f"{'OK' if ok else '*** MISMATCH ***'}")
    print(f"\nchecked {checked} range-indexed tables, problems={problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
