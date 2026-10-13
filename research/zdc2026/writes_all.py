#!/usr/bin/env python3
"""
Enumerate memory-writing call sites across the *measured* pre-auth function set
(cov-preauth-only.txt), rather than a hand-written list of functions.

Usage: python3 -I writes_all.py <measured-function-list> <source-root>
"""
import os, re, sys
NAMES_FILE = sys.argv[1]           # e.g. cov-preauth-only.txt from the coverage differential
SRC = sys.argv[2].rstrip("/") + "/"  # root of the 13.0.2 source tree
WRITES = re.compile(r"\b(memcpy|memmove|memset|bzero|strcpy|strncpy|strcat|strmov|"
                    r"strnmov|strmake|strmake_buf|sprintf|snprintf|my_snprintf|"
                    r"my_vsnprintf|my_vsnprintf_ex|strfill|int2store|int3store|int4store|"
                    r"int8store|float4store|float8store|memdup|memdup_root|strdup|my_strdup|"
                    r"my_strndup|safe_strcpy|strnxmov|strxmov|strxnmov|strmake_root|"
                    r"strncat|wsprintf|q_append)\s*\(")
# directories where pre-auth code can live; storage engines are not reachable
DIRS = ["sql", "vio", "mysys", "strings", "sql-common", "mysys_ssl", "plugin/auth_socket",
        "dbug", "include"]
EXT = (".c", ".cc", ".cpp", ".h", ".ic", ".inl")

names = set()
for line in open(NAMES_FILE, encoding='utf-8', errors='replace'):
    n = line.strip()
    if not n:
        continue
    n = re.sub(r"\(.*", "", n)          # drop C++ signature
    n = n.split("::")[-1]               # drop class qualification
    n = n.split()[-1] if " " in n else n
    if re.fullmatch(r"[A-Za-z_~][A-Za-z_0-9]*", n):
        names.add(n)

files = []
for d in DIRS:
    base = os.path.join(SRC, d)
    for root, _dirs, fs in os.walk(base):
        if "/storage/" in root or "/test" in root:
            continue
        for f in fs:
            if f.endswith(EXT):
                files.append(os.path.join(root, f))

def defs_in(src, name):
    """Yield (start_line, body) for each plausible definition of `name`."""
    out = []
    i = 0
    while True:
        i = src.find(name, i)
        if i == -1:
            return out
        # identifier boundaries
        if (i and (src[i-1].isalnum() or src[i-1] == '_')):
            i += len(name); continue
        j = i + len(name)
        if j < len(src) and (src[j].isalnum() or src[j] == '_'):
            i = j; continue
        k = j
        while k < len(src) and src[k] in ' \t\n':
            k += 1
        if k < len(src) and src[k] == '(':
            brace = src.find('{', k); semi = src.find(';', k)
            if brace != -1 and (semi == -1 or brace < semi):
                ls = src.rfind('\n', 0, i) + 1
                prefix = src[ls:i].strip()
                if prefix == "" or re.fullmatch(r"(static\s+|inline\s+|extern\s+|const\s+)*[A-Za-z_][\w \*&:<>,]*", prefix):
                    depth = 0; p = brace
                    while p < len(src):
                        if src[p] == '{': depth += 1
                        elif src[p] == '}':
                            depth -= 1
                            if depth == 0:
                                out.append((src.count('\n', 0, i) + 1, src[i:p+1]))
                                break
                        p += 1
        i = j

total = 0
found_fns = set()
report = {}
for path in files:
    try:
        src = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        continue
    for name in names:
        if name not in src:
            continue
        for startline, body in defs_in(src, name):
            hits = []
            for mo in WRITES.finditer(body):
                ln = startline + body.count('\n', 0, mo.start())
                line = body[body.rfind('\n', 0, mo.start())+1: body.find('\n', mo.start())].strip()
                hits.append((ln, line[:116]))
            if hits:
                found_fns.add(name)
                key = (os.path.relpath(path, SRC), name)
                report[key] = hits
                total += len(hits)

for (rel, name) in sorted(report):
    print(f"-- {rel} :: {name}")
    for ln, line in report[(rel, name)]:
        print(f"     {ln}: {line}")
print(f"\nfunctions from the measured set with memory writes: {len(found_fns)}")
print(f"total memory-writing call sites: {total}")
