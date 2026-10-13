#!/usr/bin/env python3
"""
Enumerate *indexed stores* in the pre-auth function set, on the binary.

4.17 enumerated writes by grepping the source for calls to memcpy, strcpy,
int4store and friends. That misses every ordinary C assignment through a
pointer -- `*p = x`, `arr[i] = v`, `p->f = v` -- because none of them is a
function call. create_fromuni's `tab[ofs]= ch;` is exactly that shape, and the
source-level enumeration never saw it; it was caught by reading the function.

So this does for writes what indirect.py did for calls: works on the binary, so
no assignment can hide behind not being a call. The interesting class is a store
whose destination address is *computed* -- a base register plus a scaled index --
because that is the shape an out-of-bounds index takes. Stores to
`off(%rbp)` / `off(%rsp)` are stack locals at fixed offsets and are listed
separately.

Usage: stores.py <measured-set> <binary>
"""
import re, subprocess, sys
from collections import Counter

setfile, binary = sys.argv[1], sys.argv[2]
want = {l.strip() for l in open(setfile) if l.strip()}

fn_re = re.compile(r"^[0-9a-f]+ <(.+)>:$")
ins_re = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
# a memory destination is the LAST operand and contains (...)
mem_dst = re.compile(r",\s*(-?(?:0x[0-9a-f]+)?\(%[^)]*\))\s*$")
# ... or the instruction has a single memory operand (inc/dec/neg/not/shl...)
mem_only = re.compile(r"^(-?(?:0x[0-9a-f]+)?\(%[^)]*\))$")
scaled = re.compile(r"\(%r[a-z0-9]+,%r[a-z0-9]+,[1248]\)|\(,%r[a-z0-9]+,[1248]\)")
stackish = re.compile(r"\(%r[bs]p\)$")

STORES = {
    "mov", "movb", "movw", "movl", "movq", "movabs",
    "add", "addb", "addl", "addq", "sub", "subl", "subq",
    "or", "orb", "orl", "orq", "and", "andb", "andl", "andq",
    "xor", "xorb", "xorl", "xorq", "inc", "incl", "incq", "dec", "decl", "decq",
    "not", "neg", "shl", "shr", "sar", "sal", "rol", "ror",
    "movzbl", "movsbl", "cmpxchg", "xadd", "xchg", "lock",
    "movups", "movaps", "movdqu", "movdqa", "movss", "movsd", "rep",
}

p = subprocess.Popen(["objdump", "-d", "-C", "--no-show-raw-insn", binary],
                     stdout=subprocess.PIPE, text=True, bufsize=1 << 20,
                     errors="replace")
cur, hot = None, False
per_fn = Counter()
sites = {}
tot = Counter()
for line in p.stdout:
    m = fn_re.match(line)
    if m:
        cur = m.group(1).split(" [clone")[0]
        hot = cur in want
        continue
    if not hot:
        continue
    m = ins_re.match(line)
    if not m:
        continue
    addr, mnem, ops = m.group(1), m.group(2), m.group(3).strip()
    base = mnem.split()[0] if mnem else ""
    if base not in STORES:
        continue
    d = mem_dst.search(ops)
    dst = d.group(1) if d else (ops if mem_only.match(ops) else None)
    if dst is None:
        continue
    if stackish.search(dst) and not scaled.search(dst):
        tot["stack"] += 1
        continue
    if scaled.search(dst):
        tot["indexed"] += 1
        per_fn[cur] += 1
        sites.setdefault(cur, []).append((addr, mnem, ops))
    else:
        tot["base"] += 1
p.stdout.close(); p.wait()

print(f"store destinations in the pre-auth set:")
print(f"  scaled-index (computed address) : {tot['indexed']}")
print(f"  base+displacement               : {tot['base']}")
print(f"  stack locals                    : {tot['stack']}")
print(f"\nfunctions with scaled-index stores: {len(per_fn)}")
for fn, n in per_fn.most_common(30):
    print(f"  {n:4d}  {fn[:94]}")
import json
json.dump({k: v for k, v in sites.items()}, open(setfile + ".stores.json", "w"))
