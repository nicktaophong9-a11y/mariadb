#!/usr/bin/env python3
"""Enumerate indirect calls inside the *measured* pre-auth function set.

This is the control-flow dual of the write enumeration: a memory-corruption RCE
needs an unbounded write, but a control-flow hijack only needs a function
pointer that attacker-influenced data can select, or one read before it is
initialised. Works on the binary rather than the source so that nothing is
missed through macros, templates, or virtual dispatch.

  classification
    reg    : call *%reg / jmp *%reg          -- pointer in a register
    mem    : call *off(%reg)                 -- pointer loaded from memory
    got    : call *off(%rip)                 -- GOT slot, i.e. a plain extern
"""
import re, subprocess, sys

setfile, binary = sys.argv[1], sys.argv[2]
want = {l.strip() for l in open(setfile) if l.strip()}

fn_re = re.compile(r"^[0-9a-f]+ <(.+)>:$")
ins_re = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )*\s*(.*)$")

p = subprocess.Popen(["objdump", "-d", "-C", "--no-show-raw-insn", binary],
                     stdout=subprocess.PIPE, text=True, bufsize=1 << 20,
                     errors="replace")
cur = None
hot = False
found = {}
nfn = 0
for line in p.stdout:
    m = fn_re.match(line)
    if m:
        cur = m.group(1)
        # objdump appends things like "[clone .cold]"; normalise
        base = cur.split(" [clone")[0]
        hot = base in want
        if hot:
            nfn += 1
        continue
    if not hot:
        continue
    m = ins_re.match(line)
    if not m:
        continue
    addr, text = m.group(1), m.group(2).strip()
    if not (text.startswith("call") or text.startswith("jmp")
            or text.startswith("notrack")):
        continue
    if "*" not in text:
        continue
    if "(%rip)" in text:
        kind = "got"
    elif re.search(r"\*-?0x[0-9a-f]+\(|\*\(", text):
        kind = "mem"
    else:
        kind = "reg"
    found.setdefault(cur, []).append((addr, kind, text))
p.stdout.close(); p.wait()

tot = {"reg": 0, "mem": 0, "got": 0}
for fn, sites in found.items():
    for _, k, _ in sites:
        tot[k] += 1
print(f"measured functions located in binary: {nfn} / {len(want)}")
print(f"indirect sites: reg={tot['reg']}  mem={tot['mem']}  got={tot['got']}")
print()
print("### register- and memory-operand indirect calls (the interesting ones)")
for fn in sorted(found):
    sites = [s for s in found[fn] if s[1] != "got"]
    if not sites:
        continue
    print(f"\n-- {fn}")
    for addr, kind, text in sites:
        print(f"   {addr}  {kind:3}  {text}")
