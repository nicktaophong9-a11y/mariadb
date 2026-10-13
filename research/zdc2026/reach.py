#!/usr/bin/env python3
"""
Static pre-auth reachability, to bound what the coverage differential missed.

NOTES 4.17 (writes) and 4.22 (indirect calls) enumerate over the 290 functions
the coverage differential measured -- i.e. over the code my own traffic
reached. Any pre-auth-reachable function the fuzzers never entered is outside
both enumerations, so "no write primitive" is only as strong as the corpus.

This builds the direct-call graph out of the binary, takes the transitive
closure from the pre-auth entry points, cuts it at the post-auth boundary, and
subtracts the measured set. What is left is pre-auth-reachable code that was
never executed in testing.

Usage: reach.py <binary> <measured-set> <out-prefix>
"""
import re, subprocess, sys
from collections import defaultdict, deque

binary, measured_file, out = sys.argv[1], sys.argv[2], sys.argv[3]

ROOTS = [
    "check_connection(THD*)",
    "acl_authenticate(THD*, unsigned int)",
    "parse_client_handshake_packet(MPVIO_EXT*, unsigned char**, unsigned long)",
    "server_mpvio_read_packet(st_plugin_vio*, unsigned char**)",
    "server_mpvio_write_packet(st_plugin_vio*, unsigned char const*, int)",
    "native_password_authenticate(st_plugin_vio*, st_mysql_server_auth_info*)",
    "do_auth_once(THD*, st_mysql_const_lex_string const*, MPVIO_EXT*)",
    "login_connection(THD*)",
    "thd_prepare_connection(THD*)",
    "my_net_read_packet_reallen(st_net*, unsigned long*, char)",
    "my_real_read(st_net*, unsigned long*, char)",
    "thd_set_peer_addr(THD*, sockaddr_storage*, char const*, unsigned int, bool, unsigned int*)",
    "find_mpvio_user(MPVIO_EXT*)",
    "send_server_handshake_packet(MPVIO_EXT*, char const*, unsigned int)",
    "send_plugin_request_packet(MPVIO_EXT*, unsigned char const*, unsigned int)",
    "read_client_connect_attrs(char**, char*, THD*)",
    "login_failed_error(THD*)",
    "inc_host_errors(char const*, Host_errors*)",
]

# the post-auth boundary: traversal stops here, so the closure stays pre-auth
CUT = {
    "do_command(THD*, bool)",
    "dispatch_command(enum_server_command, THD*, char*, unsigned int, bool)",
    "prepare_new_connection_state(THD*)",
    "set_privs_on_login(THD*, ACL_USER const*)",
    "mysql_parse(THD*, char*, unsigned int, Parser_state*)",
    "mysql_execute_command(THD*, bool)",
    "THD::cleanup()",
    "close_connection(THD*, unsigned int)",
    "unlink_thd(THD*)",
    "end_connection(THD*)",
    "mysql_audit_general(THD*, unsigned int, int, char const*)",
}

fn_re = re.compile(r"^[0-9a-f]+ <(.+)>:$")
call_re = re.compile(r"^\s*[0-9a-f]+:\s+(?:call|jmp)\s+[0-9a-f]+ <([^>]+)>")

edges = defaultdict(set)
allfns = set()
cur = None
p = subprocess.Popen(["objdump", "-d", "-C", "--no-show-raw-insn", binary],
                     stdout=subprocess.PIPE, text=True, bufsize=1 << 20,
                     errors="replace")
for line in p.stdout:
    m = fn_re.match(line)
    if m:
        cur = m.group(1).split(" [clone")[0]
        allfns.add(cur)
        continue
    if cur is None:
        continue
    m = call_re.match(line)
    if m:
        tgt = m.group(1).split("+0x")[0].split(" [clone")[0]
        if tgt != cur:
            edges[cur].add(tgt)
p.stdout.close(); p.wait()

measured = {l.strip() for l in open(measured_file) if l.strip()}

seen, q = set(), deque()
for r in ROOTS:
    if r in allfns or r in edges:
        seen.add(r); q.append(r)
missing_roots = [r for r in ROOTS if r not in seen]
while q:
    f = q.popleft()
    for g in edges.get(f, ()):
        if g in seen or g in CUT:
            continue
        seen.add(g); q.append(g)

unexplored = sorted(seen - measured)
with open(out + "-reachable.txt", "w") as fh:
    fh.write("\n".join(sorted(seen)) + "\n")
with open(out + "-unexplored.txt", "w") as fh:
    fh.write("\n".join(unexplored) + "\n")

print(f"functions in binary          : {len(allfns)}")
print(f"roots resolved               : {len(ROOTS) - len(missing_roots)}/{len(ROOTS)}")
if missing_roots:
    print("  unresolved roots:")
    for r in missing_roots:
        print(f"    {r}")
print(f"statically reachable pre-auth: {len(seen)}")
print(f"measured by coverage         : {len(measured)}")
print(f"measured but not in closure  : {len(measured - seen)}  (indirect/inlined edges)")
print(f"REACHABLE BUT NEVER EXECUTED : {len(unexplored)}")
