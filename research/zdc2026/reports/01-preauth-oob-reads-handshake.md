# Pre-authentication out-of-bounds reads in `parse_client_handshake_packet()`

**Affected:** 11.8.4, 12.0.2, 13.0.2, current trunk (verified; code is older)
**Reporter:** found while auditing the pre-auth path for ZeroDay Cloud 2026
**Impact:** remote, unauthenticated, read-only. See *Impact* below — we do not
think this is remotely exploitable for disclosure or for a reliable crash, and
we say why.

## Summary

Five out-of-bounds reads reachable from a single unauthenticated packet on
3306. Four of them share one root cause; the fifth is separate. In every case
the value read is discarded by a check that runs *after* the read, so the
consequence is the read itself. Two of the four cross the end of the
`net->buff` heap allocation when the memory after it happens to contain no zero
byte; the rest stay inside it.

They are reported together because the fix for the first four is two bounds
checks in one function.

## Finding A — `passwd` can point one byte past the packet

`sql/sql_acl.cc`, in `parse_client_handshake_packet()`:

```c
  char *passwd= strend(user)+1;
```

`my_net_read()` guarantees a terminating zero at `net->read_pos[pkt_len]`. If
the username occupies the packet to its final byte and carries no NUL of its
own, `strend(user)` stops on *that* terminator, so `passwd` becomes
`read_pos + pkt_len + 1` — outside the packet. Nothing checks it before the
three branches that consume it, and the comment above the second asserts the
opposite:

```c
  else if (!(thd->client_capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA))
  {
    /* Packet buffer is null-terminated by the network layer, so strend(user)
       stays within bounds and passwd remains within the packet. */
    passwd_len= (uchar)(*passwd++);
  }
```

`net_allocate_new_packet()` and `net_realloc()` allocate
`max_packet + NET_HEADER_SIZE + COMP_HEADER_SIZE + 1`, i.e. `max_packet + 8`,
and set `buff_end = buff + max_packet`, so there are exactly 8 bytes of slack
past `buff_end`. With `pkt_len == max_packet`, `passwd` sits at
`buff + max_packet + 1` and each branch reads a different distance:

| branch | capabilities | consumer | reads | crosses the allocation? |
|---|---|---|---|---|
| A1 | `!CLIENT_SECURE_CONNECTION` | `passwd_len= strlen(passwd)` | unbounded, until a zero | **yes**, if the following memory has no zero |
| A2 | `CLIENT_SECURE_CONNECTION` | `passwd_len= (uchar)(*passwd++)` | 1 byte | no — stays in the 8-byte slack |
| A3 | `+ ..._LENENC_CLIENT_DATA` | `safe_net_field_length_ll()` | up to 9 bytes | **yes**, by 2 bytes |

A3 is the one with a bound that exists and is defeated:

```c
    ulonglong len= safe_net_field_length_ll((uchar**)&passwd,
                            net->read_pos + pkt_len - (uchar*)passwd);
```

```c
my_ulonglong safe_net_field_length_ll(uchar **packet, size_t packet_len);
```

The second parameter is `size_t`. With `passwd == read_pos + pkt_len + 1` the
difference is `-1`, which converts to `SIZE_MAX`, so every internal
`if (packet_len < N) goto err;` passes and the 0xFE case runs
`(*packet)+=9; return uint8korr(pos+1);` with no bound — reading `pos[1..8]`,
which ends at `buff + max_packet + 9` while the last valid byte is
`buff + max_packet + 7`.

The same file already has the correct pattern, 400 lines earlier and also
pre-auth, in `read_client_connect_attrs()`:

```c
  char *ptr_save= *ptr;
  /* not enough bytes to hold the length */
  if (ptr_save >= end)
    return true;
  length= safe_net_field_length_ll((uchar **) ptr, end - ptr_save);
```

`parse_com_change_user_packet()` has the same unguarded shape at
`end - passwd`, but needs an authenticated connection.

## Finding B — the guard does not account for `db_len`

Immediately after the three branches:

```c
  if (passwd == NULL ||
      passwd + passwd_len + MY_TEST(db) > (char*) net->read_pos + pkt_len)
    return packet_error;                 /* bounds passwd + passwd_len + 1 */

  /* strlen() can't be easily deleted without changing protocol */
  db_len= safe_strlen(db);

  char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
  Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);
```

The guard accounts for `passwd_len` but not for `db_len`. `db` is inside the
packet, so `safe_strlen(db)` stops at the packet terminator at worst, putting
`db + db_len` at `read_pos + pkt_len` and `next_field` at
`read_pos + pkt_len + 1`. `Lex_cstring_strlen` is a plain `strlen`, so the scan
is **unbounded** and crosses the allocation under the same condition as A1.

This is the most readily reachable of the five: it needs no legacy or exotic
capability, only `CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB |
CLIENT_PLUGIN_AUTH`, which is what every real client sends.

Its bound exists and is correct — it just runs after the scan that needs it:

```c
  if ((thd->client_capabilities & CLIENT_PLUGIN_AUTH) &&
      (client_plugin.str < (char *)net->read_pos + pkt_len))
    next_field+= strlen(next_field) + 1;
  else
  {
    /* Some clients lie. Sad, but true */
    thd->client_capabilities &= ~CLIENT_PLUGIN_AUTH;
    ...
    client_plugin= native_password_plugin_name;    /* the bad value is replaced */
  }
```

so the out-of-packet plugin name never reaches `cached_client_reply.plugin`.
Nothing between the two sites uses `client_plugin`.

## Finding C — the post-TLS re-read skips the 32-byte minimum

```c
  if (pkt_len < MIN_HANDSHAKE_SIZE)            /* 6 */
    return packet_error;
  ulonglong client_capabilities= uint2korr(net->read_pos);
  if (client_capabilities & CLIENT_PROTOCOL_41)
  {
    if (pkt_len < 32)                          /* first read only */
      return packet_error;
    ...
  }
  if (thd->client_capabilities & CLIENT_SSL)
  {
    ...
    pkt_len= my_net_read(net);                 /* pkt_len replaced */
    if (unlikely(pkt_len == packet_error || pkt_len < NORMAL_HANDSHAKE_SIZE))
      return packet_error;                     /* NORMAL_HANDSHAKE_SIZE is 6 */
  }
  ...
  if (client_capabilities & CLIENT_PROTOCOL_41)      /* caps from the FIRST packet */
  {
    thd->max_client_packet_length= uint4korr(net->read_pos+4);   /* offsets 4..7 */
    if (thd_init_client_charset(thd, (uint) net->read_pos[8]))   /* offset 8 */
    end= (char*) net->read_pos+32;
  }
```

`client_capabilities` comes from the pre-TLS packet and still says
`CLIENT_PROTOCOL_41`, but `pkt_len` now belongs to the post-TLS packet and has
only been checked against 6. Offsets 4..8 are read out of a packet that can be
6 bytes long, and `end` is set to `read_pos + 32` regardless. The byte at
offset 8 is used as a collation id, so an out-of-packet byte selects the
connection charset; `if (end >= (char*) net->read_pos + pkt_len + 2) return
packet_error;` then rejects every `pkt_len <= 30`. The read is deep inside the
buffer, never past the allocation.

A randomised pre-auth fuzzer hit this at iteration 250 of 20,000.

## Reproduction

ASAN build, no special options needed for C; A and B need the memory after
`net->buff` to contain no zero byte, which on a normal heap it does, so the
PoC makes the heap adversarial instead of the packet:

```sh
# A and B: all four branches, packet sized so the slack past buff_end is at its
# 8-byte minimum. 511 is included because ASAN poisons whole 8-byte granules.
ASAN_OPTIONS=malloc_fill_byte=254:max_malloc_fill_size=65536 \
    mariadbd --port=3307 ...
python3 -I poc_passwd_past_end.py strlen    16384 3   # heap-buffer-overflow
python3 -I poc_passwd_past_end.py nextfield 16384 3   # heap-buffer-overflow
python3 -I poc_passwd_past_end.py lenenc    16384 3   # 8-byte read, 2 past the end
python3 -I poc_passwd_past_end.py len1      16384 3   # stays inside the slack

# C: ordinary ASAN run, no heap option
python3 -I poc_post_tls_short_packet.py 127.0.0.1 3307
```

`poc_lenenc_bound.py` isolates A3 and explains the arithmetic in its docstring.
On a stock heap all of A and B are silent (400 reps each); detecting them there
needs the buffer-tail poisoning described in `../NOTES.md` §4.24.

Observed for A3, with the offsets matching the allocation arithmetic exactly
(`my_malloc`'s 32-byte header plus `max_packet + 8` with `max_packet = 16384`):

```
==4817==ERROR: AddressSanitizer: unknown-crash
READ of size 8 at 0x52900004f222
0x52900004f228 is located 0 bytes after 16424-byte region [0x52900004b200,0x52900004f228)
    #0 uint8korr                      include/my_byteorder.h:128
    #1 safe_net_field_length_ll        sql-common/pack.c:110
    #2 parse_client_handshake_packet    sql/sql_acl.cc:14581
    #7 check_connection                 sql/sql_connect.cc:1184
```

ASAN calls it `unknown-crash` rather than `heap-buffer-overflow` because the
8-byte read straddles the boundary; the `located 0 bytes after` line and the
shadow row pin it.

## Impact

Deliberately stated low, because we could not get further:

* **The values are discarded.** For A1–A3 the guard
  `passwd + passwd_len + MY_TEST(db) > read_pos + pkt_len` is unconditionally
  true once `passwd > read_pos + pkt_len`, so the packet is rejected. For B the
  `client_plugin.str < read_pos + pkt_len` test replaces the value with a
  server-side constant. For C the connection is refused by the
  `end >= read_pos + pkt_len + 2` check. So there is no disclosure path.
* **Crossing the allocation needs heap contents the attacker does not supply.**
  No packet write ever reaches the 8 bytes past `buff_end`: `my_net_read()`
  writes the body at `0..pkt_len-1` and a zero at `pkt_len <= max_packet`. We
  tried to groom it through the `THD` reuse in `do_handle_one_connection()`
  (which does hand a reused `THD` a fresh `net->buff` while `net_end()` freed
  the old one, so a stock allocator is likely to return the same chunk) and
  could not, for that reason. Real heaps also contain plenty of zero bytes,
  which is why the stock-heap runs are clean.
* **Ceiling is a crash**, if a scan walks into an unmapped page. For A1 and B
  that needs a zero-free run from the buffer to the end of the mapping.

We think this is worth fixing as a correctness matter and because the comment
in the source states an invariant the code does not have, not because we can
demonstrate an attack.

## Patch

Two checks for A and B — the first bounds all three branches at once, mirroring
`read_client_connect_attrs()`; the second is the existing `:14658` test hoisted
above the scan that needs it:

```diff
    char *passwd= strend(user)+1;
+  if (passwd > (char*) net->read_pos + pkt_len)
+    return packet_error;
```

```diff
    char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
+  if (next_field > (char*) net->read_pos + pkt_len)
+    return packet_error;
    Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);
```

and for C, mirroring the check the first read already has:

```diff
      pkt_len= my_net_read(net);
+    if ((client_capabilities & CLIENT_PROTOCOL_41) && pkt_len != packet_error &&
+        pkt_len < 32)
+      return packet_error;
      if (unlikely(pkt_len == packet_error || pkt_len < NORMAL_HANDSHAKE_SIZE))
        return packet_error;
```

None of these rejects anything that is accepted today: the existing guards
already fail every packet that reaches them in these states.
`next_field == read_pos + pkt_len` must stay legal — that is the terminator's
own position, giving an empty plugin name — which is why the comparison is `>`
and not `>=`.

Applied to a research build, all four branches of A/B go silent at packet
lengths 511, 512 and 16384, and `poc_post_tls_short_packet.py` goes clean.

Also worth considering, though we did not need it for the PoC: the second
parameter of `safe_net_field_length_ll()` is a `size_t` that every caller
computes as a pointer difference. Making it signed, or asserting
non-negativity inside, would have turned A3 into a compile-time or run-time
complaint rather than a silent `SIZE_MAX`.

The comment at the `A2` branch should go, or be corrected: `strend(user)`
staying inside the buffer is not the same as `passwd` staying inside the
packet, and that conflation is what the three branches rely on.
