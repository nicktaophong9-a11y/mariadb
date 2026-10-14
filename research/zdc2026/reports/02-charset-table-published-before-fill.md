# `create_fromuni()` publishes `cs->tab_from_uni` before filling it — pre-auth wild read on weakly-ordered architectures

**Affected:** 11.8.4, 12.0.2, 13.0.2, current trunk (verified; code is older)
**Impact:** remote, unauthenticated. Harmless on x86-64 by accident of its
memory model; on aarch64 and ppc64 a reader can dereference an uninitialised
pointer with an attacker-influenced index and have one byte of the result sent
back in an error packet.

## Summary

Lazy charset initialisation publishes the reverse conversion table pointer,
*then* fills the table, *then* writes the end-of-list marker. The reader that
walks that table does so with no mutex and no acquire, and both ends are
reachable before authentication: the writer from one connection's collation-id
byte, the reader from another connection's error-message conversion.

On x86-64 the publish of `MY_CS_READY` after the fills, combined with the
architecture not reordering stores, is enough to make it safe. Nothing in the
code provides that ordering, so on a weakly-ordered build it is not safe.

## The write side

`strings/ctype-simple.c`, end of `create_fromuni()`:

```c
  /* Allocate and fill reverse table for each plane */
  n=i;
  if (!(cs->tab_from_uni= (MY_UNI_IDX *)
                          (loader->once_alloc)(sizeof(MY_UNI_IDX) * (n + 1))))
    return TRUE;                                        /* pointer published */

  for (i=0; i< n; i++)
    ((struct my_uni_idx_st*)cs->tab_from_uni)[i]= idx[i].uidx;   /* entries after */

  /* Set end-of-list marker */
  bzero((char*) &cs->tab_from_uni[i],sizeof(MY_UNI_IDX));        /* terminator last */
```

`my_once_alloc()` is a bump pointer over plain `malloc()` blocks and does not
zero, so between the publish and the fill the entries hold pool contents.

Reached pre-auth as:

```
  create_fromuni                strings/ctype-simple.c:1458
  my_cset_init_8bit             strings/ctype-simple.c:1547
  my_ci_init_charset            include/m_ctype.h:1296
  get_internal_charset          mysys/charset.c:908
  get_charset                   mysys/charset.c:940
  thd_init_client_charset       sql/sql_connect.cc:865
  parse_client_handshake_packet sql/sql_acl.cc:14612      <-- collation id byte
```

## The read side

`my_wc_mb_8bit()` walks the table with the terminator as its only bound and
then indexes through whatever it finds:

```c
  for (idx=cs->tab_from_uni; idx->tab ; idx++)
  {
    if (idx->from <= wc && idx->to >= wc)
    {
      str[0]= idx->tab[wc - idx->from];
```

Reached pre-auth as:

```
  my_wc_mb_8bit                 strings/ctype-simple.c:347
  my_wc_to_printable_ex          strings/ctype.c:1077
  my_wc_to_printable_8bit        strings/ctype.c:1125
  my_convert_using_func          strings/ctype.c:1198
  convert_error_message          sql/sql_error.cc:1016
  Protocol::net_send_error_packet sql/protocol.cc:445
  Protocol::end_statement        sql/protocol.cc:593
  login_connection               sql/sql_connect.cc:1253
```

A reader that observed the pointer but not the fills walks past the
not-yet-written terminator and evaluates `idx->tab[wc - idx->from]` on an
uninitialised `idx->tab` with an uninitialised `idx->from`. `wc` is the
codepoint from the attacker's own username, being converted for the error
packet, and `str[0]` goes into that packet.

## Why x86-64 is safe, and why that is not the code's doing

`get_internal_charset()` hands out a `cs` two ways:

```c
    if (cs->state & MY_CS_READY)       /* unsynchronised fast path */
    { my_collation_statistics_inc_use_count(cs_number); return cs; }
    mysql_mutex_lock(&THR_LOCK_charset);
    ... my_ci_init_charset(cs, loader) ...  /* create_fromuni runs here */
    cs->state|= MY_CS_READY;                /* set last */
    mysql_mutex_unlock(&THR_LOCK_charset);
```

`MY_CS_READY` is stored after `create_fromuni()` has finished. On x86-64 stores
are not reordered with other stores, so a thread that observes the flag also
observes `tab_from_uni`, the entries and the terminator.

But the fast-path load of `cs->state` is a plain load and the publish is a
plain store. The mutex's release edge orders things only for a thread that
*acquires* the same mutex, which the fast path never does. On aarch64 or
ppc64 the reader can observe `MY_CS_READY` while the preceding stores are still
invisible to it, and then the paragraph above happens for real.

So this is a correct-by-architecture double-checked lock, not a correct one.

## Reproduction

ThreadSanitizer reports the pair directly. Note that `-DWITH_TSAN=ON` does not
currently produce a runnable server — see report 4 — so the fix there is needed
first.

```sh
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DWITH_TSAN=ON \
      -DWITH_SSL=system -DWITH_WSREP=OFF -DWITH_EMBEDDED_SERVER=OFF
# plus the one-file exclusion from report 4, and
# --innodb-buffer-pool-size-max=256M, because TSAN's shadow mappings leave too
# little address space for the 8 TB default reservation
python3 -I preauth_concurrent.py 127.0.0.1 3307 32 600
python3 -I poc_collation_race.py 127.0.0.1 3307
```

Over ~250,000 pre-auth rounds we saw 328 reports; all but this one are
counters, the deliberately-unlocked global `sql_rand`, or InnoDB's AIO
bookkeeping. This is the only one on a pointer:

```
  Read of size 8 by thread T15:                      /* no mutex */
    #0 my_wc_mb_8bit                 strings/ctype-simple.c:347
    #4 convert_error_message          sql/sql_error.cc:1016
    #8 login_connection               sql/sql_connect.cc:1253

  Previous write of size 8 by thread T80 (mutexes: write M0):
    #0 create_fromuni                 strings/ctype-simple.c:1458
    #5 thd_init_client_charset        sql/sql_connect.cc:865
    #6 parse_client_handshake_packet   sql/sql_acl.cc:14612
```

The narrower race on `cs->state` itself also shows up, with the reader in
`my_charset_get_by_name()` from `send_server_handshake_packet()` — i.e. another
connection's greeting generation.

On x86-64 we could not turn any of this into an observable effect, as the
reasoning above predicts. We did not have an aarch64 machine to try on, so the
weakly-ordered case is argued rather than demonstrated; it is the part worth
checking.

## Patch

Two independent changes; the first removes the window under any memory model
and is worth doing on its own:

```diff
   /* Allocate and fill reverse table for each plane */
   n=i;
-  if (!(cs->tab_from_uni= (MY_UNI_IDX *)
-                          (loader->once_alloc)(sizeof(MY_UNI_IDX) * (n + 1))))
+  MY_UNI_IDX *tab_from_uni= (MY_UNI_IDX *)
+                            (loader->once_alloc)(sizeof(MY_UNI_IDX) * (n + 1));
+  if (!tab_from_uni)
     return TRUE;
 
   for (i=0; i< n; i++)
-    ((struct my_uni_idx_st*)cs->tab_from_uni)[i]= idx[i].uidx;
+    ((struct my_uni_idx_st*)tab_from_uni)[i]= idx[i].uidx;
 
   /* Set end-of-list marker */
-  bzero((char*) &cs->tab_from_uni[i],sizeof(MY_UNI_IDX));
+  bzero((char*) &tab_from_uni[i],sizeof(MY_UNI_IDX));
+  cs->tab_from_uni= tab_from_uni;          /* publish once it is complete */
   return FALSE;
```

and the double-checked lock needs the ordering it is relying on: a release
store of `cs->state |= MY_CS_READY` under the mutex with an acquire load on the
fast path.

### What testing the first half showed

Applied to a research build, the raced write in the ThreadSanitizer report
moves from `ctype-simple.c:1458` — the allocation line, publishing a table with
no entries and no terminator — to `:1474`, the single `cs->tab_from_uni=
tab_from_uni;` at the end. So after the patch a reader observes either the old
value or a complete table, which is the property that matters.

ThreadSanitizer still reports the pair, and that is expected: it reports the
absence of a happens-before edge, not inconsistent data, and a plain store
racing a plain load has no such edge however complete the table is. Closing
that is the second half of the patch. We exercised the first half only.

### The sibling sites

The same publish-then-fill shape appears twice more, both reached through the
same lazy init, and both worth the same treatment even though their readers are
weaker (pre-auth they are reached with `system_charset_info` rather than an
attacker-chosen charset):

* `init_state_maps()` (`mysys/charset.c:66`) publishes `cs->state_map` and
  derives `cs->ident_map` from it before either half is filled;
* `ctype-uca.c:34803` publishes `cs->uca` before populating it.
