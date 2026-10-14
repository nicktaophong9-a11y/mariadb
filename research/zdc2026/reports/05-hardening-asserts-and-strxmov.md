# Hardening: a pre-auth `memcpy` bounded only by `DBUG_ASSERT`, and one unbounded `strxmov`

**Affected:** 11.8.4, 12.0.2, 13.0.2, current trunk (verified)
**Impact:** neither is reachable with a bad length on a default configuration.
Both are cases where the only thing standing between attacker-influenced data
and a fixed buffer is an assertion the shipped binary does not contain.

## Finding A — `prepare_hostname_cache_key()`

`sql/hostname.cc`:

```c
static void prepare_hostname_cache_key(const char *ip_string, char *ip_key)
{
  size_t ip_string_length= strlen(ip_string);
  DBUG_ASSERT(ip_string_length < HOST_ENTRY_KEY_SIZE);

  memset(ip_key, 0, HOST_ENTRY_KEY_SIZE);
  memcpy(ip_key, ip_string, ip_string_length);
}
```

`HOST_ENTRY_KEY_SIZE` is `INET6_ADDRSTRLEN`, 46. In a release build the
`DBUG_ASSERT` is nothing, so the `memcpy` length is whatever `strlen(ip_string)`
returns, into a 46-byte destination. It is reached from `inc_host_errors()`,
i.e. on every failed login, so the pre-auth path depends on every caller
producing a string shorter than 46 bytes.

Today they all do — `ip_string` comes from `vio_peer_addr()`'s
`inet_ntop()` into a `char ip_string[128]`, and `hostname_cache_init()` creates
the cache regardless of `host_cache_size`, so `skip-name-resolve` and
`host-cache-size=0` do not take this path out of the build. We could not reach
it with anything long: the container we tested has no IPv6
(`Failed to create a socket for IPv6 '::': errno: 97`), and a scope-ID form like
`fe80::1%some-long-interface-name` is the only shape we can think of that might
exceed 46.

The fix is a bound rather than an assertion:

```diff
   size_t ip_string_length= strlen(ip_string);
   DBUG_ASSERT(ip_string_length < HOST_ENTRY_KEY_SIZE);
+  set_if_smaller(ip_string_length, HOST_ENTRY_KEY_SIZE - 1);
 
   memset(ip_key, 0, HOST_ENTRY_KEY_SIZE);
   memcpy(ip_key, ip_string, ip_string_length);
```

## Finding B — `get_internal_charset()`'s path construction

`mysys/charset.c`:

```c
      strxmov(get_charsets_dir(buf), cs->cs_name.str, ".xml", NullS);
```

`get_charsets_dir()` fills `buf` with up to `FN_REFLEN - 1` bytes of
`charsets_dir` and returns a pointer to its end; `strxmov` then appends with no
bound. `buf` is `char buf[FN_REFLEN]`, so a long `--character-sets-dir`
overflows it by `strlen(cs_name) + 4`.

Reaching it needs control of a startup option, which means already owning the
server, so this is robustness rather than a vulnerability. It is also only
entered for a charset that is neither compiled in nor already loaded, and on a
normal build every charset `Index.xml` declares is compiled in, so the branch is
effectively dead. Still an unbounded string concatenation into a fixed buffer:
`strnxmov(buf, sizeof(buf), ...)` or an `my_snprintf()` would remove the
question.

## A note on telling these apart

While auditing we flagged a third site of the same apparent shape and were
wrong about it, which seems worth passing on because the two are
indistinguishable by eye:

```c
static inline void my_collation_statistics_inc_use_count(uint id)
{
  DBUG_ASSERT(my_collation_is_known_id(id));
  my_collation_statistics[id].use_count++;
}
```

`my_collation_statistics[MY_ALL_CHARSETS_SIZE]` is 4096 entries, the assertion
is gone in a release build, the caller `get_internal_charset()` opens with
another `DBUG_ASSERT(cs_number < array_elements(all_charsets))` before indexing
`all_charsets[cs_number]`, and `parse_com_change_user_packet()` reaches
`thd_init_client_charset()` with `uint2korr(next_field)` — sixteen bits, against
a 4096-entry array — while `thd_init_client_charset()` does not bound its
argument either. That reads like an out-of-bounds read used as a
`CHARSET_INFO *` plus an out-of-bounds increment at a chosen offset.

It is not, because the real bound is one frame further up in `get_charset()`:

```c
  if (cs_number < array_elements(all_charsets))
  {
    ...
    cs= get_internal_charset(&loader, cs_number, flags);
  }
```

So both of those assertions restate a check the caller already performs, while
finding A's assertion *is* the only check. If the project wanted to make that
distinction visible, the restating ones could say so — or, better, the bound
could live with the array access instead of at the top of the call chain, so
that reading the function tells you whether it is safe.
