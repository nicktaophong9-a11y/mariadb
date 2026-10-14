# Ready-to-send text

The reports are self-contained; this is the wrapper each channel wants, so
nothing has to be rewritten at the point of sending.

---

## A. Private disclosure — reports 1, 2, 3

**To:** `security@mariadb.org`
**Subject:** Pre-authentication out-of-bounds reads and a charset-table publication race in 11.8–13.0 (+ two fail-open paths in the auth decision)
**Attach:** `01-preauth-oob-reads-handshake.md`, `02-charset-table-published-before-fill.md`, `03-auth-decision-fail-open.md`, `research-build.patch`

> Hello,
>
> Three findings from an audit of the pre-authentication path, against the
> official `mariadb:latest` image (13.0.2,
> `sha256:91c5269137b38b70bfe2d265ad010359a9aa33dacf2af5e1fa46c5ea16a8eb65`)
> and a matching ASAN build. Each attached report has impact, reproduction,
> root cause and a patch that was applied and tested.
>
> 1. **Five out-of-bounds reads in `parse_client_handshake_packet()`**, reachable
>    from one unauthenticated packet on 3306. Four share a root cause —
>    `passwd = strend(user)+1` can land one byte past the packet when the
>    username fills it — and two of those cross the end of the `net->buff`
>    allocation. The fifth is the post-TLS re-read, which re-checks `pkt_len`
>    against 6 rather than 32 while still using capabilities from the pre-TLS
>    packet, so offsets 4..8 are read out of a 6-byte packet.
>
>    I want to be straight about severity: every value read is discarded by a
>    check that runs *after* the read, so I could not build a disclosure path,
>    and crossing the allocation needs the bytes after `net->buff` to contain no
>    zero, which the attacker does not supply — I tried to groom it through the
>    `THD` reuse in `do_handle_one_connection()` and could not. The ceiling I
>    can argue for is a crash. I am reporting it as a correctness problem, and
>    because the source comment above one of the branches states an invariant
>    the code does not have.
>
> 2. **`create_fromuni()` publishes `cs->tab_from_uni` before filling it** and
>    writes the end-of-list marker last, while `my_wc_mb_8bit()` walks that
>    array from another connection's pre-auth error-message conversion with no
>    mutex. Both ends are driven by unauthenticated input: the writer by one
>    connection's collation-id byte, the reader by another's username.
>
>    On x86-64 this is safe, because `MY_CS_READY` is stored after the fills and
>    stores are not reordered there — but nothing in the code provides that
>    ordering, the fast-path load is a plain load, and the mutex's release edge
>    only helps a thread that acquires it. On aarch64 or ppc64 a reader can see
>    the flag without the fills and then dereference an uninitialised
>    `idx->tab` with an index derived from the attacker's username, one byte of
>    which goes into the error packet. I had no aarch64 machine, so that half is
>    argued rather than demonstrated, and it is the part worth checking.
>
> 3. **Two fail-open paths in the authentication decision** —
>    `do_auth_once()`'s `default:` leaves `res` at the `CR_OK` it was
>    initialised with, so a plugin with an unexpected `interface_version` would
>    be granted a login without `authenticate_user()` being called; and the
>    unknown-user guard compares `res == CR_OK` where it means any success, so
>    `CR_OK_HANDSHAKE_COMPLETE` would slip past it. Neither is reachable with
>    any shipped plugin — all declare `0x0203`, and no server-side plugin
>    returns `-2`, which `plugin_auth_common.h` documents but does not enforce.
>    Three lines each; sent here rather than to JIRA only because of where they
>    sit.
>
> Verified present in 11.8.4, 12.0.2, 13.0.2 and current trunk by extracting
> the affected functions from each and comparing; the relevant files are
> byte-identical in trunk, so none of this is already fixed.
>
> `research-build.patch` is every change I made to a 13.0.2 tree, with the
> instrumentation separated from the proposed fixes. Happy to retest anything,
> and glad to hold off on publishing for as long as you need.

---

## B. MDEV — report 4

**Summary:** `-DWITH_TSAN=ON` builds a server that segfaults in the dynamic loader
**Affects:** 13.0.2, trunk (`vector_mhnsw.cc` is newer than 11.8)
**Component:** Build / Tests

> `cmake -DWITH_TSAN=ON` links, but the resulting `mariadbd` segfaults before
> printing anything, including for `--version`, with no ThreadSanitizer
> diagnostic. The backtrace is in the loader:
>
> ```
> #1 FVector::alloc_size(unsigned long) [clone .resolver]  sql/vector_mhnsw.cc:494
> #2 elf_machine_rela (skip_ifunc=..., reloc_addr_arg=... <*ABS*@got.plt>)
> #4 _dl_relocate_object
> ```
>
> `sql/bloom_filters.h` defines function-multiversioning macros
> (`target("default")`, `target("avx2,avx,fma")`, `target("avx512f,avx512bw")`)
> which `vector_mhnsw.cc` applies to the `FVector` helpers. GCC emits an ifunc,
> instruments the generated `.resolver` like any other function, and the loader
> calls it during relocation — before `__tsan_init()`. A sanitizer must not
> instrument an ifunc resolver, and GCC does not exclude compiler-generated ones
> automatically.
>
> Workaround that gets a working TSAN server:
>
> ```cmake
> IF(WITH_TSAN)
>   SET_SOURCE_FILES_PROPERTIES(vector_mhnsw.cc PROPERTIES COMPILE_OPTIONS "-fno-sanitize=thread")
> ENDIF()
> ```
>
> Coarse — it drops race detection for that translation unit. Marking the
> multiversioned functions, or having the macros carry
> `no_sanitize("thread")` under `__SANITIZE_THREAD__`, would be narrower. The
> same hazard applies to any sanitizer that instruments function entry.
>
> One more thing needed to start: TSAN's shadow mappings leave too little
> address space for the default `innodb_buffer_pool_size_max`, so it fails with
> `InnoDB: Cannot map innodb_buffer_pool_size_max=8388608m`.
> `--innodb-buffer-pool-size-max=256M` is enough. Worth a line in the build
> docs.

---

## C. MDEV — report 5

**Summary:** Pre-auth `memcpy` bounded only by `DBUG_ASSERT`, and an unbounded `strxmov`, in the hostname cache and charset loader
**Affects:** 11.8.4, 12.0.2, 13.0.2, trunk
**Component:** Server

> Two places where the only thing between data and a fixed buffer is an
> assertion the release build does not contain. Neither is reachable with a bad
> length on a default configuration; both are cheap to make unconditional.
>
> `prepare_hostname_cache_key()` (`sql/hostname.cc`) does
> `memcpy(ip_key, ip_string, strlen(ip_string))` into a 46-byte
> (`INET6_ADDRSTRLEN`) destination, with only
> `DBUG_ASSERT(ip_string_length < HOST_ENTRY_KEY_SIZE)` above it. It is reached
> from `inc_host_errors()`, i.e. on every failed login, so the pre-auth path
> depends on every caller producing a string shorter than 46 bytes. They do
> today. `set_if_smaller(ip_string_length, HOST_ENTRY_KEY_SIZE - 1)` makes that
> a bound rather than a hope.
>
> `get_internal_charset()` (`mysys/charset.c`) does
> `strxmov(get_charsets_dir(buf), cs->cs_name.str, ".xml", NullS)`, where
> `get_charsets_dir()` has already filled `buf` with up to `FN_REFLEN - 1`
> bytes. A long `--character-sets-dir` overflows `buf`. Reaching it needs
> control of a startup option, so this is robustness only; `strxnmov()` with
> `sizeof(buf)` removes the question.
>
> The attached report also notes a third site of the same apparent shape where
> the bound turned out to live one frame up in the caller, because the two are
> indistinguishable without following the call chain.
