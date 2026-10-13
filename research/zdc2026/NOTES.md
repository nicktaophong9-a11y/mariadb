# MariaDB — ZeroDay Cloud 2026 pre-auth RCE research notes

Derived from the organisers' official target definition, from the source tree of
the exact version that target runs, and from the official image itself running
locally. No server configuration was changed or added: the container is started
with the compose file's own environment and its only argument, `--local-infile=0`.

## 1. The official target, pinned exactly

From `wiz-sec-public/zeroday-cloud-2026/mariadb`:

* `docker-compose.yaml` → `image: mariadb:latest`, `command: ["--local-infile=0"]`,
  `ports: 3306:3306`, env `MARIADB_ROOT_PASSWORD/DATABASE/USER/PASSWORD`.
* `README.md` → goal is **unauthenticated** RCE on 3306 then `/flag.sh mariadb`.
  Post-auth is explicitly ineligible; the `demo`/`root` credentials are for
  local setup and health checks only and may not be used as a starting point.

Resolving the tag against the registry:

| property | value |
|---|---|
| image version label | `13.0.2-resolute` |
| amd64 manifest digest | `sha256:91c5269137b38b70bfe2d265ad010359a9aa33dacf2af5e1fa46c5ea16a8eb65` |
| reported version | `13.0.2-MariaDB-ubu2604` |
| base image | `ubuntu:resolute` = Ubuntu 26.04.1 LTS |
| OpenSSL in image | `3.5.5-1ubuntu3.7` (mariadbd links `libssl.so.3`/`libcrypto.so.3`) |
| built | 2026-10-02 |
| built from | `MariaDB/mariadb-docker` rev `7359e74de2aa6ef63dd3b8545db5c7e177e72618`, dir `13.0` |
| server package | `mariadb-server-galera=1:13.0.2+maria~ubu2604` from `archive.mariadb.org/mariadb-13.0.2/repo/ubuntu resolute main` |

So the code under test is the **`mariadb-13.0.2` release tag**. Note `latest` is a
moving tag — re-pin before submitting.

## 2. Target configuration, read out of the running container

The image bakes `/etc/mysql/mariadb.conf.d/05-skipcache.cnf` with
`host-cache-size=0` and `skip-name-resolve`, comments out `bind-address`, `log`
and `user` in `/etc/mysql/*.cnf`, and configures no TLS certificate. Confirmed
live:

| variable | value |
|---|---|
| `have_ssl` | **YES** |
| `ssl_cert`, `ssl_key` | *(both empty)* |
| `skip_name_resolve` | ON |
| `host_cache_size` | 0 |
| `local_infile` | OFF |
| `performance_schema` | OFF |
| `max_allowed_packet` | 16777216 |
| `net_buffer_length` | 16384 |
| `userstat` | OFF |
| `proxy_protocol_networks` | *(empty)* |

`have_ssl = YES` with no certificate configured is not a contradiction: see §4.4.

### Loaded authentication plugins

```
mysql_native_password   ACTIVE   PLUGIN_LIBRARY NULL
mysql_old_password      ACTIVE   PLUGIN_LIBRARY NULL
unix_socket             ACTIVE   PLUGIN_LIBRARY NULL
```

All three are statically linked (`auth_socket` is declared `DEFAULT` in its
CMakeLists, which is why no `auth_socket.so` exists). The server package also
ships `auth_ed25519.so`, `auth_parsec.so`, `auth_mysql_sha2.so`,
`caching_sha2_password.so`, `sha256_password.so`, `auth_pam.so` and
`auth_pam_v1.so`, but **none of them is loaded** — `mysql.plugin` seeds no auth
plugin, and nothing in the compose file or entrypoint loads one.
`mariadb-plugin-gssapi-server` is a separate package the image does not install.

### Accounts

```
demo@%                   mysql_native_password   auth_or NULL
healthcheck@127.0.0.1    mysql_native_password   auth_or NULL
healthcheck@::1          mysql_native_password   auth_or NULL
healthcheck@localhost    mysql_native_password   auth_or NULL
mariadb.sys@localhost    mysql_native_password   auth_or NULL
root@%                   mysql_native_password   auth_or NULL
root@localhost           mysql_native_password   auth_or NULL
```

Seven accounts, **every one `mysql_native_password` with `nauth == 1`**.

This needs stating because MariaDB's own documentation (reproduced verbatim in
`scripts/fill_help_tables.sql`) says `root@localhost` and `mysql@localhost` are
created as `IDENTIFIED VIA unix_socket OR mysql_native_password USING 'invalid'`,
i.e. `nauth == 2`, and `scripts/mariadb_system_tables_data.sql:31` does define
such a row:

```sql
SELECT '{"access":...,"plugin":"mysql_native_password","authentication_string":"invalid","auth_or":[{},{"plugin":"unix_socket"}]}' into @all_with_auth;
```

But that row is only inserted `WHERE @auth_root_socket IS NOT NULL`, and the
official entrypoint runs

```
installArgs=( --datadir="$DATADIR" --rpm --auth-root-authentication-method=normal )
```

which leaves `@auth_root_socket` NULL, so the `tmp_user_nopasswd` branch is used
instead. `mysql@localhost` is only created when `MARIADB_MYSQL_LOCALHOST_USER` is
set, which the compose file does not set. Hence no multi-method account exists on
this target. Verified against the live container, not inferred.

## 3. What is actually reachable before authentication

Reachable:

1. **Packet framing** — `sql/net_serv.cc`: `my_net_read()` → `my_real_read()`,
   multi-packet continuation, `net_realloc()`.
2. **Handshake response parsing** — `sql/sql_acl.cc:parse_client_handshake_packet()`.
3. **Connection attributes** — `read_client_connect_attrs()`.
4. **Client charset selection** — `thd_init_client_charset()`, then
   `copy_and_convert()` / `Well_formed_prefix()` over the attacker's username,
   and `copy_with_error()` over the database name.
5. **ACL lookup** — `find_mpvio_user()` with an attacker-chosen username.
6. **`mysql_native_password` / `mysql_old_password`** server-side auth.
7. **TLS** — `sslaccept()` and the OpenSSL 3.5.5 server handshake (§4.4).
8. `has_proxy_protocol_header()` — a 4-byte `memcmp`, nothing more.

Ruled **out** in this configuration, each with the specific guard or default:

| surface | why it is not reachable |
|---|---|
| reverse DNS / host cache (`sql/hostname.cc`) | `skip_name_resolve=ON`, `host_cache_size=0` |
| PROXY protocol parsing | `handle_proxy_header()` calls `is_proxy_protocol_allowed()` before `parse_proxy_protocol_header()`; `proxy_protocol_networks` is empty |
| client compression / zlib | `net.compress=1` is set in `prepare_new_connection_state()`, which runs *after* `login_connection()` succeeds — post-auth only |
| perf-schema connect-attrs sink | `performance_schema=OFF`, so `PSI_CALL_set_thread_connect_attrs()` is a no-op |
| UCS2 / UTF16 / UTF32 conversion | `is_supported_parser_charset()` rejects them in `thd_init_client_charset()` |
| attacker-chosen server auth plugin | `do_auth_once()` only ever uses `default_auth_plugin_name` or `acl_user->auth[i].plugin`; the client-supplied plugin name never loads a plugin |
| ed25519 / parsec / sha2 / PAM plugin code | shipped as `.so` but not loaded, and no account references them |
| `unix_socket` plugin code | loaded, but no account uses it, so `do_auth_once()` never selects it |
| `LOCAL INFILE` | `local_infile=OFF` |
| `COM_*`, `COM_CHANGE_USER` | require an authenticated session |
| `decrement_connection_count()` (new in 13.0) | guarded by `!thd->userstat_running && !opt_userstat_running`; `userstat=OFF` |

## 4. Findings

### 4.1 `find_mpvio_user()` lets the username select which ACL row drives the handshake

`sql/sql_acl.cc:14094`, for a username that matches no account:

```c
    my_hasher_st hasher= my_hasher_mysql5x();
    CHARSET_INFO *cs= &my_charset_latin1;
    cs->hash_sort(&hasher, (uchar*) sctx->user, strlen(sctx->user));
    ...
    uint i= hasher.m_nr1 % acl_users.elements;
    ACL_USER *acl_user_tmp= dynamic_element(&acl_users, i, ACL_USER*);
    mpvio->acl_user= acl_user_tmp->copy(mpvio->auth_info.thd->mem_root);
    mpvio->make_it_fail= true;
```

This is deliberate — it makes failures for non-existent users indistinguishable
from failures for real ones. The side effect is that an unauthenticated client,
purely by choosing the username string, selects which ACL row drives the rest of
the handshake, and the host part is not consulted on this path, so rows that
could never be matched from a remote address are still selectable.

**Impact on this target: none beyond a fuzzing dimension.** All seven accounts
use `mysql_native_password` with `nauth == 1`, so every selection behaves
identically. It would matter on a deployment with a non-native or multi-method
account, which is exactly what §4.5 needs.

### 4.2 Post-TLS re-read skips the 32-byte minimum (reachable, not exploitable)

The pre-TLS packet is checked with `if (pkt_len < 32) return packet_error;`, but
the packet read back after `sslaccept()` is only checked against
`NORMAL_HANDSHAKE_SIZE`, which is **6**:

```c
    pkt_len= my_net_read(net);
    if (unlikely(pkt_len == packet_error || pkt_len < NORMAL_HANDSHAKE_SIZE))
      return packet_error;
```

The `CLIENT_PROTOCOL_41` layout that follows is selected from the *first*
packet's capability word and then unconditionally reads `read_pos[4..7]` and
`read_pos[8]` and sets `end = read_pos + 32`. The only guard,

```c
  if (end >= (char*) net->read_pos + pkt_len + 2) return packet_error;
```

passes for every `pkt_len >= 31`. At 31 and 32, `user = end` is at or past the
network layer's guaranteed NUL at `read_pos[pkt_len]`, so `strend(user)` and the
auth-length read that follows reach past the packet body. On the lenenc branch
the remaining-length argument

```c
    net->read_pos + pkt_len - (uchar*)passwd
```

is then negative and is passed as `size_t`, i.e. ≈2^64, defeating
`safe_net_field_length_ll()`'s own bound check.

**Tested** (`poc_post_tls_short_packet.py`): the TLS upgrade succeeds against the
official image and every body length from 6 to 40 reaches the parser and comes
back `ER_HANDSHAKE_ERROR` (1043); the server stays up. Against the ASAN build,
**no report** — because at these lengths the reads land ~16 KB inside a
16392-byte allocation. The parse then rejects the packet before anything is
echoed, so there is no disclosure either. Reachable, but inert.

### 4.3 Unbounded `strlen` one byte past the terminator (reachable, not triggerable)

```c
  char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
  Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);
```

`db_len = safe_strlen(db)` stops at the guaranteed NUL, so laying the database
field out to run to the packet's last byte puts `next_field` at
`read_pos + pkt_len + 1` and makes the `strlen` from there unbounded. The guard
`client_plugin.str < read_pos + pkt_len` is applied only *after* it has run.

How much slack there is follows from the allocator: the buffer is
`max_packet + NET_HEADER_SIZE + COMP_HEADER_SIZE + 1` = `max_packet + 8`, and
`net_realloc()` rounds `max_packet` up to a multiple of `IO_SIZE` (4096). A
packet length that is an exact multiple of 4096 therefore makes
`max_packet == pkt_len` and leaves only **7 bytes** between the terminator and
the end of the allocation; any other length rounds up and restores ~4 KB.

**Tested** (`poc_next_field_boundary.py`) at 4096/8192/12288/16384/20480/24576/
32768/65536 and the neighbouring ±1 lengths, with the database field running to
the final byte. The 4096-multiples do reduce the slack to 7 bytes as predicted,
and the error that comes back (1300, from the `copy_with_error()` on the
database name) is raised *after* the `strlen` — so the path really is executed.
Still **no ASAN report**: on a fresh connection those 7 bytes are zero, so the
`strlen` terminates inside the allocation. Nothing writes near that offset
before the first packet is parsed (the server's greeting occupies only the first
~90 bytes), so there is no way to dirty them from the client side. Latent, not
triggerable here.

### 4.4 TLS is active on the target even though no certificate is configured

`opt_use_ssl` defaults to `1` (`sql/mysqld.cc:1608` and the `"ssl"` option
entry), and when neither key nor cert is given `vio_set_cert_stuff()` generates
an ephemeral key and a self-signed certificate:

```c
  if (!cert_file && !key_file)
  {
    if (!is_client)
    {
      EVP_PKEY *pkey;  X509 *x509;
      if (!(pkey= vio_keygen()) || SSL_CTX_use_PrivateKey(ctx, pkey) < 1) ...
      if (!(x509= vio_gencert(pkey)) || SSL_CTX_use_certificate(ctx, x509) < 1) ...
```

Confirmed live: `have_ssl=YES` with `ssl_cert`/`ssl_key` empty, the greeting
advertises `CLIENT_SSL`, and a `CERT_NONE` client completes the handshake. So
**`sslaccept()` and the full OpenSSL 3.5.5 server-side handshake are pre-auth
attack surface**, and the §4.2 path is reachable through it. This is the largest
single piece of reachable pre-auth code on the target, and most of it is not
MariaDB's.

### 4.5 `net->buff` can move pre-auth while cached pointers into it are live (not reachable here)

`net_realloc()` uses `my_realloc`, so `net->buff` can change address, and
pre-auth `net->max_packet_size = MAX(net_buffer_length, max_allowed_packet)` =
16 MB while `net->max_packet` starts at 16 KB. An unauthenticated client can
therefore force a buffer move by sending a packet larger than 16 KB.

`MPVIO_EXT::cached_client_reply.pkt` and `.plugin.str` are raw pointers into
`net->buff`. `server_mpvio_write_packet()` clears both on the normal
plugin-switch path, which is what makes the common case safe. Two gaps remain:

* the cached-hit branch of `server_mpvio_read_packet()` returns
  `*buf = cached_client_reply.pkt` and sets `status = FAILURE` but does **not**
  clear `.pkt`;
* `acl_authenticate()` re-arms `mpvio.status = MPVIO_EXT::RESTART` for each
  `acl_user->auth[]` entry without clearing the cache:

```c
    for (mpvio.curr_auth= mpvio.status != MPVIO_EXT::RESTART;
         res != CR_OK && mpvio.curr_auth < acl_user->nauth;
         mpvio.curr_auth++)
    {
      thd->clear_error();
      mpvio.status= MPVIO_EXT::RESTART;
      res= do_auth_once(thd, &acl_user->auth[mpvio.curr_auth].plugin, &mpvio);
    }
```

Reaching the stale dereference needs all of:

1. `.pkt` to be set, which only happens on the RESTART return of
   `parse_client_handshake_packet()`, which requires `acl_user->auth[0].plugin`
   to differ from `mysql_native_password`;
2. the plugin for that entry to have a non-NULL `client_auth_plugin`, otherwise
   `server_mpvio_read_packet()` short-circuits before the comparison —
   `unix_socket` has `client_auth_plugin == 0` (`socket_auth_handler`'s second
   field), so it always short-circuits;
3. `nauth >= 2` so the loop iterates again;
4. an extra `read_packet` round trip in which the >16 KB packet is sent.

On this target (1) and (3) both fail: every account is `mysql_native_password`
with `nauth == 1`. The pattern is worth re-checking if the account set ever
changes — e.g. a deployment installed with
`--auth-root-authentication-method=socket`, where `root@localhost` does get
`nauth == 2`, still fails (2) because the second method is `unix_socket`.

### 4.6 Paths audited and found sound

* **Multi-packet framing.** In `my_net_read_packet_reallen()` the
  `net->where_b += len` accumulation is bounded because `net_realloc()` refuses
  `length >= max_packet_size`, and the final `net->read_pos[len]=0` always lands
  below `max_packet` since `roundup4096(k * 0xFFFFFF)` is strictly greater than
  `k * 0xFFFFFF` for every reachable `k`.
* **`copy_and_convert()` / `my_convert()`.** Bounded by `MY_MIN(to_length,
  from_length)` on the ASCII path and by `to_length - copied` on the
  `my_convert_using_func()` path; the 385-byte `user_buff` is passed
  `sizeof(user_buff) - 1`, and the post-`Well_formed_prefix()`
  `user[user_len]='\0'` stays in bounds even after the leading-quote shift.
* **`native_password_authenticate()`.** Accepts only `pkt_len == 0` or
  `pkt_len == SCRAMBLE_LENGTH` (20); everything else is `ER_HANDSHAKE_ERROR`.
  `check_scramble()` works on fixed 20-byte buffers.
* **`read_client_connect_attrs()`.** The 64 KB cap is applied before the blob is
  used, so the pointer-overflow in `*ptr + length > end` (with `length` up to
  2^64 from a 9-byte length encoding) cannot be reached.
* **The 13.0 password/database parsing refactor.** It *fixed* a pre-existing
  bug: 11.8.4 computed `db` from the pointer value saved *before* the
  length-encoding advance (`db + passwd_len + 1`), which was only correct for
  1-byte encodings. 13.0.2 computes it per branch from the advanced pointer.
* **`has_proxy_protocol_header()`.** A 4-byte `memcmp` against two signatures.
* **The 13.0 `my_free()` added to `thd_set_peer_addr()`.** Only two callers:
  `check_connection()`, where `main_security_ctx.host` is NULL for TCP, and
  `handle_proxy_header()`, which is unreachable without
  `proxy_protocol_networks`. No double call in this configuration.
* **`set_user_salt()` / `set_user_auth()`** and their `MAX_SCRAMBLE_LENGTH`
  stack buffers are admin paths (`CREATE USER`, `SET PASSWORD`, ACL load), not
  pre-auth.

### 4.7 Authentication decision logic — audited, sound

The success/failure algebra is easy to misread because of the constant values
(`include/mysql/plugin_auth_common.h`):

```
CR_OK                    = -1      CR_ERROR                 =  0
CR_OK_HANDSHAKE_COMPLETE = -2      CR_AUTH_USER_CREDENTIALS =  1
                                   CR_AUTH_HANDSHAKE        =  2
                                   CR_AUTH_PLUGIN_ERROR     =  3
```

so `acl_authenticate()`'s failure test `if (res > CR_OK && mpvio.status !=
MPVIO_EXT::SUCCESS)` means "res >= 0", and the two ways past it are a negative
`res` or `status == SUCCESS`. Both were chased down:

* **`status == SUCCESS`** is assigned at exactly two places in the whole server
  (`sql_acl.cc:14333` and `:14641`), and both are inside `if (!initialized)`,
  the `--skip-grant-tables` branch. `initialized` is a file-static that is only
  ever assigned `1`, in `acl_init()` (`sql_acl.cc:2981`); nothing clears it at
  runtime, so a failed or reloaded ACL cannot re-open that branch.

* **A negative `res`** means a plugin returned `CR_OK` or
  `CR_OK_HANDSHAKE_COMPLETE`. Here there *is* a real gap: the safety net

  ```c
    if (mpvio.make_it_fail && res == CR_OK)
    { mpvio.status= MPVIO_EXT::FAILURE; res= CR_ERROR; }
  ```

  only neutralises `CR_OK`. A plugin returning `CR_OK_HANDSHAKE_COMPLETE` (-2)
  would keep `make_it_fail` from taking effect *and* pass `res > CR_OK`,
  authenticating a username that matched no account as whichever real ACL row
  §4.1's hash selected. It is unreachable because **no server-side auth plugin
  returns -2** — the only producers in the tree are client-side plugins
  (`auth_dialog/dialog.c`, `auth_examples/*`, `auth_gssapi/{gssapi,sspi}_client.cc`).
  Worth reporting upstream as hardening, not usable here.

Why `make_it_fail` matters at all: `native_password_authenticate()` returns

```c
  if (pkt_len == 0) /* no password */
    DBUG_RETURN(info->auth_string_length != 0 ? CR_AUTH_USER_CREDENTIALS : CR_OK);
```

so an **empty** auth response authenticates any account whose stored
`auth_string` is empty — and `mariadb.sys@localhost` on this target has
`"authentication_string":""`. It cannot be reached by name (its host is
`localhost`, and with `skip_name_resolve` a remote connection has
`sctx->host == NULL` and only an IP to match against), but §4.1's hash *can*
select it for an unknown username. `make_it_fail` is precisely what stops that
from being an auth bypass.

### 4.8 `set_user_salt_if_needed()` indexes the current ACL row with a stale index

Called pre-auth from the `done:` block of `server_mpvio_read_packet()`:

```c
  ACL_USER *user= find_user_exact(user_copy->hostname(), user_copy->user);
  // make sure the user wasn't altered or dropped meanwhile
  if (user)
  {
    ACL_USER::AUTH *auth= user->auth + curr_auth;
    if (!auth->salt.str && auth->plugin.length == auth_copy->plugin.length && ...)
      auth->salt= auth_copy->salt;
```

`curr_auth` comes from the per-connection *copy* of the account. `user` is the
account as it stands now, and its `nauth` is never re-checked, so if the account
was altered to have fewer authentication methods between the copy and this
point, `user->auth + curr_auth` is out of bounds — first read, for the
`plugin.length`/`auth_string.length` comparison, then written by
`auth->salt= auth_copy->salt`. The only thing relating `curr_auth` to the array
is the `DBUG_ASSERT` on entry, which compiles out of a release build.

Not reachable pre-auth: it needs a concurrent `ALTER USER`, which requires
privileges. Reported here because it is a genuine lifetime/index bug and a
write, unlike everything else in §4.

### 4.9 Pre-auth memory amplification via the database field

`THD::copy_fix()` sizes its allocation as

```c
  size_t dst_length= dstcs->mbmaxlen * src_length;
  if (alloc_lex_string(dst, dst_length + 1)) ...
```

For the handshake path `dstcs` is `system_charset_info` (utf8mb3, mbmaxlen 3)
and `src_length` is the database-name length, bounded only by the packet, so one
unauthenticated connection can force a ~48 MB allocation on its THD mem_root
from a 16 MB packet. With `max_connections` at its default this is multi-GB of
memory reachable without credentials. The arithmetic itself cannot overflow on
64-bit at this bound, and the conversion is correctly limited to `dst_length`,
so this is a resource issue, not corruption — and a DoS is outside what the
competition counts.

### 4.10 Paths audited this round and found sound

* **`vio/viossl.c`** (MariaDB's own TLS glue, not OpenSSL). `vio_ssl_read()` and
  `vio_read()` are declared `size_t` but `return -1` on error, i.e. `SIZE_MAX`.
  `my_real_read()` guards this correctly with an explicit cast —
  `if ((ssize_t) length <= 0)` — so `remain -= length` / `pos += length` cannot
  run away. `ssl_do()`/`ssl_handshake_loop()` keep no state across the
  handshake, and the peer-certificate printing is inside `#ifndef DBUG_OFF`.
* **The out-of-order packet path.** Sending a handshake response with a wrong
  sequence number is enough to reach `my_real_read()`'s `packets_out_of_order`
  label, which offers the bytes to `handle_proxy_header()` first. Without
  `proxy_protocol_networks` that returns `IGNORE` (or `ABORT` if the first four
  bytes match a PROXY signature), and the only path that re-enters the read
  loop, `RETRY`, is behind `is_proxy_protocol_allowed()`. Fuzzed with both
  signature families and desynchronised sequence numbers.
* **`handle_password_errors()`** takes `acl_cache->lock` and asserts it does not
  already hold it; the lookup is by name and host, not by a cached pointer.
* **13.0 vs 11.8.4.** Extracting and diffing the individual pre-auth functions
  shows `send_server_handshake_packet()`, `read_client_connect_attrs()`,
  `ignore_max_password_errors()` and `check_require_secured_transport()` are
  **identical** across the two releases. Apart from the password/database
  parsing refactor in §4.6, the pre-auth path has not changed — so "new code in
  13.0" is not a useful way in; this is mature, long-fuzzed code.

### 4.11 `prepare_hostname_cache_key()` — pre-auth `memcpy` bounded only by a `DBUG_ASSERT`

`sql/hostname.cc:178`:

```c
static void prepare_hostname_cache_key(const char *ip_string, char *ip_key)
{
  size_t ip_string_length= strlen(ip_string);
  DBUG_ASSERT(ip_string_length < HOST_ENTRY_KEY_SIZE);

  memset(ip_key, 0, HOST_ENTRY_KEY_SIZE);
  memcpy(ip_key, ip_string, ip_string_length);
}
```

`HOST_ENTRY_KEY_SIZE` is `INET6_ADDRSTRLEN`, i.e. **46**, the callers pass a
`char ip_key[HOST_ENTRY_KEY_SIZE]` on the stack, and the length of `ip_string`
is never checked outside that assert — which is compiled out of a release
build, and the official image is a release build.

**This is reachable before authentication.** `inc_host_errors(thd->security_ctx->ip,
&errors)` runs on every failed login, from `acl_authenticate()`'s error block
and from the `check_require_secured_transport()` path in
`parse_client_handshake_packet()`, and it calls
`prepare_hostname_cache_key()` directly. `skip-name-resolve` and
`host-cache-size=0` do **not** turn it off: `hostname_cache_init()`
unconditionally does `new Hash_filo<Host_entry>(..., host_cache_size, ...)`, so
the cache object exists at size 0 and the lookup path still runs. The third
caller, in `ip_to_hostname()`, is the one `skip-name-resolve` skips.

Can `ip_string` exceed 45 characters? `thd->main_security_ctx.ip` is only ever
assigned at `sql_connect.cc:978`, `my_strdup(ip)`, where `ip` comes from
`vio_peer_addr()`:

```c
    err_code= vio_getnameinfo((struct sockaddr *) &vio->remote,
                              ip_buffer, ip_buffer_size,
                              port_buffer, NI_MAXSERV,
                              NI_NUMERICHOST | NI_NUMERICSERV);
```

`ip_buffer` is `check_connection()`'s `char ip[NI_MAXHOST]` (1025), so
`vio_getnameinfo()` itself has room. The problem is what it may produce:
for a **scoped** IPv6 source address glibc's `getnameinfo()` appends
`%<interface>` to the numeric form. `vio_get_normalized_ip()` only rewrites
IPv4-mapped and IPv4-compatible addresses; a native IPv6 address takes

```c
      /* This is a "native" IPv6 address. */
      memcpy(dst, src, src_length);
```

which preserves `sin6_scope_id`. A link-local peer such as
`fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff%<ifname>` is 39 characters of address
plus `%` plus up to 15 (`IFNAMSIZ - 1`) — up to 55 — so `strlen(ip_string)` can
exceed the 46-byte destination and overflow the caller's stack frame by up to
nine bytes. The comment above `vio_get_normalized_ip_string()` in the same file
states the assumption that breaks here: "The system constant INET6_ADDRSTRLEN
can be used to reserve buffers of the right size."

**Not reachable on the ZeroDay Cloud target.** The container has no IPv6 at all
— `/proc/net/if_inet6` does not exist inside it and the server logs
`Failed to create a socket for IPv6 '::': errno: 97` (EAFNOSUPPORT) on every
start — so every peer address is an IPv4 dotted quad of at most 15 characters.
Triggering it needs an IPv6-enabled host, an attacker on the same link so the
source address is link-local, and an interface name long enough to push address
plus scope past 45 characters.

This is the only pre-auth **write** found whose sole bound is a compiled-out
assert, so it is the one worth reporting upstream even though it does not help
here.

### 4.12 Paths audited in the source-audit round and found sound

* **`err_conv()` / `ErrBuff::set_str()` / `set_strq()`** (`sql/sql_error.cc:935`,
  `sql/sql_error.h:875`). Reachable pre-auth with attacker bytes: the §4.3 PoC
  shows `ER_INVALID_CHARACTER_STRING` firing on the database field, which builds
  an `ErrConvString(src, src_length, &my_charset_bin)` out of up to 16 MB of
  client data into a 512-byte `err_buffer`. The binary branch keeps the
  invariant `to == buff + res`, checks `res + 4 >= to_length` before each
  five-byte `\xNN` escape, and `set_strq()`'s `err_buffer[len+2]= 0` lands on
  index 511 at worst — it fits exactly.
* **`send_server_handshake_packet()`**. `buff` is `my_alloca`'d *before*
  `data_len` is raised to `SCRAMBLE_LENGTH`, which is a latent sizing hazard,
  but the 64-byte constant absorbs it: with `SERVER_VERSION_LENGTH` 60, a
  22-character `server_version` and a 21-character `client_auth_plugin` the
  slack is 58 bytes. The `data_len == 0` entry needs an auth plugin that reads
  before writing, and the default plugin always writes first —
  `default_auth_plugin_name` is initialised to `mysql_native_password` and never
  reassigned anywhere in `sql/`. Also worth noting for §4.5:
  `cached_server_packet.pkt` is a `thd->memdup()` copy, **not** a pointer into
  `net->buff`.
* **`net_send_error_packet()`** (`sql/protocol.cc:411`). `buff` is
  `2+1+SQLSTATE_LENGTH+MYSQL_ERRMSG_SIZE` = 520 bytes; with `CLIENT_PROTOCOL_41`
  `pos` is `buff+8` and `strmake(pos, converted_err, MYSQL_ERRMSG_SIZE-1)`
  writes through index 519 at worst — exactly in bounds. The message itself is
  pre-truncated by `convert_error_message()` into a 512-byte buffer.
  **Correction:** an earlier version of this note said the error templates bound
  their arguments with precision specifiers and quoted
  `'%-.48s'@'%-.64s'` for `ER_ACCESS_DENIED_ERROR`. That is MySQL's template,
  not MariaDB's. MariaDB 13.0.2's `errmsg-utf8.txt` has
  `eng "Access denied for user '%s'@'%s' (using password: %s)"` — **plain `%s`,
  no precision** — and the same is true of `ER_ACCESS_DENIED_NO_PASSWORD_ERROR`.
  So the attacker's username is *not* bounded by the format string. The chain is
  still safe, but for a different reason: `my_vsnprintf()`'s `%s` handler
  (`process_str_arg`) computes `left_len = (end - to) + 1`, reads the argument
  with `strnlen(par, width)` rather than `strlen`, and then clamps with
  `if (left_len <= plen) { plen = left_len - 1; length = plen; }` before
  `strnmov`. An unspecified precision gives `width = MAX_WIDTH` (65535), so even
  that scan is bounded. `par == NULL` is substituted with `"(null)"`, which
  disposes of the separate worry about `my_error(..., sctx->user, ...)` being
  reached before the username is set. The clamp applies independently at each of
  the three stages — `my_error`'s `ebuff[MYSQL_ERRMSG_SIZE]`,
  `convert_error_message`'s `converted_err[512]`, and this function's
  `buff[520]` — which is what actually makes the path safe. `LOG_WARNINGS` is 2
  on the target, so `login_failed_error()` additionally formats the same
  arguments into `vprint_msg_to_log`'s `char buff[1024]`; same clamp, same
  reasoning. The one unbounded-looking write in `process_str_arg` is the field
  padding `strfill(to, length - plen - dots, ' ')`, which has no `end` check —
  it is unreachable here only because `length` comes from a field width in the
  format string and none of the pre-auth templates specify one.
* **`ignore_max_password_errors()`** would `strcasecmp()` the account's
  `host.hostname` directly, which is a NULL dereference under the MySQL
  convention where a `%` host is stored as NULL. MariaDB's `update_hostname()`
  substitutes `host_not_specified` instead and the comment says so — "This will
  not be modified!" — so the pointer is never NULL. Independently, its caller is
  guarded by `password_errors >= max_password_errors` and `max_password_errors`
  is `DEFAULT(UINT_MAX)` with `VALID_RANGE(1, UINT_MAX)`, so reaching it would
  take 2^32 failed attempts.
* **`check_connection()` / `thd_set_peer_addr()` / `vio_peer_addr()`**. Every
  buffer write carries its size (`ip[NI_MAXHOST]` into `vio_getnameinfo`,
  `ip_string[128]` into `inet_ntop`), and with `skip_name_resolve` the whole
  `ip_to_hostname()` block is skipped, so `sctx->host` stays NULL for a TCP
  connection — which is the concrete reason a `localhost`-only account such as
  `mariadb.sys` cannot be matched by name from the network (§4.7).
* **`compare_hostname()` / `find_by_username_or_anon()`**. Both NULL-safe for
  `host == NULL`; the wildcard *pattern* comes from the ACL row, not from the
  client, so the recursive `wild_compare()` matcher is not attacker-driven, and
  the lookup loop is bounded by `acl_users.elements`.
* **`my_real_read()`'s out-of-order path**, **`handle_password_errors()`** and
  **`vio/viossl.c`** — see §4.10.

### 4.13 The charset conversion tier, verified rather than assumed

Earlier passes dismissed this tier with "`copy_and_convert()` is bounded by
`MY_MIN(to_length, from_length)`". That was too shallow in two ways, and one of
them was an outright gap.

**The gap: the client picks *both* ends of the conversion.**
`thd_init_client_charset()` ends with

```c
    thd->org_charset= cs;
    thd->update_charset(cs, cs, cs);
```

so the single collation-id byte at offset 8 of the handshake response sets
`character_set_client`, `collation_connection` **and**
`character_set_results`. The earlier audit only ever treated the destination as
`system_charset_info` (utf8mb3). But `net_send_error_packet()` does

```c
  convert_error_message(converted_err, sizeof(converted_err),
                        thd->variables.character_set_results,
                        err, strlen(err), system_charset_info, &error);
```

into a 512-byte stack buffer, and `convert_error_message()` writes through
`to_cs->cset->wc_to_printable` — a function pointer that was never looked at —
with `to_cs` chosen by the client. So the destination encoder of every
pre-auth error message is attacker-selected, and the whole encoder tier had to
be audited, not just utf8mb3's.

**The reachable charset set**, read off the running server rather than guessed:
`is_supported_parser_charset()` is `mbminlen == 1 && number != 17`, which
excludes ucs2/utf16/utf32 (and the filename charset). What survives with a
collation id below 256 is utf8mb4 (maxlen 4), utf8mb3 / ujis / eucjpms (3),
big5 / cp932 / euckr / gb2312 / gbk / sjis (2), and about 25 single-byte
charsets. **gb18030 is not compiled into the official image** — a direct query
of `information_schema.COLLATIONS` returns no rows for it — which removes the
historically most bug-prone decoder from scope.

**Generic engines.** `my_convert()`, `my_convert_using_func()`,
`my_convert_fix()`, `my_copy_fix_mb()` and
`my_append_fix_badly_formed_tail()` do not bound anything themselves: each
delegates the destination limit to `wc_mb(to_cs, wc, to, to_end)` and stops as
soon as it returns `MY_CS_TOOSMALL*`, or checks `to + chlen > to_end` directly.
`my_convert()`'s split between the ASCII fast path and the slow path keeps the
sum within the original `to_length` (`to_length -= copied_length` before the
hand-off). `my_copy_fix_mb()` bounds its `memmove` by
`MY_MIN(src_length, dst_length)` and passes the hard `dst + dst_length` to the
tail fixer. So the entire tier's safety rests on the per-charset handlers.

**The `well_formed_char_length` template** (`ctype-mb.inl`) advances `b` only by
a positive `CHARLEN()` result and `CHARLEN()` returns `MY_CS_TOOSMALL` once
`b >= e`, so `status->m_source_end_pos <= e` always. That is what *proves*
`Well_formed_prefix(...).length()` can only shrink, and therefore that
`user[user_len]= '\0'` after the leading-quote chop stays inside
`user_buff[USERNAME_LENGTH + 1]`.

**The printable-escape path.** `my_wc_to_printable_generic`, `_8bit` and
`_sjis` all funnel into `my_wc_to_printable_ex()`, which reserves
`my_printable_length(bslen, diglen)` = `bslen + (MY_CS_PRINTABLE_CHAR_LENGTH - 1) * diglen`
before escaping. The obvious way for this to be wrong would be an escape whose
length depends on the magnitude of `wc` while the reservation is constant — it
is not: `to_printable_8bit()` emits the prefix plus **all four** nibbles and
returns `MY_CS_PRINTABLE_CHAR_LENGTH` (5) unconditionally. `_sjis` passes
`bslen = 2`, reserving 6 for 5 written, because U+005C encodes as the two bytes
`81 5F` in sjis. The non-ASCII branch (ucs2/utf16/utf32) is unreachable pre-auth
anyway because `mbminlen > 1`.

**Decoders (`mb_wc`), all ten.** `my_mb_wc_utf8mb3_quick`,
`my_mb_wc_utf8mb4_quick`, `my_mb_wc_euc_jp`, `my_mb_wc_eucjpms`,
`my_mb_wc_big5`, `my_mb_wc_cp932`, `my_mb_wc_euc_kr`, `my_mb_wc_gb2312`,
`my_mb_wc_gbk`, `my_mb_wc_sjis`: every one checks `s >= e` first and
`s + N > e` before dereferencing `s[1..N-1]`, and the negative "valid sequence
without a Unicode mapping" return (`-2`, `-3`) is only produced after the
corresponding bytes were confirmed available — which matters because
`my_convert_using_func()` advances `from += (-cnvres)` on that return. The utf8
decoders return only positive lengths, and reject overlong forms (`c < 0xc2`)
and out-of-range lead bytes (`c < 0xf5`).

**Encoders (`wc_mb`), all ten.** `my_uni_utf8mb3` checks `r >= e`, `r + 2 > e`,
`r + 3 > e` on its three branches and returns `MY_CS_ILUNI` for
`wc >= 0x10000`; that last point is what caps expansion at three bytes per
character and so *validates* `THD::copy_fix()`'s `dstcs->mbmaxlen * src_length`
sizing. `my_wc_mb_utf8mb4` computes `count` from the magnitude and then checks
`r + count > e` before writing. `my_wc_mb_8bit`, `my_wc_mb_euc_jp`,
`my_wc_mb_eucjpms`, `my_wc_mb_big5`, `my_wc_mb_cp932`, `my_wc_mb_euc_kr`,
`my_wc_mb_gb2312`, `my_wc_mb_gbk`, `my_wc_mb_sjis` each check the end before
every write. The EUC-JP/eucjpms/sjis/cp932 encoders guard `wc > 0xFFFF` before
indexing their `unicode_to_*` tables.

**Tables.** This is where an index driven straight by client bytes could land
out of bounds, so it was checked mechanically rather than by eye
(`verify_charset_tables.py`):

* the six directly indexed tables — `jisx0208_eucjp_to_unicode`,
  `jisx0212_eucjp_to_unicode` and the two eucjpms equivalents,
  `unicode_to_sjis`, `unicode_to_cp932` — are each declared `[65536]`, which
  covers the full domain the guards allow: `(hi << 8) + s[1]` reaches 0xFFFF,
  and the encoders cap `wc` at 0xFFFF;
* the 49 range-guarded tables behind `func_big5_uni_onechar`,
  `func_gbk_uni_onechar`, `func_ksc5601_uni_onechar`,
  `func_gb2312_uni_onechar` and their `func_uni_*_onechar` inverses were all
  parsed out of the sources and their real initializer entry counts compared
  against `HIGH - LOW + 1`, with the subtracted offset checked against the
  guard's `LOW`. **All 49 match exactly; zero problems.**

**Empirically** (`poc_deep_targeted.py`, groups A/B/D against the ASAN build):
23 database-field lengths of non-printable bytes from 1 to 65535, chosen to land
on the 509/510/511/512 boundaries of `err_buffer` and on the four-byte escape
boundary, all return `ER_INVALID_CHARACTER_STRING` — i.e. they really do drive
`err_conv()` → `set_strq()` → `convert_error_message()` →
`net_send_error_packet()` — with no sanitizer report. Usernames of 127..512
bytes, bare and quoted, each ending in a deliberately truncated multi-byte
sequence, across eleven charsets: clean. And a sweep of **all 256 collation
ids** against ten adversarial byte sequences in both the username and the
database field: clean.

### 4.14 Correction: a packet of exactly 0xFFFFFF is a multi-packet marker

Worth recording because it invalidated one of the targeted tests. A single
handshake-response packet whose length is exactly `MAX_PACKET_LENGTH`
(0xFFFFFF) does not get parsed on its own: `my_net_read_packet_reallen()` treats
`len == MAX_PACKET_LENGTH` as "first fragment of a multi-packet" and blocks
waiting for a continuation, so the connection just stalls. The legal way to
deliver a 16 MB payload pre-auth is `0xFFFFFF` followed by a zero-length
packet, and that is also the only combination `net_realloc()` permits against
the 16 MB `max_allowed_packet` (any non-zero continuation makes
`helping = len + where_b` reach `max_packet_size` and is refused). Sending it
that way returns `ER_ACCESS_DENIED_ERROR`, which confirms the ~48 MB
`THD::copy_fix()` allocation of §4.9 really does execute and complete.

### 4.15 Measured coverage: what the testing actually reached

Claiming "46,500 fuzz cases, no finding" is not evidence of anything on its own
— it says nothing about which branches ran. So the whole battery was re-run
against a third build (`-DCMAKE_BUILD_TYPE=Debug -DWITH_ASAN=ON` plus
`--coverage`), which does two things at once: `DBUG_ASSERT` is live again, so any
assertion that fires marks a condition the release build waves through — exactly
the class of bug §4.11 is — and gcov records what was executed.

Per-function line coverage, taken from gcov's own function attribution
(`gcov -f`) rather than from a hand-written line-range guess, after 8,000 fuzz
cases plus all four PoC suites:

| function | covered |
|---|---|
| `parse_client_handshake_packet` | **96.05%** of 152 |
| `native_password_authenticate` | **100%** of 26 |
| `thd_init_client_charset` | **100%** of 26 |
| `convert_error_message` | **100%** of 11 |
| `my_net_init` / `net_allocate_new_packet` | **100%** |
| `send_server_handshake_packet` | 92.06% of 63 |
| `net_realloc` | 90.91% of 22 |
| `my_real_read` | 89.25% of 93 |
| `set_user_salt_if_needed` | 88.89% of 18 |
| `net_send_error_packet` | 86.21% of 29 |
| `err_conv` | 85.71% of 28 |
| `read_client_connect_attrs` | 84.62% of 13 |
| `login_connection` / `end_connection` | 86.96% / 92.86% |
| `server_mpvio_write_packet` | 80.00% of 15 |
| `net_write_command` | 75.00% of 32 |
| `find_mpvio_user` | 65.31% of 49 |
| `check_connection` | 60.00% of 40 |
| `acl_authenticate` | 57.89% of 190 |
| `net_real_write` | 52.38% of 63 |
| `server_mpvio_read_packet` | 50.91% of 55 |
| `do_auth_once` | 50.00% of 28 |
| `handle_proxy_header` | 47.62% of 21 |
| `check_require_secured_transport` | 42.86% of 7 |
| `net_write_buff` | 36.00% of 25 |
| `thd_set_peer_addr` | 30.77% of 39 |
| `my_net_read_packet_reallen` | 27.71% of 83 |
| `secure_auth` | **0%** of 11 |
| `ignore_max_password_errors` | **0%** of 6 |

**Every low number has a structural explanation that matches the scope analysis
in §3, which is the useful part — the measurement corroborates the exclusions
instead of just asserting them:**

* `my_net_read_packet_reallen` 27.71% — the bulk of its body is the
  `#ifdef HAVE_COMPRESS` compressed-protocol branch, and compression is
  post-auth only (`net.compress=1` is set in `prepare_new_connection_state()`).
* `thd_set_peer_addr` 30.77% — the `ip_to_hostname()` block is skipped under
  `skip-name-resolve`, and the `AF_UNIX` and `ip == NULL` (PROXY protocol)
  branches are unreachable over TCP without `proxy_protocol_networks`.
* `net_write_buff` 36% and `net_real_write` 52% — the compressed and
  larger-than-`max_packet` branches; the pre-auth server writes are a ~90-byte
  greeting and short error packets.
* `handle_proxy_header` 47.62% — `has_proxy_protocol_header()` and the `ABORT`
  return *were* covered (the fuzzer sends both PROXY signature families); the
  uncovered remainder is exactly everything behind
  `is_proxy_protocol_allowed()`.
* `do_auth_once` 50% — the `interface_version >> 8 == 0x01` compatibility path
  and the `!plugin` → `ER_PLUGIN_IS_NOT_LOADED` path, which needs an account
  naming an unloaded plugin.
* `server_mpvio_read_packet` 50.91% and `acl_authenticate` 57.89% — the
  `MPVIO_EXT::RESTART` machinery and the whole post-success tail (proxy user,
  `acl_check_ssl`, password expiry, roles). No login ever succeeds here and no
  account is non-native, so this is the expected shape.
* `check_require_secured_transport` 42.86% — only the early return runs;
  `require_secure_transport` is OFF.
* `secure_auth` and `ignore_max_password_errors` at **0%** — independently
  argued dead in §4.7 and §4.12, now measured dead.

Within `parse_client_handshake_packet` the uncovered lines were individually
inspected, and all but one pair are branches already established as unreachable:
the `--skip-grant-tables` block (14641-14642, §4.7), the
`ER_SECURE_TRANSPORT_REQUIRED` block (14497-14505), and —  usefully — the
**`MPVIO_EXT::RESTART` cache-set block at 14689-14693**, i.e. the
`cached_client_reply.pkt = passwd` assignment that §4.5's lifetime pattern
depends on. It never executed, which is the measured confirmation that §4.5 is
unreachable on this target rather than merely an argument about `nauth`.

**Two genuinely untested branches turned up, and both were closed**
(`poc_coverage_gaps.py`):

1. **`sslaccept()` failure.** Every TLS case so far had completed its handshake,
   so the rejection path — `return packet_error` after
   `ssl_acceptor_stats_update(ssl_ret)`, with a half-built `SSL` object to tear
   down — had never run. Ten malformed-TLS shapes were added (random bytes, a
   truncated ClientHello, a fatal alert, a bogus record type, an SSLv2-style
   header, an HTTP request, an immediate FIN, a single byte, a zero-length
   record, a record claiming 0xFFFF bytes). Eight return `ER_HANDSHAKE_ERROR`,
   two close the connection; lines 14477-14478 now show **10 executions**.
2. **`net_realloc()`'s `ER_NET_PACKET_TOO_LARGE`.** Nothing sent so far had ever
   declared more than `max_allowed_packet`, because a single packet's length
   field caps at 0xFFFFFF — one byte below the 16 MB limit. Reaching it needs a
   multi-packet whose continuation pushes `helping = len + where_b` over
   `max_packet_size`. All four continuations tried (0xFFFFFF, 0x800000, 2 and
   **1**) return `ER_NET_PACKET_TOO_LARGE`; lines 217-219 now show **4
   executions**. That the continuation of length *one* already trips it is the
   empirical confirmation of §4.14's derivation that `0xFFFFFF + 0` is the only
   legal pre-auth multi-packet.

After closing them, `parse_client_handshake_packet` is at **96.05%**,
`net_realloc` at **90.91%**, `my_real_read` at **89.25%**.

**No `DBUG_ASSERT` fired anywhere in the battery.** Across 8,000 fuzz cases, the
four targeted PoC suites, the 256-collation sweep and the gap-closing cases, the
assertion-enabled build produced zero assertion failures, zero sanitizer
reports and zero crashes. Given §4.11 — a pre-auth `memcpy` whose only bound
*is* a `DBUG_ASSERT` — this was the single most likely way to surface another
bug of that class, and it found none in the paths that are reachable here.

### 4.16 Lazy collation initialisation is pre-auth reachable, and its publish is a data race

This one was found by the coverage differential rather than by reading code,
which is the argument for doing the measurement. Comparing the functions
executed with pre-auth traffic against those executed by a bare server
start/stop put `my_coll_parser_scan_rule`, `my_coll_rules_realloc`,
`my_coll_rule_expand`, `my_uca_generate_page`, `my_char_weight_put`,
`my_uca_copy_page`, `create_fromuni`, `my_cset_init_8bit`,
`my_8bit_charset_flags_from_data` and `my_coll_init_8bit_bin` in the
pre-auth-only set. Those are the charset and collation *builders*: they run the
first time a collation is used, not at startup.

`thd_init_client_charset()` calls `get_charset(net->read_pos[8])` with the
collation-id byte out of the handshake response, so **an unauthenticated client
decides which collation gets built and when**. Nothing in the earlier scope
analysis had noticed that.

`get_internal_charset()` publishes the result with double-checked locking
(`mysys/charset.c`):

```c
    if (cs->state & MY_CS_READY)   /* read with no mutex held */
    {
      my_collation_statistics_inc_use_count(cs_number);
      return cs;
    }
    mysql_mutex_lock(&THR_LOCK_charset);
    ...
        if (my_ci_init_charset(cs, loader) || my_ci_init_collation(cs, loader))
          cs= NULL;
        else
          cs->state|= MY_CS_READY;   /* published last, still under the mutex */
    mysql_mutex_unlock(&THR_LOCK_charset);
```

`cs->state` is a plain `uint` — not atomic, not volatile, with no
release/acquire pairing — so this is a data race by the language rules: a thread
on the fast path can in principle observe `MY_CS_READY` without observing the
weight pages and handler pointers the initialising thread wrote. That matters
because several weight lookups deliberately rely on pages being non-NULL ("By
adding these dummy pages we can avoid testing 'page' against NULL",
`ctype-utf8.c`). The neighbouring `my_collation_statistics_inc_use_count()` race
is *documented* as intentional and harmless; this one is not.

**Tested** (`poc_collation_race.py`): on a freshly started server, for each of
collation ids 1..255, 24 connections pre-connect, pre-build their packets, and
release on a barrier so their `get_charset()` calls land together — 6,120
barrier-synchronised racing connections in total, each then asked to decode
non-ASCII and truncated multi-byte sequences in both the username and the
database field. Every connection got its reply, the server stayed up, and ASAN
reported nothing.

That matches the reasoning: the initialisation itself is inside the mutex, the
flag store is the last thing before the unlock, and on x86-64 the store-store
ordering plus the non-inlined `my_ci_init_*` calls acting as compiler barriers
make the publish effectively ordered in practice. So this is a real
standard-level race and a hardening issue worth reporting, not an exploitable
one here. It also means the collation builders themselves are exercised for all
256 ids without a memory error.

### 4.17 Every memory write in the pre-auth call graph, enumerated

Spot-checking writes is how a write primitive gets missed, so they were
enumerated mechanically instead: for each function in the pre-auth call graph,
every call to `memcpy`, `memmove`, `memset`, `bzero`, `strcpy`, `strncpy`,
`strcat`, `strmov`, `strnmov`, `strmake`, `strmake_buf`, `sprintf`,
`snprintf`/`my_snprintf`/`my_vsnprintf`, `strfill`, `int2store`/`int3store`/
`int4store`/`int8store`, `memdup`, `strdup`, `my_strndup`, `safe_strcpy` and
`strnxmov` was extracted and checked individually. **38 call sites.**

All but one were already covered by §4.6/§4.10/§4.12/§4.13. The exception was
`server_mpvio_read_packet`'s

```c
  strmake_buf(ai->authenticated_as, mpvio->acl_user->user.str);
```

`authenticated_as` is `char[MYSQL_USERNAME_LENGTH + 1]` = 513, `strmake_buf(D,S)`
expands to `strmake(type_assert_buf(D), S, sizeof(D) - 1)` so the bound is 512
and `type_assert_buf` even rejects a pointer where an array is expected, and the
source is an ACL username capped at `USERNAME_LENGTH` = 384. Bounded with
margin.

Combined with §4.5's conclusion about dangling pointers — `mpvio->db`,
`sctx->user` and `cached_server_packet.pkt` are all independent copies
(`copy_with_error`, `my_strndup`, `thd->memdup`), and the one pointer that does
alias `net->buff` across a `my_net_read()` is reassigned right after it —
**there is no write primitive in the reachable pre-auth path on this target.**
That is the central negative result: a memory-corruption RCE needs a write, and
every write here is bounded by a correct size computation.

**Transitive version, over the measured set rather than my hand list.** The 38
sites above came from a call graph I wrote down, and the way that misses a
primitive is by omitting a function. Re-running the same enumeration over all
290 functions from the coverage differential (§4.15) gives **127 memory-writing
call sites across 46 functions** — 89 more than the hand list. Triaged, every
one of the additions falls into four groups and none is a new primitive:

* **already audited** under §4.6/§4.10/§4.12/§4.13;
* **name collisions** — a `memcpy` in a same-named function in another
  translation unit, which `gcov -f -m` attribution resolves;
* **post-auth, reachable in the measured set only through the fidelity gap of
  §4.19** (the `root@127.0.0.1` passwordless login that inflated the first
  measurement) — `set_privs_on_login`, `do_command`, `send_ok`, `acl_check_ssl`;
* **compressed-protocol branches**, which are post-auth because `net.compress`
  is set in `prepare_new_connection_state()`: `net_real_write`'s
  `memcpy(b + header_length, packet, len)` (`net_serv.cc:674`) sits inside
  `if (net->compress)`, as do `my_net_read_packet_reallen`'s three `memmove`s
  (`:1151`, `:1170`, `:1182`).

Two sites outside those groups were read in full and are bounded:
`print_aborted_warning()` (`sql_class.h`) uses `snprintf(real_ip_str,
sizeof(real_ip_str), ...)` and its "real ip" branch is gated on
`net.using_proxy_protocol`, unreachable without `proxy_protocol_networks`; its
`ER_NEW_ABORTING_CONNECTION` template bounds all five arguments with precision
specifiers (`%-.192s`, `%-.48s`, `%-.64s`, `%-.64s`, `%-.64s`).

The negative result therefore holds over the *measured* surface, not just over
a list I chose. For the control-flow dual of this enumeration — function
pointers, which need no write at all — see §4.22.

### 4.18 Concurrency, measured

Everything before this was single-connection. `preauth_concurrent.py` runs 32
threads of mixed pre-auth shapes — half of them hammering one ACL row with a
fixed username to maximise contention in `find_mpvio_user()` and
`set_user_salt_if_needed()`, half spreading the hash across every row — with
TLS upgrades, deliberately failed TLS handshakes, desynchronised sequence
numbers, auth-switch replies above `net_buffer_length`, and oversized
multi-packets mixed in. **233,624 rounds over 600 s, no sanitizer report, no
crash.**

RSS was sampled throughout as an independent leak check, since a per-connection
allocation into a *global* root (rather than the THD mem_root, which is released
with the connection) would show up as monotonic growth. It did not: the samples
oscillate — 371 MB, 950 MB, 724 MB, 834 MB above baseline — so memory is being
reclaimed. The peak is consistent with §4.9's per-connection amplification
(32 concurrent connections each able to hold a ~48 MB conversion buffer), which
is a resource-exhaustion vector bounded by `max_connections`, not a leak.

> **Superseded, see §4.20.** The RSS argument in this paragraph is too
> insensitive to support "memory is being reclaimed": at the growth rate that
> later proved measurable, 233,624 connections amount to ~29 MB, well inside
> the noise of these samples. The question is settled in §4.20 by MariaDB's own
> byte-exact `Memory_used` accounting instead, and the answer is the same — the
> stock pre-auth path does not accumulate — but the evidence here was not strong
> enough to say so.

Two related leads were closed by reading rather than guessing:

* **The host cache is completely dead at `host_cache_size=0`**, not merely
  bypassed. `hash_filo::add()` begins `if (!m_size) return 1;`, so nothing is
  ever inserted and `search()` always returns NULL — there is no LRU churn to
  race on. `inc_host_errors()` therefore reduces to the one `memcpy` of §4.11.
* **No `acl_memroot` growth per connection.** `set_user_salt_if_needed()`
  returns early when `auth_copy->salt.str` is set, and for an account with an
  empty `auth_string` — `mariadb.sys` on this target — `safe_lexcstrdup_root()`
  returns a static `""` rather than allocating, so `salt.str` is non-NULL from
  ACL load onwards and the early return always fires.

### 4.19 In-process fuzzing, and a fidelity bug in the test rig it exposed

Network fuzzing is bounded by connection setup. §4.15 showed coverage was
already near-complete, so the missing dimension was inputs per covered branch,
not coverage. The instrumented build therefore carries an **env-gated,
discovery-only** hook (`MARIADB_PREAUTH_FUZZ_HOOK` at build time,
`MARIADB_FUZZ_HANDSHAKE=N` at run time) that re-parses each connection's first
handshake packet N times over mutated copies of itself, against the real THD,
NET and ACL state. It restores `thd->client_capabilities`, `mpvio->acl_user`,
`mpvio->curr_auth`, `mpvio->status` and `cached_client_reply` between
iterations, preserves the NUL terminator the network layer guarantees at
`read_pos[len]`, and clears `CLIENT_SSL` and `CLIENT_PLUGIN_AUTH` from every
mutated packet because those two branches would do blocking network I/O from
inside the loop (both are covered over the network instead, §4.15). Anything it
finds has to reproduce over the network against an unmodified binary.

The hook was verified to actually be running rather than assumed: 100 seed
packets take **140 ms with it off and 1031 ms with it on at N=5000**, i.e. about
1.8 µs per extra parse. A first campaign of 2,000 seeds × 5,000 iterations =
**10,000,000 parses** produced no sanitizer report.

Building this also exposed a **fidelity bug in the test rig**, which is worth
recording because it had been inflating the measured surface. The
coverage-differential set contained `acl_check_ssl`, `set_privs_on_login`,
`acl_find_proxy_user`, `check_password_lifetime`, `mysql_change_db`,
`init_for_queries`, `do_command`, `change_user`, `send_ok` and `net_send_ok` —
all post-authentication. The reason: `mariadb-install-db
--auth-root-authentication-method=normal` creates `root@127.0.0.1`,
`root@::1` and `root@<hostname>` **with no password**, and the fuzzers connect
from 127.0.0.1, so any case that happened to send user `root` with an empty
auth response simply logged in. The official entrypoint drops exactly those
accounts (`DROP USER IF EXISTS root@'127.0.0.1', root@'::1'` plus the hostname
one) and sets a password on `root@localhost`. Both instrumented servers have now
been aligned to the official account set — demo@%, healthcheck@{127.0.0.1,::1,
localhost}, mariadb.sys@localhost, root@%, root@localhost — so later runs are
pre-auth only. The earlier negative results are unaffected (a successful login
only adds code paths), but the measured "pre-auth" surface was too generous and
is corrected here.

### 4.20 Correction to §4.18: the pre-auth memory question, answered at byte level

§4.18 concluded "no leak" from RSS being non-monotonic over 233,624 concurrent
pre-auth rounds. That conclusion was under-powered and I am withdrawing the
reasoning behind it. At the growth rate that later turned out to be measurable,
233,624 connections would have accounted for roughly 29 MB — comfortably inside
the noise of an RSS sample taken from `/proc/<pid>/status` on a server whose
baseline is ~470 MB. §4.18 did not rule the question out; it merely could not
see it.

What forced the issue was the in-process campaign dying at seed 22100. That was
**not** a crash:

```
oom-kill:constraint=CONSTRAINT_MEMCG,...,task=mariadbd,pid=32096
Memory cgroup out of memory: Killed process 32096 (mariadbd)
    total-vm:30077313968kB, anon-rss:13891348kB
```

no ASAN report, no assertion, and an error log that simply stops mid-line on
ordinary `Access denied` warnings — the signature of `SIGKILL`. 13.9 GB over
~110 M parses is ~126 B per parse, and the driver closes every connection
(`c.close()`) and runs strictly sequentially, so per-connection teardown should
have reclaimed it. That is what made it worth measuring properly rather than
dismissing.

RSS cannot answer the question, because it is the high-water mark of the ASAN
allocator, which does not return its regions to the OS. MariaDB's own
accounting can: `Memory_used` is maintained by `update_malloc_size()` and
reports live tracked bytes. Reading it needs an authenticated session, so
`probe_status.py` (scratchpad) speaks native_password over the unix socket as
`root@localhost` — the socket is used deliberately, because it matches an
account that exists in the official set rather than adding one.

Stock pre-auth path, hook off, one parse per connection, 5,000 connections per
batch:

| batch | ΔMemory_used | per connection |
|-------|--------------|----------------|
| 1 | +2,446,408 B | +489 B (first touch: thread caches) |
| 2 | +667,672 B | +133 B |
| 3 | **−671,744 B** | **−134 B** |
| 4 | +802,816 B | +160 B |

The deltas oscillate about zero and one of them is negative; +667,672 and
−671,744 are the same ~670 KB thread-cache block being taken and given back.
**The stock pre-auth path does not accumulate memory**, measured to the byte
over 20,000 connections. The 13.9 GB is an artifact of the research hook, which
performs its N re-parses *inside a single connection*, before any teardown can
run, multiplying the per-connection peak by N.

For the competition this is a dead end either way: memory growth is not a write
primitive, and at one parse per connection there is no exhaustion vector to
speak of. It is recorded because the earlier claim was weaker than it sounded.

### 4.21 A fidelity limit of the in-process hook, and what it does to §4.19

With `MARIADB_FUZZ_HANDSHAKE=5000` set, my own legitimate login was refused:

```
login failed: #28000Access denied for user 'root'@'localhost' (using password: YES)
```

The hook saves and restores `thd->client_capabilities`, `mpvio->acl_user` and
`mpvio->curr_auth`, but `parse_client_handshake_packet()` also writes
`mpvio->status`, `mpvio->cached_client_reply` and — via
`my_free(sctx->user); sctx->user= my_strndup(...)` — the security context's
username, none of which the hook puts back. So the real parse that follows the
mutated ones starts from state the mutations left behind.

That bounds what §4.19 proves. The in-process campaign explores
`parse_client_handshake_packet()` **from accumulated, mutated state**, not from
the state of a fresh connection; only the network campaigns (~250,000 cases)
are faithful to a fresh connection. Since neither found a crash, the caveat
does not invalidate a finding — it limits the reach of a negative result, and
that is worth stating plainly rather than letting the parse count speak for
itself.

Two consequences, both applied: a lower N gives better fidelity per parse (the
state drifts less far before the real parse), and the server is now recycled
every 30,000 connections so the harness's own accumulation cannot reach OOM
again. The campaign now runs at N=200 with recycling; as of this writing
42,000,000 in-process parses with no sanitizer report and RSS flat at ~1.33 GB
per round.

Anything the hook ever flags must still be reproduced over the network against
an unmodified binary before it counts. That was always the rule; it matters
more now that the state divergence is understood.

### 4.22 Every indirect call in the pre-auth call graph, enumerated

§4.17 showed there is no unbounded write pre-auth, which closes
memory-corruption-by-write. But a control-flow hijack does not need a write at
all: it needs a **function pointer** whose value attacker data can influence,
or one that is read before it is initialised. That is the dual question and
§4.17 does not touch it.

Enumerated on the binary rather than the source, so that macros, templates and
virtual dispatch cannot hide a site (`indirect.py`, scratchpad): stream
`objdump -d -C` over `build-dbg/sql/mariadbd`, keep only the functions in the
*measured* 290-function pre-auth set from §4.15, and classify every `call`/`jmp`
with a `*` operand.

```
measured functions located in binary: 301 / 290     (clones and .cold parts)
indirect sites: reg=1809  mem=73  got=0
1882 unique addresses -> 1098 distinct source locations (addr2line)
```

`got=0` is expected: external calls go through a direct `call` to a PLT stub,
not a `*(%rip)` load. `reg=1809` is inflated by the `-O0` debug build, where
every C++ method call through a loaded pointer materialises as `call *%rax`.

Triaging by the *source of the pointer* rather than by site, every pre-auth
function pointer comes from one of these, and none takes its value from
attacker bytes:

| structure | selected by | notes |
|---|---|---|
| `Vio` method table | attacker, via `CLIENT_SSL` | two compiled-in tables; see §4.23 |
| `CHARSET_INFO::cset` / `::coll` | attacker, via the collation id byte | static tables, lazily initialised (§4.16) |
| `st_mysql_auth::authenticate_user` | server | plugin comes from `default_auth_plugin_name` or `acl_user->auth[]`, never from the client (§5) |
| `MY_CHARSET_LOADER::once_alloc` | server | `create_fromuni`, both sites NULL-checked |
| PSI service table | server config | `performance_schema` |
| audit plugin table | server config | dominates the count (`sql_audit.h`); no audit plugin is loaded on the target |
| `scheduler_functions` | server config | thread handling |
| comparison callbacks passed as parameters | server | e.g. `find_by_username_or_anon`'s `bool (*)(ACL_USER*, char const*, char)` |

Sites I checked individually because they looked attacker-adjacent:

* `create_fromuni` (`ctype-simple.c:1418`, `:1459`) — in the measured set, so
  pre-auth traffic really does reach charset table construction. Both indirect
  calls are `(loader->once_alloc)(...)`, server-supplied and NULL-checked. The
  table fill is in bounds: `ofs = wc - idx[i].uidx.from` under the guard
  `from <= wc <= to`, so `0 <= ofs <= numchars-1`, and `from`/`to` come from the
  compiled-in `tab_to_uni[]`, not from the wire. The attacker chooses *which*
  charset is initialised, not what it is initialised from.
* `find_mpvio_user` → `charset_info_st::hash_sort` (`m_ctype.h:1245`, called at
  `sql_acl.cc:14108`) — dispatches through `coll->hash_sort`, but on
  `CHARSET_INFO *cs= &my_charset_latin1`, hardcoded, and latin1 is statically
  initialised. Not attacker-selected.
* `do_auth_once` → `info->authenticate_user` — see §5.
* `acl_check_ssl` (reached inlined from `do_auth_once`) — OpenSSL calls, and
  every official account has an empty `ssl_type`, so it returns 0 early.

So a hijack would need a write to corrupt one of those tables, and §4.17 says
there is no write to be had. The two enumerations together close
memory-corruption RCE in the pre-auth path: no unbounded write, and no pointer
an attacker can supply.

What this does **not** close: an OOB *read* (an info leak is not an RCE but
could feed one), and a bug in a path neither enumeration covers — which is why
the measured function set, not a hand list, is the input to both.

### 4.23 The TLS glue: handlers are installed only after the handshake, and a second `sslaccept()` is impossible

The one way a static method table turns dangerous is if it is installed early
and left behind on an error path. For the pre-auth TLS upgrade it is not.
`ssl_do()` (`vio/viossl.c`):

```c
  if (!(ssl= SSL_new(ptr->ssl_context))) { *errptr= ERR_get_error(); return 1; }
  ...
  if ((r= ssl_handshake_loop(vio, ssl, func)) < 1)
  {
    *errptr= SSL_errno(ssl, r);
    SSL_free(ssl);
    DBUG_RETURN(1);                 /* vio_reset() has NOT run yet */
  }
  if (vio_reset(vio, VIO_TYPE_SSL, SSL_get_fd(ssl), ssl, 0))
    DBUG_RETURN(1);
```

`ssl` is a local and is only published into the `Vio` by `vio_reset()`, which
runs **after** the handshake succeeds. On every failure path the `Vio` still
carries the plain-TCP table and an untouched `ssl_arg`, so the teardown that
follows `return packet_error` in `parse_client_handshake_packet()` cannot
dispatch through SSL methods or touch the freed `SSL`. No stale table, no
use-after-free. (Malformed-TLS shapes were also driven over the network:
§4.15.)

That leaves a second upgrade on the same `Vio`, which would call `vio_reset()`
again over a live `SSL`. It cannot happen, and the guard is not where I first
looked: `mpvio->packets_read` is only ever incremented
(`sql_acl.cc:14914`, `:14934`, `:15244`) and never reset, starting from 0, so

```c
  if (mpvio->packets_read == 1)
    pkt_len= parse_client_handshake_packet(mpvio, buf, pkt_len);
```

is true for exactly one call per connection. `parse_client_handshake_packet()`
runs at most once, therefore its `CLIENT_SSL` branch and `sslaccept()` run at
most once, including across an auth-plugin RESTART (which re-enters
`server_mpvio_read_packet` but with `packets_read > 1`, taking the cached-reply
or re-read path instead).

Correction to my own note: the line clearing `CLIENT_SSL` out of the packet at
`sql_acl.cc:14851` is part of **my research hook**, not a MariaDB guard — I
read it out of the modified tree and briefly took it for upstream code. MariaDB's
guard is the `packets_read` monotonicity above.

## 5. What an auth bypass would actually buy on this target

Worth knowing before spending effort on one, since a bypass to `root@%`
followed by post-auth code execution would count as unauthenticated RCE. On the
official image the usual post-auth levers are closed (checked against the
running container):

| lever | state |
|---|---|
| `SET GLOBAL wsrep_provider='/path/evil.so'` (dlopen) | `ERROR 1238 ... read only variable` |
| `SET GLOBAL wsrep_notify_cmd='...'` (command exec) | `ERROR 1238 ... read only variable` |
| `CREATE FUNCTION ... SONAME` / `INSTALL PLUGIN` | `plugin_dir` is read-only and `/usr/lib/mysql/plugin` is `root:root 0755` while mariadbd runs as uid 999 — no way to place a `.so` |
| `secure_file_priv` | `NULL`, i.e. **unrestricted**, so arbitrary file *write* as uid 999 is available — but nothing executes from the paths that uid can write |

`wsrep_on` is `0` and the galera provider is not loaded. So a bypass alone is
not obviously RCE here: an entry needs a bypass **plus** a code-execution
primitive, or memory corruption that gets there directly.

### 5.1 And why there is no bypass to be had

The decision is made by exactly one rejection site in `acl_authenticate()`:

```c
  if (res > CR_OK && mpvio.status != MPVIO_EXT::SUCCESS)
  { ... inc_host_errors(...); login_failed_error(thd); DBUG_RETURN(1); }
  sctx->proxy_user[0]= 0;                 /* reaching here grants the login */
```

It needs **both** conditions to reject, so there are two ways to fail open:
`res <= CR_OK`, or `mpvio.status == SUCCESS` despite an error. Four facts close
both, and each is checked rather than assumed:

1. **`mpvio.status` can never become `SUCCESS` pre-auth on this target.**
   `MPVIO_EXT::SUCCESS` is assigned at exactly two places in the whole tree
   (`sql_acl.cc:14341`, `:14649`) and both sit inside `if (!initialized)`, i.e.
   only under `--skip-grant-tables`. `static bool initialized=0` (`:725`) is set
   to 1 at exactly one site, `acl_init()` (`:2989`). The target runs with grant
   tables, so the rejection reduces to `res > CR_OK`.

2. **No server-side path returns `CR_OK_HANDSHAKE_COMPLETE` (−2).** This
   matters because the unknown-user guard compares exactly:
   ```c
   if (mpvio.make_it_fail && res == CR_OK) { mpvio.status= FAILURE; res= CR_ERROR; }
   ```
   −2 does not match, and `−2 > −1` is false, so a −2 would grant the login to
   an unknown user. Every `return CR_OK_HANDSHAKE_COMPLETE` in the tree is
   client-side — `libmariadb/plugins/auth/*`, `sql-common/client.c`, the client
   halves of dialog/gssapi/sspi, and `plugin/auth_examples/*` which release
   builds do not ship. `plugin_auth_common.h` states the contract outright:
   *"Server plugins should not return this value."*

3. **The client never chooses the server's plugin.** `do_auth_once()` is called
   with `default_auth_plugin_name` (`:15266`) or `acl_user->auth[curr_auth].plugin`
   (`:15288`) — both server-side. `get_auth_plugin()` compares by pointer
   identity (`name.str == native_password_plugin_name.str`) and otherwise goes
   through `my_plugin_lock_by_name(thd, &name, MYSQL_AUTHENTICATION_PLUGIN)`,
   which enforces the plugin type. The client's plugin name only triggers an
   auth-switch request. So no type confusion onto `st_mysql_auth`.

4. **The one fail-open in `do_auth_once()` is not reachable with shipped
   plugins.** Its dispatch is
   ```c
   switch (info->interface_version >> 8) {
   case 0x02: res= info->authenticate_user(...); break;
   case 0x01: ... break;
   default: DBUG_ASSERT(0);          /* no-op in a release build */
   }
   ```
   `res` is initialised to `CR_OK`, so a plugin whose `interface_version >> 8`
   is neither 1 nor 2 would be granted the login *without `authenticate_user`
   ever being called*. Every server auth plugin in the tree declares
   `MYSQL_AUTHENTICATION_INTERFACE_VERSION`, which is `0x0203` → `>> 8 == 2`.
   Worth reporting upstream as defence-in-depth — a `default:` that leaves a
   success value standing is the wrong default — but it is not an unauth vector,
   because the attacker cannot influence which plugin an account uses.

That leaves the native plugin's own logic, which is tight:
`native_password_authenticate()` returns `CR_OK` outside the crypto check in
exactly one branch — `pkt_len == 0` (no password sent) **and**
`info->auth_string_length == 0` (the account has no password). Otherwise it
needs `pkt_len == SCRAMBLE_LENGTH`, a 20-byte stored hash, and
`check_scramble()` to pass.

So the question becomes whether any account on the target has an empty
password. Dumped from the official container, authoritatively:

| account | auth_string | locked |
|---|---|---|
| `demo@%`, `root@%`, `root@localhost` | `*52CB4371…` | — |
| `healthcheck@127.0.0.1`, `@::1`, `@localhost` | `*4A65F9E8…` | — |
| **`mariadb.sys@localhost`** | **"" (empty)** | **true** |

Exactly one, and it is covered twice over: the host is restricted to
`localhost` (a remote attacker's host never matches, and PROXY-protocol source
spoofing is out — `proxy_protocol_networks` is unset, §4.12), and even on a
host match `acl_authenticate()` rejects it at
`if (acl_user->account_locked) { my_error(ER_ACCOUNT_HAS_BEEN_LOCKED); DBUG_RETURN(1); }`,
which sits after the password check inside `if (initialized)`.

For an unknown user, `find_mpvio_user()` fabricates a row and sets
`make_it_fail`, and fact 2 shows that guard cannot be slipped. **The auth
bypass line is closed.**

## 6. Status

**No unauthenticated RCE found.** Two enumerations, both run over the
*measured* pre-auth surface rather than a hand-written call graph, are the
central results:

* **§4.17 — no write primitive.** 127 memory-writing call sites across 46 of
  the 290 measured pre-auth functions, each checked individually; every one is
  bounded by a correct size computation, or is post-auth, or is a name
  collision that `gcov -f -m` attribution resolves.
* **§4.22 — no attacker-supplied function pointer.** 1,882 indirect call sites
  (1,809 register-operand, 73 memory-operand) in the same measured set,
  deduplicated to 1,098 distinct source locations and triaged by the *source*
  of the pointer. Every pre-auth function pointer comes from a compiled-in
  table; the attacker chooses *which* valid table runs (collation id, TLS on or
  off), never what a pointer contains.

A memory-corruption RCE needs one or the other. Neither exists in this path.
And §5.1 closes the remaining route — a bypass followed by post-auth execution
— at the single rejection site in `acl_authenticate()`, with four checked facts.

Specifically:

* every out-of-bounds access found (§4.2, §4.3) is a *read* that provably stays
  inside the `net->buff` allocation on this target;
* the three write-shaped bugs found all need something an unauthenticated client
  cannot cause on this target — a concurrent `ALTER USER` (§4.8), an account with
  more than one authentication method (§4.5), or an IPv6-capable host and a
  link-local peer (§4.11);
* the authentication decision logic (§4.7, §5.1) is sound; the one latent
  fail-open (`do_auth_once`'s `default:` leaving `res == CR_OK`, §5.1 fact 4) is
  unreachable with any shipped plugin and is worth an upstream report as
  defence-in-depth, not a competition entry;
* the pre-auth TLS glue (§4.23) installs its method table only after the
  handshake succeeds, and `packets_read` monotonicity makes a second
  `sslaccept()` on one connection impossible.

Done:
* target pinned, configuration and account set read out of the running image ✔
* pre-auth surface enumerated with the non-reachable parts positively excluded ✔
* source audit of every reachable path (§4): the framing layer, the handshake
  parser, the TLS glue, the auth decision logic, the connection setup
  (`check_connection`/`thd_set_peer_addr`/`vio_peer_addr`), the ACL lookup and
  host matching, the error-formatting path (`err_conv`, `net_send_error_packet`)
  and the host-error accounting ✔
* the charset conversion tier verified end to end (§4.13) ✔ — ten decoders, ten
  encoders, five generic engines, the printable-escape arithmetic, and all 55
  conversion tables checked mechanically against the index ranges their guards
  allow
* the pre-auth surface *measured* by coverage differential rather than listed by
  hand (§4.15) ✔ — `parse_client_handshake_packet` at 96.05% of its lines,
  `native_password_authenticate` / `thd_init_client_charset` /
  `convert_error_message` at 100%, two genuinely untested branches found and
  closed, no assertion failure anywhere with `DBUG_ASSERT` live
* **both** enumerations over that measured set: writes (§4.17) and indirect
  calls (§4.22) ✔
* the auth-bypass line closed with the official account set dumped from the
  running container (§5.1) ✔
* concurrency (§4.18) ✔ — 233,624 rounds over 32 threads; and the lazy
  collation-initialisation race (§4.16) ✔ — 6,120 barrier-synchronised
  connections across all 256 collation ids on a freshly started server
* network fuzzing ✔ — ~250,000 randomised and targeted pre-auth cases against
  the ASAN build: capability-flag combinations, charset ids,
  username/database/plugin-name shapes, all three auth-response length
  encodings, malformed connection-attribute blobs, truncation at the 31/32
  boundary, multi-packet bodies, auth-switch replies above `net_buffer_length`,
  TLS-upgraded and deliberately-failed-TLS connections, desynchronised sequence
  numbers and PROXY-protocol signatures. No sanitizer report, no crash.
* in-process fuzzing (§4.19, §4.21) ✔ — hook verified live by A/B timing
  (140 ms vs 1031 ms per 100 seeds); campaign now runs at N=200 with the server
  recycled every 30,000 connections. No sanitizer report.
* the pre-auth memory question settled at byte level (§4.20) ✔ — and the
  weaker RSS-based claim in §4.18 withdrawn

Known limits of these results, stated rather than left implicit:
* the in-process campaign parses from **accumulated, mutated state**, not from
  fresh-connection state (§4.21); only the network campaigns are faithful to a
  fresh connection, and anything the hook flags must be reproduced over the
  network against an unmodified binary before it counts;
* neither enumeration closes an out-of-bounds **read**. An info leak is not an
  RCE, but it could feed one, and §4.2/§4.3 are both reads that happen to stay
  in bounds *on this target* — a different allocator state would change that
  argument, not the code;
* the `-O0` debug build used for §4.22 has more indirect calls than the release
  binary the target runs; that direction is conservative (it over-reports
  sites), but the release build's devirtualisation was not separately checked.

What is still outstanding, in order of expected value:
* **Out-of-bounds reads as a class**, enumerated the way writes and indirect
  calls were, over the same measured set. This is the one memory-safety class
  not yet closed mechanically.
* **Re-pin `mariadb:latest` before any submission.**

## 7. Tooling in this directory

* `mariadb_preauth.py` — byte-level pre-auth protocol client. Exposes every
  handshake-response field independently, supports raw packet truncation,
  multi-packet bodies, the three auth-response length encodings, raw
  connection-attribute blobs and the auth-switch round trip. Run directly to
  dump a server's greeting and whether it advertises `CLIENT_SSL`.
* `preauth_fuzz.py` — randomised driver over that harness with a liveness-based
  crash detector. Covers plain and TLS-upgraded connections, desynchronised
  packet sequence numbers and PROXY-protocol signatures.
* `poc_post_tls_short_packet.py` — §4.2: TLS upgrade, then handshake responses
  shorter than 32 bytes.
* `poc_next_field_boundary.py` — §4.3: packet lengths aligned to the allocator's
  4096-byte rounding, with the database field running to the final byte.
* `poc_deep_targeted.py` — §4.13/§4.14: four groups aimed at specific
  arithmetic rather than at random coverage — the error-formatting buffers at
  their exact boundaries, the username boundary across charsets, the
  `net_realloc` and multi-packet shapes, and every collation id.
* `verify_charset_tables.py` — static, no server needed: parses every
  range-guarded conversion-table lookup out of the charset sources and compares
  the table's real initializer length against the range its guard admits.
* `poc_coverage_gaps.py` — §4.15: the two branches measured coverage showed were
  never reached, a rejected TLS handshake and a multi-packet that exceeds
  `max_allowed_packet`.
* `preauth_concurrent.py` — §4.18: many-threaded pre-auth stress against the
  shared ACL/TLS/counter state, with RSS sampling for leak detection.
* `poc_collation_race.py` — §4.16: barrier-synchronised bursts that race the
  first use of each collation id, which is what an unauthenticated client picks.
* `drive_inprocess_fuzz.py` — §4.19: seed supplier for the in-process re-parse
  hook; keeps every packet inside the hook's size window so it always engages.
* `writes_all.py` — §4.17: enumerates every memory-writing call site across the
  *measured* pre-auth function set, so the result does not depend on a call
  graph written by hand.
  `python3 -I writes_all.py cov-preauth-only.txt <source-root>`
  → 46 functions, 127 call sites.
* `indirect.py` — §4.22: the control-flow dual of the above. Streams
  `objdump -d -C` over the server binary, keeps the measured pre-auth functions
  and classifies every indirect `call`/`jmp` by operand (register, memory, GOT),
  so no site can hide behind a macro, a template or virtual dispatch.
  `python3 -I indirect.py cov-preauth-only.txt <build>/sql/mariadbd`
  → 1,809 register / 73 memory / 0 GOT. Deduplicate to source locations with
  `addr2line -e <binary> -C -s`.
* `probe_status.py` — §4.20: minimal authenticated client over the unix socket
  (native_password by hand), used to read MariaDB's own byte-exact
  `Memory_used` accounting, which RSS cannot substitute for on an ASAN build.
  `python3 -I probe_status.py <datadir>/m.sock '<password>'`

### Reproducing

```bash
# official target, exactly as the organisers define it
docker compose pull && docker compose up -d
python3 -I mariadb_preauth.py 127.0.0.1 3306

# instrumented build for the memory-safety work
cmake -S <src> -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DWITH_ASAN=ON \
      -DWITH_SSL=system -DWITH_WSREP=OFF -DWITH_EMBEDDED_SERVER=OFF
cmake --build build-asan --target mariadbd
# ASAN_OPTIONS=abort_on_error=1 so a bad access kills the server and the
# harness' liveness check notices
```
