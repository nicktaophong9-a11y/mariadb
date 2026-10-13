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

### 4.24 Making out-of-packet reads visible, and what that does to §4.3

The one memory-safety class the two enumerations do not close is the
out-of-bounds *read*, and §4.2 and §4.3 are exactly that: reads that leave the
packet body but stay inside the `net->buff` allocation. That is precisely why
ASAN cannot see them — the slack between the end of the packet and
`net->buff_end` is addressable memory, so an over-read lands in valid heap and
nothing complains. The argument that they are harmless was mine, from reading
the code; nothing was checking it.

So the research build now poisons that slack. For the duration of each
re-parse the hook calls

```c
  uchar *from= net->read_pos + len + 1;   /* +1: the terminator my_net_read sets */
  from= (uchar*) (((uintptr_t) from + 7) & ~(uintptr_t) 7);
  if (net->buff_end > from)
    __asan_poison_memory_region(from, (size_t) (net->buff_end - from));
```

and unpoisons before its own `memcpy` and on the way out. The start is rounded
up because ASAN poisons whole 8-byte granules, so the detector is accurate to
within 8 bytes of the packet end rather than exactly at it — it under-reports,
never over-reports.

This is only safe *inside the hook*. The hook clears `CLIENT_SSL` and
`CLIENT_PLUGIN_AUTH` out of every mutated packet, so the parser performs no
network I/O; poisoning around the **network** parse would false-positive,
because `my_net_init()` sets `net->buff = net->write_pos` and
`net->read_pos = net->buff` — one buffer for both directions — so the two
nested `my_net_read()` calls inside `parse_client_handshake_packet()`
(`sql_acl.cc:14490` post-TLS, `:14722` auth-switch) and the four write sites in
`sql_acl.cc` all land in the poisoned slack legitimately. Extending it to the
network path means unpoisoning at each of those six sites; not done yet.

**The detector fires on the first run**, which is the point of building it:

```
==3868==ERROR: AddressSanitizer: use-after-poison on address 0x5290000f0228
READ of size 2 at 0x5290000f0228 thread T13
    #0 strlen
    #1 parse_client_handshake_packet  sql_acl.cc:14567
    ...
0x5290000f0228 is located 40 bytes inside of 16424-byte region
  =>0x5290000f0200: 00 00 00 00 00[f7]f7 f7 f7 f7 f7 f7 ...
```

`sql_acl.cc:14567` is `passwd_len= strlen(passwd);` in the
`!CLIENT_SECURE_CONNECTION` branch — **§4.3**. So §4.3 is no longer a reading
of the code: it has a sanitizer stack trace behind it, reached from an ordinary
pre-auth packet. The shadow bytes read exactly as designed: five addressable
granules, then poison, and the scan one byte past the boundary.

Because that known read halts the server on the first mutated packet that
reaches it, the hook now also sets `CLIENT_SECURE_CONNECTION` back on, so the
poisoned campaign can explore the rest of the parser instead of stopping on
something already written up. The branch itself is still fuzzed over the
network, where the poisoning is not in effect.

#### §4.3 is bounded by an invariant, not by luck

With the read demonstrated, its original dismissal deserved a harder look.
§4.3 said "not triggerable" because the slack is `my_malloc`'d and a fresh
mapping reads back as zeros, so the scan stops immediately. That argument is
about the allocator, and an attacker who can put non-zero bytes in the slack
would break it. There is a path to try: `parse_client_handshake_packet()` runs
once per connection, but its `CLIENT_SSL` branch reads a **second** packet into
the same buffer, so a large pre-TLS packet followed by a small post-TLS one
leaves the first packet's bytes in the tail the scan then walks. Only the
capability words are parsed before `sslaccept()`, so the rest of that first
packet is free padding.

`poc_slack_scan.py` does this — the large packet *is* the SSLRequest, which is
what `Conn.start_tls(request=...)` was added for — and sweeps pre-TLS padding
from 0 to 65536 against usernames that run to the final byte so that `passwd`
lands past the terminator. It also runs the stronger form: one connection fills
a buffer and drops it, and the next connection's `my_net_init()` may be handed
the same freed chunk, so the tail is the previous connection's data rather than
a fresh mapping.

**40 padding cases and 125 fill/scan pairs: every one returns `err1043`, the
server stays up, and there is no ASAN report.** The reason is an invariant
rather than the allocator: `my_net_read()` always writes a terminating zero at
`read_pos[pkt_len]`, so *every* region of the buffer that has ever held
incoming data ends in a zero, at a position no higher than
`net->buff + net->max_packet` — inside the allocation. The scan therefore stops
at the most recent terminator wherever it starts. Pre-auth there is no way to
write a large region with no trailing zero: the write side shares the buffer
but everything it emits pre-auth is small (the greeting, an auth-switch
request, an error packet capped at 520 bytes by §4.13), and a packet large
enough to reach the end of the buffer triggers `net_realloc` into a fresh
allocation whose tail is untouched.

That is a materially better argument than the one §4.3 shipped with, and it
does not depend on the allocator. One honest caveat in the other direction:
ASAN quarantines freed chunks, so the fill-then-scan phase is weaker evidence
on this build than it would be against stock glibc — but the invariant does
not care which allocator is underneath.

### 4.25 A pre-auth out-of-bounds read that leaves the heap block — one root cause, four branches

This is the first memory-safety defect found here that actually crosses an
allocation boundary, and it is reached from a single unauthenticated packet on
3306. It is **not** an RCE, and the reasons are set out at the end; it is
recorded because it is a real bug with a one-line fix, and because it corrects
§4.3.

#### The root cause

```c
  char *passwd= strend(user)+1;                      /* sql_acl.cc:14547 */
```

`my_net_read()` guarantees a terminating zero at `read_pos[pkt_len]`. When the
username fills the packet to its final byte and carries no NUL of its own,
`strend(user)` stops on *that* terminator, so `passwd == read_pos + pkt_len + 1`
— one byte outside the packet. Nothing checks `passwd` before the three
branches that consume it, and the comment above the second one asserts the
opposite:

```c
  else if (!(thd->client_capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA))
  {
    /* Packet buffer is null-terminated by the network layer, so strend(user)
       stays within bounds and passwd remains within the packet. */
    passwd_len= (uchar)(*passwd++);                  /* :14575 */
  }
```

#### The three branches read different distances past the buffer

`net_allocate_new_packet()` and `net_realloc()` both allocate
`max_packet + NET_HEADER_SIZE + COMP_HEADER_SIZE + 1`, i.e. `max_packet + 8`,
and set `buff_end = buff + max_packet`. So there are exactly **8 bytes** of
slack past `buff_end`, and a packet of exactly `max_packet` bytes puts `passwd`
at `buff + max_packet + 1`, with 7 bytes of slack left.

| branch | capabilities | consumer | reads |
|---|---|---|---|
| `strlen` | `!CLIENT_SECURE_CONNECTION` | `strlen(passwd)` | **unbounded** — until it finds a zero |
| `len1` | `CLIENT_SECURE_CONNECTION` | `(uchar)(*passwd++)` | 1 byte — stays inside the slack |
| `lenenc` | `+ ..._LENENC_CLIENT_DATA` | `safe_net_field_length_ll()` | up to 9 bytes |

The `lenenc` branch is the interesting one, because it defeats a bound that
exists to stop exactly this:

```c
    ulonglong len= safe_net_field_length_ll((uchar**)&passwd,
                            net->read_pos + pkt_len - (uchar*)passwd);  /* :14581 */
```

and the helper takes that bound **unsigned**:

```c
my_ulonglong safe_net_field_length_ll(uchar **packet, size_t packet_len);
```

With `passwd == read_pos + pkt_len + 1` the difference is `-1`, which converts
to `SIZE_MAX`. Every internal `if (packet_len < N) goto err` then passes, so the
0xFE case runs `(*packet)+=9; return uint8korr(pos+1);` with no bound at all —
`uint8korr` reads `pos[1..8]`, ending at `buff + max_packet + 9` while the last
valid byte is `buff + max_packet + 7`. **Two bytes past the end of the block.**

#### A fourth consumer, on the capability set every real client sends

`passwd` is not the only pointer the guard fails to bound. Immediately after it:

```c
  if (passwd == NULL ||
      passwd + passwd_len + MY_TEST(db) > (char*) net->read_pos + pkt_len)
    return packet_error;                 /* bounds passwd + passwd_len + 1 */

  /* strlen() can't be easily deleted without changing protocol */
  db_len= safe_strlen(db);               /* db is inside, so db + db_len can
                                            reach read_pos + pkt_len exactly */

  char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
  Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);   /* :14598 */
```

The guard accounts for `passwd_len` but **not for `db_len`**. `db` is inside the
packet, so `safe_strlen(db)` stops at the packet terminator at worst, which puts
`db + db_len` at `read_pos + pkt_len` and `next_field` at
`read_pos + pkt_len + 1` — outside again, and `Lex_cstring_strlen` is a plain
`strlen`, so the scan is **unbounded**.

This is the most serious of the four, because it needs no legacy or exotic
capability: `CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB |
CLIENT_PLUGIN_AUTH` is what every real client sends. Under the adversarial heap:

```
nextfield -> AddressSanitizer: heap-buffer-overflow
             READ of size 8 at 0x5290000ef228
             0x5290000ef228 is located 0 bytes after 16424-byte region
             #0 strlen
             #1 Lex_cstring_strlen::Lex_cstring_strlen(char const*) sql/lex_string.h:140
             #2 parse_client_handshake_packet sql_acl.cc:14598
```

and clean on a stock heap over 400 reps, like the others.

The bound for it **exists and is correct** — it is just evaluated after the scan
that needs it:

```c
  if ((thd->client_capabilities & CLIENT_PLUGIN_AUTH) &&
      (client_plugin.str < (char *)net->read_pos + pkt_len))     /* :14658 */
    next_field+= strlen(next_field) + 1;
  else
  {
    /* Some clients lie. Sad, but true */
    thd->client_capabilities &= ~CLIENT_PLUGIN_AUTH;
    ...
    client_plugin= native_password_plugin_name;        /* the bad value is replaced */
  }
```

So the out-of-packet plugin name never reaches `cached_client_reply.plugin` or
the plugin comparison: `:14658` catches exactly the case `:14598` creates and
substitutes a server-side constant. Nothing between the two uses
`client_plugin`. The over-read happens; its result is thrown away.

The same file already has the correct pattern, 400 lines earlier and also
pre-auth, in `read_client_connect_attrs()`:

```c
  char *ptr_save= *ptr;
  /* not enough bytes to hold the length */
  if (ptr_save >= end)
    return true;                                     /* :14195 -- the guard */
  length= safe_net_field_length_ll((uchar **) ptr, end - ptr_save);
```

`parse_com_change_user_packet()` (`:14270`) has the same unguarded shape but is
post-auth, so it is out of scope here and worth mentioning only upstream.

#### Measured

`poc_passwd_past_end.py`, packet exactly 16384 bytes (a multiple of `IO_SIZE`,
so `net_realloc` leaves `max_packet == pkt_len` and the slack at its minimum),
username running to the final byte. Whether the read leaves the block depends on
the bytes following the buffer, which are **not** attacker-supplied — so the
heap is made adversarial instead of the packet, with
`ASAN_OPTIONS=malloc_fill_byte=254:max_malloc_fill_size=65536`: no zero byte
anywhere, and 0xFE is what selects the 9-byte branch.

```
strlen -> AddressSanitizer: heap-buffer-overflow
          READ of size 8 at 0x5290000ef228
          0x5290000ef228 is located 0 bytes after 16424-byte region
          #0 strlen  #1 parse_client_handshake_packet sql_acl.cc:14567

len1   -> 3 reps, server survived, no report

lenenc -> AddressSanitizer: unknown-crash
          READ of size 8 at 0x5290000ef222
          0x5290000ef228 is located 0 bytes after 16424-byte region
          #0 uint8korr include/my_byteorder.h:128
          #1 safe_net_field_length_ll sql-common/pack.c:110
          #2 parse_client_handshake_packet sql_acl.cc:14581
```

ASAN calls the `lenenc` case `unknown-crash` rather than
`heap-buffer-overflow` because the 8-byte read *straddles* the boundary — it
starts addressable and ends in the redzone — so it cannot be attributed to one
category; the `is located 0 bytes after` line and the shadow row
`00 00 00 00 [00] fa fa …` pin the boundary.

The offsets check out exactly: the 16424-byte region is
`my_malloc`'s `HEADER_SIZE` (32) plus the requested `max_packet + 8` with
`max_packet = 16384`, so `buff = region + 32`, the last valid byte is
`region + 16423`, and `uint8korr(pos+1)` ends at `region + 16425`.

Stack is pure pre-auth and owes nothing to my instrumentation — the hook was
off (`MARIADB_FUZZ_HANDSHAKE=0`) and no poisoning was in effect:
`check_connection` → `acl_authenticate` → `do_auth_once` →
`native_password_authenticate` → `server_mpvio_read_packet` →
`parse_client_handshake_packet`.

**On a stock heap it does not fire: 400 reps at the triggering length, server
survived, no report.**

#### Why this is not an RCE, and what it actually is

* The value is **discarded**. Whatever `passwd_len` comes back as, the common
  guard `passwd + passwd_len + MY_TEST(db) > read_pos + pkt_len` is
  unconditionally true once `passwd > read_pos + pkt_len`, so the packet is
  rejected with `packet_error`. There is no path from the bytes read to
  anything the client observes, so not even an information leak.
* It is a **read**, and §4.17 shows there is no write primitive to pair it with.
* The fourth branch's value is discarded too, by the existing `:14658` check —
  which is why this is an over-read and not a pre-auth heap disclosure, even
  though the plugin name would otherwise flow into `cached_client_reply`.
* Reaching past the block needs the memory after `net->buff` to contain no
  zero byte (and, for `lenenc`, a 0xFE at `buff + max_packet + 1`). Those bytes
  are not attacker-supplied through the protocol: no packet write ever reaches
  the 8-byte slack, because `my_net_read()` writes data at `0..pkt_len-1` and a
  zero at `pkt_len <= max_packet`. Arranging it means heap grooming, which I
  have **not** demonstrated — and real heaps are full of zero bytes, which is
  why the stock run is clean.
* Even granting the read, the consequence is at most a crash if the scan walks
  into an unmapped page. For the `strlen` branch that needs a zero-free run
  from the buffer to the end of the mapping; for `lenenc` it is 2 bytes.

So: a genuine pre-auth out-of-bounds read, conditional on heap contents,
worth an upstream report and not a ZeroDay Cloud entry.

#### Correction to §4.3

§4.3 called this shape "reachable, not triggerable", on the grounds that the
slack is `my_malloc`'d and a fresh mapping reads back as zeros. The first half
is right and the second is the wrong reason to be reassured: it is a statement
about what the allocator happens to hand over, not a bound. The accurate
statement is the one above — the read *does* leave the allocation whenever the
following memory has no zero in it, and what keeps it harmless is that the
result is discarded, not that it cannot happen. §4.24's invariant argument
(every region that ever held incoming data ends in a zero at a position no
higher than `buff + max_packet`) bounds the scan to the slack **inside** the
buffer only while that memory came from a previous packet; it says nothing
about memory past `buff_end`, which is where these reports land.

#### Fix

Two checks, not one. I first wrote this up as a single line bounding `passwd`,
which is wrong: it covers the first three branches but **not** the fourth,
where `passwd` is legitimately inside the packet and it is `next_field` that
escapes.

```c
   char *passwd= strend(user)+1;
+  if (passwd > (char*) net->read_pos + pkt_len)
+    return packet_error;
```

bounds the `strlen` / `len1` / `lenenc` branches at once, mirroring
`read_client_connect_attrs()`. And for the fourth, hoisting the check that
already exists at `:14658` above the scan at `:14598`:

```c
   char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
+  if (next_field > (char*) net->read_pos + pkt_len)
+    return packet_error;
   Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);
```

Neither rejects anything that is accepted today. For the first, the existing
guard already fails every packet that reaches it with `passwd` past the end;
for the second, `:14658` already discards the value. `next_field ==
read_pos + pkt_len` must stay legal — that is the terminator's own position,
giving an empty plugin name — which is why the comparison is `>` and not `>=`.

Both checks are applied in the research build and verified to silence all four
branches; see §4.26.

### 4.26 The poisoning moved onto the network path, and the fix validated against it

§4.24's poisoning only ran inside the hook, which limits it twice over: the hook
parses from accumulated mutated state (§4.21), and it clears `CLIENT_SSL` and
`CLIENT_PLUGIN_AUTH` out of every packet, so the post-TLS re-read branch — §4.2's
own path — and the auth-switch branch were the two places the poisoning could
never reach.

Extending it to the network parse means handling the ~20 `return packet_error`
paths of `parse_client_handshake_packet()` without leaving the buffer poisoned
behind, so it is a scope guard rather than scattered unpoison calls:

```cpp
class Preauth_tail_poison
{
  NET *m_net;
public:
  Preauth_tail_poison(NET *net, ulong len) : m_net(net)
  { preauth_poison_tail(net, len); }
  void lift() { preauth_unpoison_buffer(m_net); }
  ~Preauth_tail_poison() { preauth_unpoison_buffer(m_net); }
};
```

It is instantiated **after** the `CLIENT_SSL` / `check_require_secured_transport`
chain, where `pkt_len` is final for both the plain and the post-TLS path, so one
object covers the whole rest of the parse — the post-TLS branch included —
without needing to re-poison around the nested read. `lift()` is then needed at
exactly one place, the auth-switch round trip, which writes and reads
`net->buff` for real:

```c
  if (client_auth_plugin &&
      !client_plugin.streq(Lex_cstring_strlen(client_auth_plugin)))
  {
    tail_poison.lift();
    ...
    if (send_plugin_request_packet(...)) return packet_error;
    passwd_len= my_net_read(&thd->net);
```

Nothing else in that scope writes into the tail: `my_error()` only fills the
diagnostics area, and the error packet is not written to `net->buff` until after
the parse has returned and the guard has lifted.

#### What this buys: detection on a stock heap

§4.25 needed `malloc_fill_byte=254` to see anything, because on a stock heap the
over-reads land in valid memory. With the slack poisoned they are reported
regardless of what the heap holds:

```
nextfield -> use-after-poison, sql_acl.cc:14658   (stock heap, 512-byte packet)
strlen    -> use-after-poison, sql_acl.cc:14627   (stock heap, 512-byte packet)
```

The other two are silent at that length for a reason worth recording, because it
is the detector's resolution rather than their absence: ASAN poisons whole
8-byte granules, so `preauth_poison_tail()` rounds the start up and the first
`(8 - (pkt_len + 1) % 8) % 8` bytes past the packet stay addressable. `len1`
reads exactly one byte there and falls in that gap; `lenenc` reads one byte too
unless the heap hands it 0xFE. Choosing `pkt_len ≡ 7 (mod 8)` puts the poison
boundary exactly at `pkt_len + 1`, which is why 511 is in the test set
alongside 512 and 16384.

#### The proposed fix, validated

The two checks §4.25 proposes are now applied in the research build, behind
`MARIADB_PREAUTH_FUZZ_HOOK`, both so they can be tested and so the four known
sites stop masking everything else. Against the poisoned network path, all four
branches go clean at all three lengths:

```
nextfield -> clean (511/512/16384)
strlen    -> clean (511/512/16384)
lenenc    -> clean (511/512/16384)
len1      -> clean (511/512/16384)
```

So the fix is complete for this root cause, not merely plausible — which is
also what justifies my correcting the single-check version I first wrote down.

With the bug patched in the instrumented build, the whole battery was re-run
under the new detection regime: 20,000 randomised cases, the four targeted PoC
groups, the coverage-gap shapes, the post-TLS short packets, the slack-scan
pairs, 32-thread concurrency and the collation race. Every one of these had been
run before, but never with the memory past the packet poisoned, so an over-read
that stays inside `net->buff` is now a report instead of silence.

### 4.27 §4.2 confirmed: the post-TLS re-read does read out of the packet

With the poisoning on the network path and §4.25 fixed in the research build,
the randomised driver produced a report at iteration 250 of 20,000 — so this is
not a corner the fuzzer struggles to reach:

```
==7494==ERROR: AddressSanitizer: use-after-poison
    #0 parse_client_handshake_packet  sql/sql_acl.cc:14579
    #1 server_mpvio_read_packet       sql/sql_acl.cc:15035
    #2 native_password_authenticate   sql/sql_acl.cc:15678
    #3 do_auth_once                   sql/sql_acl.cc:15227
    #4 acl_authenticate               sql/sql_acl.cc:15356
    #5 check_connection               sql/sql_connect.cc:1184
```

`:14579` is `thd_init_client_charset(thd, (uint) net->read_pos[8])`, with
`uint4korr(net->read_pos+4)` on the line above it. The structure is what makes
it reachable:

```c
  if (pkt_len < MIN_HANDSHAKE_SIZE)            /* 6 */
    return packet_error;
  ulonglong client_capabilities= uint2korr(net->read_pos);
  if (client_capabilities & CLIENT_PROTOCOL_41)
  {
    if (pkt_len < 32)                          /* the 32-byte check, first read only */
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

`client_capabilities` is parsed from the pre-TLS packet and still says
`CLIENT_PROTOCOL_41`, but `pkt_len` now belongs to the post-TLS packet and has
only been checked against 6. So offsets 4..8 are read out of a packet that can
be 6 bytes long, and `end` is set to `read_pos + 32` regardless.

This is **§4.2**, which recorded the missing 32-byte minimum but could only call
it "reachable, not exploitable" — the over-read itself was never observed,
because it lands inside `net->buff` where ASAN cannot see it. It is now
observed.

Consequences, and why it stays bounded: the byte at offset 8 is a collation id,
so an out-of-packet byte selects the connection charset and drives the lazy
collation initialisation of §4.16 and the conversion tier of §4.13. Then
`end = read_pos + 32` meets `if (end >= (char*) net->read_pos + pkt_len + 2)
return packet_error;`, which rejects every `pkt_len <= 30`. So the charset is
set from stale buffer memory and the connection is then refused; the read is
deep inside the 16 KB buffer, never past the allocation. A remote client gets
no observable difference, and nothing persists.

Fix, mirroring the check the first read already has:

```c
     pkt_len= my_net_read(net);
+    if ((client_capabilities & CLIENT_PROTOCOL_41) && pkt_len != packet_error &&
+        pkt_len < 32)
+      return packet_error;
     if (unlikely(pkt_len == packet_error || pkt_len < NORMAL_HANDSHAKE_SIZE))
       return packet_error;
```

Applied in the research build and `poc_post_tls_short_packet.py` goes clean,
so the battery can carry on to whatever is behind it. Both §4.25's and this
fix are behind `MARIADB_PREAUTH_FUZZ_HOOK` and must not ship — they are there
to stop known bugs masking unknown ones.

### 4.28 The battery under the new detection regime, and two parsers finished off

With §4.25 and §4.2 both patched in the research build and the tail poisoning
live on the network path, the whole battery was re-run. **All eight stages
clean, no sanitizer report:** 20,000 randomised cases, the four targeted PoC
groups of §4.13/§4.14, the coverage-gap shapes of §4.15, the `next_field`
boundary sweep, the post-TLS short packets, the slack-scan padding sweep and
fill/scan pairs, 32-thread concurrency for 240 s, and the barrier-synchronised
collation race over all 256 ids.

That is worth more than the same result was worth yesterday. The detector is
demonstrably sensitive — it produced five sites in minutes on code that ~250,000
network cases had previously walked through in silence — so a clean run now
says something about the inputs rather than about the instrument.

**Then at volume.** `netcampaign.sh` ran 40 rounds of 25,000 randomised cases —
**1,000,000 pre-auth cases** — against the poisoned build, restarting the server
after any report so one finding could not stop the run. Every round came back
`rc=0` with zero reports and the server alive. Unlike the in-process campaign
this parses from true fresh-connection state (§4.21), so it is the faithful
measurement; and unlike the earlier ~250,000 cases, the memory past the packet
was poisoned throughout. For comparison, the first 20,000 cases under this
regime found §4.27 at iteration 250.

The in-process campaign reached **108,000,000 poisoned parses** with no report
before being stopped — it shared port 3307 and the datadir with the network
campaign, so the two could not run together, and the faithful one won.

Taken together: of the five over-read sites, all five were found within the
first 20,000 cases once the slack was poisoned, and a further 1,000,000 network
cases plus 108,000,000 in-process parses produced nothing new. That is the
strongest statement available here about the *inputs* having been explored,
given a detector whose sensitivity is demonstrated rather than assumed.

Two parsers were then read line by line, both pre-auth and both previously
waved past on scope grounds rather than audited:

**`read_client_connect_attrs()`** — I had excluded the connection-attributes
blob early on because its sink is the performance schema, which is off. That
argument is about the sink; the *parser* runs regardless. It is sound:

```c
  if (ptr_save >= end) return true;                       /* the guard */
  length= safe_net_field_length_ll((uchar **) ptr, end - ptr_save);
  if (*ptr == NULL) return true;
  if (*ptr + length > end) return true;
  if (length > 65535) return true;
```

`length` is a `ulonglong` straight off the wire, so `*ptr + length` can wrap for
a 9-byte length encoding and the third check would pass — but the 64 KB limit
rejects every length large enough to wrap before anything uses it, so only
values ≤ 65535 reach the sink and for those the pointer arithmetic is honest.
Note the first guard here is exactly what §4.25's call site is missing.

`is_connector_net_client()`, which runs whether or not the performance schema
is on, is also guarded:

```c
  if (length < prefix.length)
    return false;
  if (connection_attrs[prefix.length - 1] != prefix.str[prefix.length - 1])
    return false;
  return !memcmp(connection_attrs, prefix.str, prefix.length);
```

both the fast path and the `memcmp` are covered by the length test, and
`length` was already bounded by `*ptr + length <= end`, so the comparison stays
inside the packet.

**The non-compressed multi-packet reassembly** in `my_net_read_packet_reallen()`
/ `my_real_read()`. §4.17 established that the `memmove`s there are
compressed-branch, i.e. post-auth, but said nothing about the arithmetic of the
path an unauthenticated client *can* drive with `0xFFFFFF` continuations:

```c
      len= uint3korr(net->buff + net->where_b);
      if (!len) goto end;                        /* end of big multi-packet */
      helping= MY_MAX(len, *complen) + net->where_b;
      if (helping >= net->max_packet)
        if (net_realloc(net, helping)) { len= packet_error; goto end; }
      pos= net->buff + net->where_b;
```

The bound includes `where_b`, so it is the *accumulated* total that
`net_realloc` tests against `max_packet_size`, not each segment on its own —
which is the mistake that would have made this interesting. With
`max_allowed_packet = 16777216` the first `0xFFFFFF` segment leaves
`where_b = 16777215`, so any continuation of even one byte makes
`helping >= 16777216` and is refused (§4.14). On the failure path
`pos = net->buff + net->where_b` is never reached, so nothing is written at the
advanced offset, and the caller restores `where_b = save_pos` before computing
`read_pos`. Sound.

### 4.29 The logging tier, which runs on every failed pre-auth login

Easy to overlook because it is not part of the protocol, but the instrumented
server's own log shows attacker bytes going through it before authentication:

```
[Warning] Access denied for user 'Ã©Ã©Ã©Ã©Ã©Ã©Ã©Ã©Ã©Ã©Ã©Ã©…'@'127.0.0.1'
[Warning] Aborted connection 22188 to db: 'unconnected' user: 'unauthenticated'
```

`login_failed_error()` has three sinks, and two of them are live on the target:

```c
static void login_failed_error(THD *thd)
{
  my_error(access_denied_error_code(thd->password), MYF(0),
           thd->main_security_ctx.user, thd->main_security_ctx.host_or_ip, ...);
  general_log_print(thd, COM_CONNECT, ER_THD(thd, ...),
                    thd->main_security_ctx.user, ...);
  ...
  if (global_system_variables.log_warnings > 1)
    sql_print_warning(ER_DEFAULT(access_denied_error_code(thd->password)),
                      thd->main_security_ctx.user, ...);
}
```

* `my_error()` → the client error packet, audited in §4.13
  (`ebuff[MYSQL_ERRMSG_SIZE]` → `converted_err[512]` → `buff[520]`).
* `sql_print_warning()` → `error_log_print` → `vprint_msg_to_log`, which is
  **active by default** since `log_warnings` defaults to 2:
  ```c
    char buff[1024];
    length= my_vsnprintf(buff, sizeof(buff), format, args);
  ```
* `general_log_print()` → `LOGGER::general_log_print`, which formats
  **unconditionally**, before `general_log_write()` checks `opt_log`:
  ```c
    char message_buff[MAX_LOG_BUFFER_SIZE];          /* 1024 */
    if (format)
      message_buff_len= my_vsnprintf(message_buff, sizeof(message_buff),
                                     format, args);
    return general_log_write(thd, command, message_buff, message_buff_len);
  ```
  So the username is written into a 1 KB stack buffer on every failed login
  whether or not the general log is on; only the consumer is gated.

All three pass `sizeof(dest)`, so the question is what `my_vsnprintf` does with
it, and that matters well beyond here — the returned length is used as a length
by its callers:

```c
  DBUG_ASSERT(to <= end);
  *to='\0';
  return (size_t) (to - start);
```

It returns the bytes **actually written**, not the would-be length the way C99
`snprintf` does. That is the contract that makes
`general_log_write(thd, command, message_buff, message_buff_len)` safe: an
inflated length there would be an out-of-bounds read with an attacker-influenced
size, on every failed login. It is not inflated.

The formats are server constants throughout (`ER_DEFAULT`, `ER_THD`), never
attacker data, so there is no format-string exposure either; and §4.13 already
verified `process_str_arg`'s clamping for the unqualified `%s` in
`ER_ACCESS_DENIED_ERROR` (MariaDB's template carries no precision specifier —
the precision is MySQL's, which is the mistake §4.13 records me making).

### 4.30 The blind spot in §4.17 and §4.22, measured and closed

Both enumerations ran over the 290-function set from the coverage differential
of §4.15, and that set is `cov-B − cov-A`: functions executed by pre-auth
traffic **but not** by a bare start/stop. Two consequences I had not drawn:

1. anything that runs at startup *and* pre-auth was subtracted away, even where
   an unauthenticated client can re-enter it;
2. the set is "what my own corpus reached", so a pre-auth-reachable function the
   fuzzers never entered is outside both enumerations entirely.

So "no write primitive" was only ever as strong as my corpus. `reach.py`
(scratchpad) closes that: it builds the direct-call graph out of the binary,
takes the transitive closure from 18 pre-auth entry points, cuts it at the
post-auth boundary (`do_command`, `dispatch_command`,
`prepare_new_connection_state`, `set_privs_on_login`, …) and compares.

```
functions in binary                    : 44,737
statically reachable pre-auth          :    901
  of those executed in the traffic run :    452
  of those never executed              :    449
differential set used by §4.17/§4.22   :    290
  executed, in the closure, but DROPPED
  by the differential (ran at startup) :    331
```

331 functions were executed, are pre-auth-reachable, and were thrown away by my
own method — among them `Binary_string::alloc/realloc/copy/c_ptr`,
`Diagnostics_area::push_warning`, the `Charset_collation_map_st` lookups: exactly
the string and buffer machinery attacker data flows through. (Of the 290, only
121 are in the static closure; the other 169 are reached through indirect or
inlined edges a direct-call graph cannot see, which is why the corrected target
is the *union* of the two, 621 functions, rather than the closure alone.)

#### Re-run over the union: both results hold, and now without the blind spot

Writes: **120 functions, 378 call sites** (was 46 / 127), so 110 write-bearing
functions had never been enumerated. Triaged, no new primitive. The two shapes
that looked like one:

* `mysys/charset.c:846`, in `find_collation_data_inheritance_source()` —
  `memcpy(name, beg, end - beg)` into `char name[MY_CS_COLLATION_NAME_SIZE + 1]`
  is the shape of a stack overflow, but the condition that reaches it is
  `(beg= cs->tailoring + 8) + MY_CS_COLLATION_NAME_SIZE > end`, i.e.
  `end - beg < MY_CS_COLLATION_NAME_SIZE`, so the copy and the following
  `name[end - beg]= '\0'` both land inside. Bounded, and `cs->tailoring` is
  compiled-in or file-loaded data, not wire data.
* `mysys/charset.c:886`, in `get_internal_charset()` —
  `strxmov(get_charsets_dir(buf), cs->cs_name.str, ".xml", NullS)` is genuinely
  unbounded, and its safety rests on `--character-sets-dir` being short:
  `get_charsets_dir()` fills `buf` with up to `FN_REFLEN-1` bytes and `strxmov`
  appends past that. Controlling that option means already owning the server, so
  it is a robustness issue rather than a vector.

The primitives §4.17's whole argument rests on were also never in the set, so
they were never checked. They are correct:

* `safe_strcpy(dst, dst_size, src)` — `strncpy(dst, src, dst_size)` then
  `dst[dst_size - 1]= 0`; writes stay in `[0, dst_size)`.
* `strnmov(dst, src, n)` — copies at most `n` bytes and deliberately does not
  terminate, which is why its caller compares the result against `dst + n`
  before writing `dst[dst_size-1]= 0`.
* `strmake(dst, src, length)` — copies at most `length` and writes `*dst= 0` at
  index `length`, so it needs `length + 1` bytes, which is exactly why
  `strmake_buf(D, S)` passes `sizeof(D) - 1`.

Indirect calls: **reg=2,972 / mem=558** over the union (was 1,809 / 73). Every
memory-operand function new to this run falls in a category §4.22 already
settled — PSI service pointers, the allocator size callback, the
`error_log_handler_list` handlers, `lf_hash`'s comparison callback,
`IO_CACHE::read_function`, `THD::m_internal_handler`, and the `CHARSET_INFO`
handlers (`my_well_formed_length`, `Lex_ident_fs::check_body`) that the
attacker's collation id selects among. No pointer takes its value from
attacker bytes.

So the larger enumeration **confirms** §4.17 and §4.22 instead of overturning
them, and no longer depends on my differential's blind spot.

#### The 449 that are reachable and were never executed

Attributed to a file through the debug build's line info, every bucket has a
reason, and every one is unreachable by an unauthenticated client:

| bucket | functions | why it never ran |
|---|---|---|
| `pfs_*.cc`, `pfs.cc` | 32 | `performance_schema` is off |
| `sql_cache.cc` | 35 | query cache off by default, and post-auth |
| `debug_sync.cc`, `dbug.c` | 34 | debug build only, not in the release the target runs |
| `xml.c`, `ctype.c` | 25 | charset XML loader: startup-only behind `my_pthread_once`, and the per-charset branch is dead because all 36 charsets Index.xml declares are compiled in — see below |
| `dtoa.c`, `my_vsnprintf.c` | 25 | float and other conversions no pre-auth template uses |
| `hostname.cc` | 8 | `skip_name_resolve=ON` (§2) |
| `sql_db.cc` | 7 | post-auth |
| `sql_profile.cc` | 6 | profiling off |
| `sql_audit.cc`/`.h` | 6 | no audit plugin loaded |
| `proxy_protocol.cc` | 5 | `proxy_protocol_networks` unset |
| `my_compress.c` | 4 | compression is post-auth (`net.compress` is set in `prepare_new_connection_state`) |
| `my_sha224.cc` | 4 | `caching_sha2_password` / `sha256_password` are not loaded |

(269 of the 449 attribute to a file; the rest are template instantiations and
inlined helpers `nm` does not place.)

#### The last bucket, and a correction: it is closed too

`xml.c` / `ctype.c` is the `Index.xml` charset loader. I first wrote this up as
attacker-triggerable, reasoning that `get_internal_charset()` enters

```c
    if (!(cs->state & (MY_CS_COMPILED|MY_CS_LOADED)))  /* if CS is not in memory */
    {
      strxmov(get_charsets_dir(buf), cs->cs_name.str, ".xml", NullS);
      my_read_charset_file(&loader, buf, flags);
    }
```

for any collation id whose charset is not compiled in, and that §4.13 had shown
gb18030 missing from the official image. **Both halves of that were wrong**, and
the conclusion with them.

There is no `ctype-gb18030.c` anywhere in the 13.0.2 tree and nothing under
`strings/` or `include/` mentions gb18030: it is a MySQL charset MariaDB does
not implement. So "not compiled into the official image" is true but says
nothing about the package's charset set — §4.13 was right to drop gb18030 from
scope, and I was wrong to build an argument about build fidelity on top of it.

The branch is dead on this target in any case. The image ships one charset
file, `/usr/share/mariadb/charsets/Index.xml`, declaring 36 charsets, and every
one of the 36 has a `ctype-*.c` implementation in the source — nothing is
declared but not compiled. Every collation id that resolves at all resolves to
a compiled charset, so `!(MY_CS_COMPILED|MY_CS_LOADED)` is never true.

The loader does run, but at startup rather than on demand:
`init_available_charsets()` calls `init_compiled_charsets()` and then reads
Index.xml unconditionally, behind
`my_pthread_once(&charsets_initialized, init_available_charsets)` — once per
process, triggered by server initialisation long before any client connects,
with a fixed server-owned file as input.

So why were those 25 functions never executed here? Because my build tree has
no `share/charsets/` directory at all: `my_read_charset_file()` cannot open the
file and returns, so `my_xml_parse()` never runs. That is the real difference
between my build and the target, it is nothing like the charset-set gap I
claimed, and it changes nothing pre-auth — on the target the same code parses
the same server-owned file once at startup.

**So every one of the 449 is accounted for and none is attacker-reachable** —
this bucket by the `once` guard and the compiled-charset set, the rest by the
target's configuration.

### 4.31 The §4.25 bug class, hunted on purpose instead of by accident

§4.25's `lenenc` branch is a bound defeated by a pointer difference going
negative and converting to an unsigned parameter. I found it by following an
ASAN report, not by looking for it — which means the class deserved a
systematic pass rather than one lucky hit. `narrow.py` (scratchpad) enumerates
the two shapes across the pre-auth sources:

* **DIFF** — a pointer or length difference passed as an argument, where a
  negative value becomes enormous if the parameter is unsigned;
* **CAST** — a narrowing or sign-changing cast applied to a length expression.

Run over `sql_acl.cc`, `net_serv.cc`, `sql_connect.cc`, `pack.c`, `hostname.cc`,
`viosocket.c`, `viossl.c`, and then over the conversion tier (`ctype.c`,
`ctype-simple.c`, `ctype-utf8.c`, `ctype-mb.c`, `my_vsnprintf.c`,
`sql_string.cc`, `sql_error.cc`, `m_ctype.h`), it reports 30 sites in the
protocol files and 54 in the conversion tier. Most are the ordinary "cursor
minus start equals bytes written" shape, non-negative by construction. The ones
where the subtrahend could in principle exceed the minuend were read
individually:

| site | verdict |
|---|---|
| `sql_acl.cc:14198` `end - ptr_save` | guarded by `if (ptr_save >= end) return true;` (§4.28) |
| `sql_acl.cc:14581` `read_pos + pkt_len - passwd` | **this is §4.25** |
| `sql_acl.cc:14272`, `:14282` `end - passwd` | same shape, `parse_com_change_user_packet`, post-auth — for the upstream report, not this target |
| `sql_acl.cc:13877` `SCRAMBLE_LENGTH - data_len` | inside `if (data_len < SCRAMBLE_LENGTH)`; and `data` comes from the server plugin, not the client |
| `net_serv.cc:694`, `:719` `end - pos` | `pos` only advances by bytes actually written, so `pos <= end` holds |
| `net_serv.cc:1212`, `:1213` | compressed branch, post-auth |
| `my_vsnprintf.c:361` `length - res_length` | inside `if (res_length < length)`, with `length= MY_MIN(length, to_length)` and an earlier `if (res_length > to_length) return to;` above it, so `diff + res_length = length <= end - to` |
| `sql_string.cc:522` `max_length - str_length` | in the `else` of `if (str_length > max_length)` |
| `ctype-mb.c:985`, `:986` | `my_like_range_mb`, post-auth |

`ctype-simple.c:172` is worth quoting, because it shows the codebase is alive to
this class where it matters:

```c
  /*
    We can't use (slen - tlen) here as the result may be outside of the
    precision of a signed int
  */
  if (tlen == slen)
    return 0;
  *t_is_prefix= 0;
  return slen > tlen ? 1 : -1;
```

So the class that produced the only real finding here has now been swept rather
than stumbled into, and §4.25 plus its post-auth twin are the only two
instances in the pre-auth sources. That is the difference between "I did not
find another one" and "I looked for another one".

### 4.32 Can the memory after `net->buff` be groomed? Not this way

§4.25 crosses the allocation boundary only when the bytes after `net->buff`
contain no zero (and, for the `lenenc` branch, a 0xFE at `buff + max_packet + 1`).
I showed that with `malloc_fill_byte=254` and left the real question open: can an
unauthenticated client arrange it?

There is a mechanism that looked like it should work. `do_handle_one_connection()`
keeps the same `THD` across connections when a thread is cached:

```c
  for (;;)
  {
    if (thd_prepare_connection(thd))      /* authentication */
      goto end_thread;
    ...
end_thread:
    close_connection(thd);
    unlink_thd(thd);
    if (... || !(connect= thread_cache.park()))
      break;
    if (!(connect->create_thd(thd)))      /* reuses this THD */
      break;
```

and the `goto end_thread` path means a **failed** pre-auth connection is
followed by a reused `THD`. `CONNECT::create_thd(thd)` calls
`thd->reset_for_reuse()` and then `my_net_init()`, which allocates a *fresh*
`net->buff` while `net_end()` freed the old one — so on a stock allocator the
next connection of the same size class is likely handed the same chunk back,
contents intact. That is the grooming primitive I said I did not have.

To test it without ASAN's quarantine hiding the reuse the research build gained
a single switch: `MARIADB_PREAUTH_STOCK=1` turns off both the §4.25/§4.27 fixes
and the tail poisoning, so the binary behaves like the shipped one while still
running under ASAN. Combined with
`quarantine_size_mb=0:thread_local_quarantine_size_kb=0`, freed chunks are
reused immediately, the way glibc does and ASAN by default does not.

`groom.py` then alternates a connection that writes 16384 non-zero bytes across
`net->buff` and drops, with one whose username runs to the final byte so the
§4.25 `strlen()` walks whatever follows. **60 pairs, server survived, no
report.**

The reason is a flaw in my own design, not a property of the allocator: the
filling connection cannot write into the slack either. `my_net_read()` writes
the body at `0..pkt_len-1` and a terminating zero at `pkt_len <= max_packet`,
and the slack is the 8 bytes *after* `max_packet` — so no packet, filling or
scanning, ever reaches it. Grooming those offsets needs the previous occupant of
that memory to be some *other* allocation, not a `net->buff`.

Pre-auth, the attacker does have allocations whose size they choose — the
database-name conversion buffer of §4.9 goes up to tens of megabytes — so
genuine heap grooming is not obviously impossible. But it is now a question
about heap layout rather than about the protocol, the payoff is a read whose
value is discarded, and the ceiling is a crash. Recorded as open, and not
chased further on that basis.

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

**No unauthenticated RCE found.** One real memory-safety defect was found —
§4.25, a pre-auth out-of-bounds *read* that leaves the `net->buff` heap block,
reached from a single unauthenticated packet, with a one-line fix. It is not an
RCE: the value read is discarded by the guard that follows, there is no write
primitive to pair it with, and crossing the block boundary needs heap contents
I have not shown to be attacker-controllable. Worth reporting upstream, not a
competition entry.

Otherwise, two enumerations, both run over the *measured* pre-auth surface
rather than a hand-written call graph, are the central results:

* **§4.17 — no write primitive.** 378 memory-writing call sites across 120
  pre-auth functions, each checked individually; every one is bounded by a
  correct size computation, or is post-auth, or is a name collision that
  `gcov -f -m` attribution resolves. The bounded-copy primitives the argument
  rests on — `safe_strcpy`, `strnmov`, `strmake` — are verified too (§4.30),
  having been outside the first set entirely.
* **§4.22 — no attacker-supplied function pointer.** 3,530 indirect call sites
  (2,972 register-operand, 558 memory-operand), triaged by the *source* of the
  pointer. Every pre-auth function pointer comes from a compiled-in table or a
  server-set callback; the attacker chooses *which* valid table runs (collation
  id, TLS on or off), never what a pointer contains.
* **§4.30 — and both of those over the right set.** §4.17 and §4.22 first ran
  over the 290 functions of the coverage differential, which is `cov-B − cov-A`
  and therefore drops anything that also runs at startup — 331 pre-auth-reachable
  functions, including `Binary_string::alloc/realloc/copy` and
  `Diagnostics_area::push_warning`. Static reachability from the pre-auth entry
  points gives 901 functions, 452 of them executed; re-running both
  enumerations over the corrected union of 621 confirms both results instead of
  overturning them. The numbers above are the corrected ones. The 449 reachable
  functions that were never executed are accounted for bucket by bucket, and
  none of them is reachable by an unauthenticated client.

A memory-corruption RCE needs one or the other. Neither exists in this path.
And §5.1 closes the remaining route — a bypass followed by post-auth execution
— at the single rejection site in `acl_authenticate()`, with four checked facts.

Specifically:

* every out-of-bounds access found is a *read*. §4.2 stays inside the
  allocation; §4.3 does **not** always, which §4.25 corrects — it leaves the
  block whenever the memory after `net->buff` holds no zero byte, and what
  keeps it harmless is that the result is discarded, not that it cannot
  happen;
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
* out-of-bounds reads attacked directly (§4.24–§4.27) ✔ — the research build
  poisons the unused tail of `net->buff`, which is what made §4.2/§4.3-shaped
  over-reads visible at all: they land inside a valid 16 KB allocation, so
  ASAN cannot see them unaided. It reproduced §4.3 immediately, then found the
  other three branches of that root cause (§4.25, one of which crosses the
  allocation boundary), and once the poisoning was moved onto the network
  path (§4.26) it confirmed §4.2 as well (§4.27). Both of the read findings
  that §4.2/§4.3 could only call "reachable, not exploitable" are now
  demonstrated rather than argued.
* the methodology that produced them: patch each confirmed bug in the research
  build behind `MARIADB_PREAUTH_FUZZ_HOOK`, verify the PoC goes clean, and
  re-run the battery so a known bug cannot mask an unknown one. §4.25's fix is
  validated this way (all four branches clean at three lengths, §4.26) and so
  is §4.27's.

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
* **Can the memory after `net->buff` be groomed?** This is what separates
  §4.25 from a remote crash. The 8-byte slack is unreachable through the
  protocol, so it would have to be heap layout: a freed block of the same size
  class landing there with no zero byte in it. ASAN's quarantine and size
  classes make the instrumented build a poor place to test this; it wants a
  stock-allocator build.
* **Extend the tail poisoning to the network parse** (§4.24) — six unpoison
  sites: the two nested `my_net_read()` calls and the four write sites in
  `sql_acl.cc`, since `net->buff` is shared between both directions. The hook
  path has the volume but parses from mutated state (§4.21); the network path
  is the faithful one.
* **Out-of-bounds reads as a class**, enumerated mechanically over the measured
  set the way writes and indirect calls were. §4.24/§4.25 attacked them with
  instrumentation rather than enumeration, which found a bug but does not
  bound the class.
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
* `poc_slack_scan.py` — §4.24: asks whether the tail of `net->buff` that the
  §4.3 scan walks can be attacker-filled, using the second packet read inside
  the `CLIENT_SSL` branch, and in its second phase using one connection's freed
  buffer as the next connection's tail.
* `poc_lenenc_bound.py` — §4.25: the length-encoded branch, where the bound
  handed to `safe_net_field_length_ll()` goes negative and converts to
  `SIZE_MAX`.
* `poc_passwd_past_end.py` — §4.25: all four branches of the one root cause,
  against a packet sized so the slack past `buff_end` is at its 8-byte minimum.
  Run the server with `ASAN_OPTIONS=malloc_fill_byte=254:max_malloc_fill_size=65536`
  to make the heap adversarial.
* `narrow.py` — §4.31: sweeps the pre-auth sources for the bug class §4.25
  belongs to — differences passed as unsigned arguments, and narrowing casts on
  length expressions.
  `python3 -I narrow.py <source-root> sql/sql_acl.cc sql/net_serv.cc ...`
* `reach.py` — §4.30: static pre-auth reachability out of the binary. Builds
  the direct-call graph with `objdump`, takes the closure from 18 pre-auth entry
  points, cuts it at the post-auth boundary, and reports what the coverage
  differential measured, what it dropped, and what is reachable but was never
  executed. This is what bounds how much §4.17 and §4.22 depend on my corpus.
  `python3 -I reach.py <build>/sql/mariadbd cov-preauth-only.txt <out-prefix>`
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
