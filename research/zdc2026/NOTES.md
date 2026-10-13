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
  pre-truncated by `convert_error_message()` into a 512-byte buffer, and the
  error templates bound their arguments with precision specifiers
  (`ER_ACCESS_DENIED_ERROR` is `'%-.48s'@'%-.64s'`).
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

## 6. Status

**No unauthenticated RCE found. No write primitive reachable pre-auth, and no
authentication bypass.** Specifically:

* every out-of-bounds access found (§4.2, §4.3) is a *read* that provably stays
  inside the `net->buff` allocation on this target;
* the three write-shaped bugs found all need something an unauthenticated client
  cannot cause on this target — a concurrent `ALTER USER` (§4.8), an account with
  more than one authentication method (§4.5), or an IPv6-capable host and a
  link-local peer (§4.11);
* the authentication decision logic (§4.7) is sound, with one latent gap that no
  loaded plugin can reach.

Done:
* target pinned, configuration and account set read out of the running image ✔
* pre-auth surface enumerated with the non-reachable parts positively excluded ✔
* source audit of every reachable path (§4): the framing layer, the handshake
  parser, the TLS glue, the auth decision logic, the connection setup
  (`check_connection`/`thd_set_peer_addr`/`vio_peer_addr`), the ACL lookup and
  host matching, the error-formatting path (`err_conv`, `net_send_error_packet`)
  and the host-error accounting ✔
* ASAN build of 13.0.2 and targeted PoCs for §4.2 and §4.3 ✔
* 46,500 randomised pre-auth cases against the ASAN build ✔ — capability-flag
  combinations, charset ids, username/database/plugin-name shapes, all three
  auth-response length encodings, malformed connection-attribute blobs,
  truncation at the 31/32 boundary, multi-packet bodies, auth-switch replies
  above `net_buffer_length`, TLS-upgraded connections, desynchronised sequence
  numbers and PROXY-protocol signatures. No sanitizer report, no crash.

Remaining ideas, in order of expected value:
* **In-process fuzzing.** Network fuzzing caps out around 50 cases/second, which
  is far too slow for this parser. The leverage is a harness that drives
  `parse_client_handshake_packet()` directly — there is no in-tree libFuzzer
  target for the protocol, so it means constructing a THD and ACL state outside
  `mysqld`, or adding a debug-only entry point to the ASAN build (acceptable for
  discovery; any finding must then reproduce on the stock binary).
* **Concurrency.** Everything so far was single-connection. The pre-auth path
  touches shared state — `acl_cache->lock`, the host-error counters, the
  password-error counters in §4.7 — and §4.8 is an index/lifetime bug that only
  shows up under concurrent ACL change. Worth driving many simultaneous
  pre-auth connections under ASAN with thread sanitiser as a second build.
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
