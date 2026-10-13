# MariaDB — ZeroDay Cloud 2026 pre-auth RCE research notes

Everything below is derived from the organisers' official target definition and
from the source tree of the exact version that target runs. No server
configuration was changed or added.

## 1. The official target, pinned exactly

From `wiz-sec-public/zeroday-cloud-2026/mariadb`:

* `docker-compose.yaml` → `image: mariadb:latest`, `command: ["--local-infile=0"]`,
  `ports: 3306:3306`, env `MARIADB_ROOT_PASSWORD/DATABASE/USER/PASSWORD`.
* `README.md` → goal is **unauthenticated** RCE on 3306 then `/flag.sh mariadb`.
  Post-auth is explicitly ineligible; the `demo`/`root` credentials are for
  local health checks only and may not be used as a starting point.

Resolving the tag against the registry (`registry-1.docker.io`, manifest for
`mariadb:latest`):

| property | value |
|---|---|
| image version label | `13.0.2-resolute` |
| amd64 manifest digest | `sha256:91c5269137b38b70bfe2d265ad010359a9aa33dacf2af5e1fa46c5ea16a8eb65` |
| base image | `ubuntu:resolute` |
| built | 2026-10-02 |
| built from | `MariaDB/mariadb-docker` rev `7359e74de2aa6ef63dd3b8545db5c7e177e72618`, dir `13.0` |
| server package | `mariadb-server-galera=1:13.0.2+maria~ubu2604` from `archive.mariadb.org/mariadb-13.0.2/repo/ubuntu resolute main` |

So the code under test is the **`mariadb-13.0.2` release tag** (`VERSION`:
13.0.2, `SERVER_MATURITY=stable`). Note `latest` is a moving tag — re-pin before
submitting.

### Configuration baked into the official image (from its Dockerfile)

These matter because they *remove* attack surface, and an entry must not
re-introduce it:

* `/etc/mysql/mariadb.conf.d/05-skipcache.cnf` contains
  `host-cache-size=0` and `skip-name-resolve`.
* `bind-address`, `log` and `user` lines in `/etc/mysql/*.cnf` are commented out
  (hence the server listens on all interfaces).
* No TLS certificate or key is configured.
* `--local-infile=0` is added by the compose file.

### Accounts that exist on the target

Created by the official entrypoint / `mysql_install_db`:

* `root@%` and `root@localhost` — `mysql_native_password`
* `demo@%` — `mysql_native_password`
* `mysql@localhost` — **`IDENTIFIED VIA unix_socket`**
* `healthcheck@localhost`, `healthcheck@127.0.0.1`, `healthcheck@::1` — native
* `mariadb.sys@localhost`

## 2. What is actually reachable before authentication

Verified against the 13.0.2 source. Reachable:

1. **Packet framing** — `sql/net_serv.cc`: `my_net_read()` → `my_real_read()`,
   multi-packet continuation, `net_realloc()`.
2. **Handshake response parsing** — `sql/sql_acl.cc:parse_client_handshake_packet()`
   (capability flags, declared max packet, charset id, user, auth response in
   three length encodings, database, auth plugin name).
3. **Connection attributes** — `read_client_connect_attrs()`.
4. **Client charset selection** — `thd_init_client_charset()`, then
   `copy_and_convert()` / `Well_formed_prefix()` over the attacker's username.
5. **ACL lookup** — `find_mpvio_user()` with an attacker-chosen username.
6. **`mysql_native_password` / `mysql_old_password`** server-side auth.
7. **TLS** — `sslaccept()` and the whole OpenSSL server handshake (see §4.4).
8. `has_proxy_protocol_header()` — a 4-byte `memcmp`, nothing more.

Ruled **out** in this configuration, with evidence:

| surface | why it is not reachable |
|---|---|
| reverse DNS / host cache (`sql/hostname.cc`) | image sets `skip-name-resolve` and `host-cache-size=0` |
| PROXY protocol parsing | `handle_proxy_header()` calls `is_proxy_protocol_allowed()` before `parse_proxy_protocol_header()`; needs `--proxy-protocol-networks`, which is unset |
| client compression / zlib | `net.compress=1` is set in `prepare_new_connection_state()`, which runs *after* `login_connection()` succeeds — post-auth only |
| perf-schema connect-attrs sink | `performance_schema` is `DEFAULT(FALSE)` (`sql/sys_vars.cc`), so `PSI_CALL_set_thread_connect_attrs()` is a no-op |
| UCS2 / UTF16 / UTF32 conversion bugs | `is_supported_parser_charset()` rejects them during `thd_init_client_charset()` |
| attacker-chosen server auth plugin | `do_auth_once()` only ever uses `default_auth_plugin_name` or `acl_user->auth[i].plugin`; the client-supplied plugin name is never used to load a plugin |
| `LOCAL INFILE` | disabled by the compose command |
| `COM_*` commands, `COM_CHANGE_USER` | require an authenticated session |
| `decrement_connection_count()` (new in 13.0) | guarded by `!thd->userstat_running && !opt_userstat_running`; `userstat` is off by default |

## 3. Reachability amplifier: `find_mpvio_user()` picks a real account for unknown users

`sql/sql_acl.cc:14094`:

```c
  if (!mpvio->acl_user)
  {
    /* A matching user was not found. Fake it. Take any user, make the
       authentication fail later. ... */
    my_hasher_st hasher= my_hasher_mysql5x();
    CHARSET_INFO *cs= &my_charset_latin1;
    cs->hash_sort(&hasher, (uchar*) sctx->user, strlen(sctx->user));
    ...
    uint i= hasher.m_nr1 % acl_users.elements;
    ACL_USER *acl_user_tmp= dynamic_element(&acl_users, i, ACL_USER*);
    mpvio->acl_user= acl_user_tmp->copy(mpvio->auth_info.thd->mem_root);
    mpvio->make_it_fail= true;
  }
```

This exists to make failures for non-existent users look like failures for real
ones. The side effect is that **an unauthenticated client, purely by choosing
the username string, selects which ACL row drives the rest of the handshake** —
and the host part is not consulted on this path. So accounts that could never
be matched from a remote address, such as `mysql@localhost` with
`IDENTIFIED VIA unix_socket`, can still be made to drive the state machine.

Consequences:
* the plugin-switch / `MPVIO_EXT::RESTART` path becomes pre-auth reachable;
* the server-side code of any auth plugin used by *any* account becomes
  pre-auth reachable (here: `unix_socket` in addition to the two native ones);
* the username is a cheap, fully controlled selector — useful both as a fuzzing
  dimension and for steering an exploit at a specific account.

## 4. Memory-safety observations (source-level; empirical confirmation pending)

### 4.1 Post-TLS re-read skips the 32-byte minimum

In `parse_client_handshake_packet()` the pre-TLS packet is checked with
`if (pkt_len < 32) return packet_error;`, but after `sslaccept()` the
replacement packet is only checked against `NORMAL_HANDSHAKE_SIZE`, which is
**6**:

```c
    pkt_len= my_net_read(net);
    if (unlikely(pkt_len == packet_error || pkt_len < NORMAL_HANDSHAKE_SIZE))
      return packet_error;
```

The `CLIENT_PROTOCOL_41` layout that follows is selected from the *first*
packet's capability word and then unconditionally reads `read_pos[4..7]` and
`read_pos[8]` and sets `end = read_pos + 32`. The only guard is

```c
  if (end >= (char*) net->read_pos + pkt_len + 2)
    return packet_error;
```

which passes whenever `pkt_len >= 31`. At `pkt_len == 31` or `32`, `user = end`
is at or past the network layer's guaranteed NUL at `read_pos[pkt_len]`, so
`strend(user)` and then `*passwd` read beyond the packet body.

### 4.2 Negative remaining-length passed as `size_t`

On the `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` branch:

```c
    ulonglong len= safe_net_field_length_ll((uchar**)&passwd,
                                  net->read_pos + pkt_len - (uchar*)passwd);
```

When `passwd` has already passed `read_pos + pkt_len` (see 4.1) this argument is
negative and is passed as `size_t`, i.e. ≈2^64, which defeats the helper's own
bound check and lets it consume up to 9 bytes past the packet.

### 4.3 Unbounded `strlen` one byte past the terminator

```c
  char *next_field= passwd + passwd_len + (db ? db_len + 1 : 0);
  Lex_ident_plugin client_plugin= Lex_cstring_strlen(next_field);
```

`db_len = safe_strlen(db)` stops at the guaranteed NUL, so `next_field` can be
`read_pos + pkt_len + 1` — one past the terminator — and the `strlen` from there
is unbounded. The guard `client_plugin.str < read_pos + pkt_len` is applied
*after* the `strlen` has already run.

**Assessment of 4.1–4.3.** These are out-of-bounds *reads*. They land inside the
`net->buff` allocation unless `pkt_len` is within ~8 bytes of `net->max_packet`
(`net_allocate_new_packet()`/`net_realloc()` over-allocate by
`NET_HEADER_SIZE + COMP_HEADER_SIZE + 1` = 8). So on their own they are
crash / info-disclosure candidates, not a write primitive. Worth driving with
ASAN at buffer-boundary sizes.

### 4.4 TLS is active on the target even though no certificate is configured

`opt_use_ssl` defaults to `1` (`sql/mysqld.cc:1608` and the `"ssl"` option entry),
and when neither key nor cert is given `vio_set_cert_stuff()` **generates an
ephemeral key and self-signed certificate**:

```c
  if (!cert_file && !key_file)
  {
    if (!is_client)
    {
      EVP_PKEY *pkey;  X509 *x509;
      if (!(pkey= vio_keygen()) || SSL_CTX_use_PrivateKey(ctx, pkey) < 1) ...
      if (!(x509= vio_gencert(pkey)) || SSL_CTX_use_certificate(ctx, x509) < 1) ...
```

So `ssl_acceptor_fd != 0` on the official image: `CLIENT_SSL` is honoured, the
full OpenSSL server-side handshake is pre-auth surface, and the 4.1 path is
unlocked. The OpenSSL version shipped in `ubuntu:resolute` is therefore in
scope and should be pinned and checked against known issues.

### 4.5 `net->buff` can move pre-auth while cached pointers into it are live

`net_realloc()` uses `my_realloc`, so `net->buff` can change address, and
pre-auth `net->max_packet_size = MAX(net_buffer_length, max_allowed_packet)`
(16 MB) while `net->max_packet` starts at `net_buffer_length` (16 KB). An
unauthenticated client can therefore force a buffer move by sending a packet
larger than 16 KB.

`MPVIO_EXT::cached_client_reply.pkt` and `.plugin.str` are raw pointers into
`net->buff`. `server_mpvio_write_packet()` clears both on the normal
plugin-switch path, which is what makes the common case safe. Two gaps remain:

* the cached-hit branch of `server_mpvio_read_packet()` returns
  `*buf = cached_client_reply.pkt` and sets `status = FAILURE` but does **not**
  clear `.pkt`;
* `acl_authenticate()`'s retry loop re-arms `mpvio.status = MPVIO_EXT::RESTART`
  for each `acl_user->auth[]` entry without clearing the cache:

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

Reaching a stale dereference needs an account with `nauth >= 2` whose methods
share a `client_auth_plugin`, plus an extra `read_packet` round trip in which
the oversized packet is sent. **No default account in the official image has
`nauth >= 2`**, so today this is a latent pattern rather than a reachable bug.
Re-check if the account set ever changes.

## 5. Tooling in this directory

* `mariadb_preauth.py` — byte-level pre-auth protocol client. Exposes every
  field of the handshake response independently, supports raw truncation,
  multi-packet bodies, the three auth-response length encodings, raw
  connection-attribute blobs, and the auth-switch round trip.
* `preauth_fuzz.py` — randomised driver over that harness with a liveness-based
  crash detector. Aimed at the paths in §4, and uses the §3 username selector as
  an explicit fuzzing dimension.

Intended to be run against an ASAN build of `mariadb-13.0.2` so that any
out-of-bounds access aborts and is caught, with findings then reproduced
against the unmodified official image.

## 6. Status

* Official target pinned and its configuration read out of the image build. ✔
* Pre-auth surface enumerated, with the non-reachable parts positively excluded. ✔
* Source audit of the reachable paths: observations in §4; no write primitive
  identified yet.
* ASAN build of 13.0.2 and fuzzing: in progress.
* Pulling the official image for final validation is currently blocked by
  Docker Hub anonymous rate limiting (HTTP 429) from this egress IP.
