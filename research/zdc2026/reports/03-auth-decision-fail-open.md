# Two fail-open patterns in the authentication decision

**Affected:** 11.8.4, 12.0.2, 13.0.2, current trunk (verified)
**Impact:** none that we could reach on any shipped configuration. Both are
defence-in-depth: the authentication decision treats "something unexpected
happened" as success. Sent privately because of where they are, not because we
have an exploit.

## Context

`acl_authenticate()` rejects a login at exactly one place:

```c
  if (res > CR_OK && mpvio.status != MPVIO_EXT::SUCCESS)
  { ... inc_host_errors(...); login_failed_error(thd); DBUG_RETURN(1); }
  sctx->proxy_user[0]= 0;                 /* reaching here grants the login */
```

With `CR_OK == -1`, that needs **both** conditions, so any path that leaves
`res <= CR_OK` grants the login. `mpvio.status` cannot be `SUCCESS` with grant
tables loaded — it is assigned in exactly two places, both inside
`if (!initialized)` — so in a normal server the decision reduces to
`res > CR_OK`. Both findings below are about `res`.

## Finding A — `do_auth_once()`'s `default:` leaves the success value standing

```c
static int do_auth_once(THD *thd, const LEX_CSTRING *auth_plugin_name,
                        MPVIO_EXT *mpvio)
{
  int res= CR_OK;
  ...
  if (plugin)
  {
    st_mysql_auth *info= (st_mysql_auth *) plugin_decl(plugin)->info;
    switch (info->interface_version >> 8) {
    case 0x02:
      res= info->authenticate_user(mpvio, &mpvio->auth_info);
      break;
    case 0x01:
      { ... res= info->authenticate_user(mpvio, (MYSQL_SERVER_AUTH_INFO *)&compat); ... }
      break;
    default: DBUG_ASSERT(0);
    }
```

`res` is initialised to `CR_OK`, and `DBUG_ASSERT(0)` compiles to nothing in a
release build. So a plugin whose `interface_version >> 8` is neither 1 nor 2
**grants the login without `authenticate_user()` ever being called**.

Not reachable with anything shipped: every server auth plugin in the tree
declares `MYSQL_AUTHENTICATION_INTERFACE_VERSION`, which is `0x0203`, so
`>> 8 == 2`. It would take a third-party or future plugin with an unexpected
version, which is exactly the case the `default:` exists for.

Suggested fix — make the unexpected case fail:

```diff
-    default: DBUG_ASSERT(0);
+    default:
+      DBUG_ASSERT(0);
+      res= CR_ERROR;
+      break;
     }
```

## Finding B — the unknown-user guard compares one value where it means "any success"

For an unknown user, `find_mpvio_user()` fabricates an ACL row and sets
`make_it_fail`, so the handshake proceeds normally and the failure is applied at
the end:

```c
  if (mpvio.make_it_fail && res == CR_OK)
  {
    mpvio.status= MPVIO_EXT::FAILURE;
    res= CR_ERROR;
  }
```

The comparison is exact. `CR_OK_HANDSHAKE_COMPLETE` is `-2`, so it does not
match, and `-2 > CR_OK` is false — meaning a plugin returning `-2` would grant
the login **to a user that does not exist**, with the guard that exists
specifically to prevent that sitting right above it.

Not reachable today, and the reason is documented rather than enforced:
`include/mysql/plugin_auth_common.h` says of `CR_OK_HANDSHAKE_COMPLETE`

> Server plugins should not return this value.

and every `return CR_OK_HANDSHAKE_COMPLETE` in the tree is client-side
(`libmariadb/plugins/auth/*`, `sql-common/client.c`, the client halves of
dialog/gssapi/sspi, and `plugin/auth_examples/*`, which release builds do not
ship).

Suggested fix — say "any success", not "this success":

```diff
-  if (mpvio.make_it_fail && res == CR_OK)
+  if (mpvio.make_it_fail && res <= CR_OK)
```

and, since the contract is only a comment, consider rejecting `-2` from a
server plugin where it arrives:

```diff
     case 0x02:
       res= info->authenticate_user(mpvio, &mpvio->auth_info);
+      DBUG_ASSERT(res != CR_OK_HANDSHAKE_COMPLETE);
+      if (res == CR_OK_HANDSHAKE_COMPLETE)
+        res= CR_ERROR;                 /* server plugins must not return this */
       break;
```

## Regression test

Both patches change the authentication decision, so the matrix that matters is
whether it still decides correctly. With 3A and 3B applied:

| attempt | result |
|---|---|
| `root` + correct password | granted as `root@localhost` |
| `root` + wrong password | refused, `ER_ACCESS_DENIED_ERROR` |
| `root` + empty password | refused |
| unknown user + password | refused |
| unknown user + **empty** password | refused — this is the `make_it_fail` path 3B touches |
| `mariadb.sys` + empty password | refused, "this account is locked" |

and 15,000 randomised pre-auth cases plus the targeted PoC groups run clean
afterwards.

## Why both are worth changing anyway

The decision site needs `res` to mean "the plugin said yes". Both findings are
places where `res` can mean "we never asked" or "a value the server side is not
supposed to produce" and the site reads it as yes. Neither is reachable now;
both are one third-party plugin away, and the cost of fixing them is three
lines.

For completeness, the rest of the decision logic checked out: the plugin is
always chosen server-side (`default_auth_plugin_name` or
`acl_user->auth[curr_auth].plugin`, never the client's name, and
`get_auth_plugin()` enforces the type through
`my_plugin_lock_by_name(..., MYSQL_AUTHENTICATION_PLUGIN)`), and
`native_password_authenticate()` returns `CR_OK` outside the crypto check only
when the account has an empty `auth_string` and the client sent no password.
