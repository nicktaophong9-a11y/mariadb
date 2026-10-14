# Upstream reports

Five reports drawn from the pre-auth audit in `../NOTES.md`. Each is
self-contained: impact, reproduction, root cause and a proposed patch.

**Every patch here was applied to a research build and tested.** What each
test showed:

* **Report 1** — all four branches of finding A/B go silent at packet lengths
  511, 512 and 16384, and `poc_post_tls_short_packet.py` goes clean.
* **Report 2** — the raced write moves from `ctype-simple.c:1458` (publishing an
  empty table) to `:1474` (publishing a complete one), so a reader can no longer
  observe a partially built array. ThreadSanitizer still reports the pair,
  because the patch closes the *window* without adding synchronisation; that is
  what the second half of the patch, the release/acquire on `MY_CS_READY`, is
  for. Both halves are in the report and only the first was exercised.
* **Report 3** — the auth decision still behaves: correct password granted,
  wrong password refused, empty password refused, unknown user refused, unknown
  user with an empty password refused (the `make_it_fail` path the patch
  touches), and `mariadb.sys` still refused by the `account_locked` check.
* **Report 4** — the workaround is what made the TSAN server start at all.
* **Report 5** — no behaviour change observed.

With all of them in, 15,000 randomised pre-auth cases, the four targeted PoC
groups, the post-TLS shapes and the collation race run clean with no sanitizer
report and the server alive.

| # | report | class | where to send |
|---|---|---|---|
| 1 | [`01-preauth-oob-reads-handshake.md`](01-preauth-oob-reads-handshake.md) | pre-auth out-of-bounds reads, 5 sites, one root cause | `security@mariadb.org` |
| 2 | [`02-charset-table-published-before-fill.md`](02-charset-table-published-before-fill.md) | pre-auth race; wild read on weakly-ordered architectures | `security@mariadb.org` |
| 3 | [`03-auth-decision-fail-open.md`](03-auth-decision-fail-open.md) | two fail-open patterns in the auth decision | `security@mariadb.org` |
| 4 | [`04-tsan-build-ifunc-resolver.md`](04-tsan-build-ifunc-resolver.md) | `-DWITH_TSAN=ON` produces an unusable binary | jira.mariadb.org (MDEV) |
| 5 | [`05-hardening-asserts-and-strxmov.md`](05-hardening-asserts-and-strxmov.md) | bounds that exist only as `DBUG_ASSERT`; one unbounded `strxmov` | jira.mariadb.org (MDEV) |

Reports 1–3 go to the private address because they concern the
pre-authentication path and the authentication decision, which is what
MariaDB's security policy asks for; reports 4 and 5 are a build defect and
hardening, so they are ordinary MDEVs. 3 is not exploitable on any shipped
configuration we could find, but it is in the auth decision, so it is routed
privately rather than argued about in public.

## Sending them

[`submission.md`](submission.md) has the wrapper each channel wants: the cover
email for the private disclosure of reports 1–3, and JIRA-ready summary,
affects and description for reports 4 and 5.

## Affected versions

Every finding was verified present in **11.8.4, 12.0.2, 13.0.2 and current
trunk** (`main` at `Merge 13.1 to main`, 2026-10-13) by extracting the affected
functions from each revision and comparing them. The 13.x refactor that renamed
`len` to `passwd_len` in `parse_client_handshake_packet()` did not change the
behaviour. The code is MySQL-derived and probably older than 11.8; we did not
try to find the first affected release.

## How these were found

Against the official `mariadb:latest` image
(`sha256:91c5269137b38b70bfe2d265ad010359a9aa33dacf2af5e1fa46c5ea16a8eb65`,
13.0.2) and a matching ASAN build, in the course of looking for an
unauthenticated RCE for ZeroDay Cloud 2026. **No RCE was found** — see
`../NOTES.md` §6 for what was ruled out and how. These are what the audit did
turn up.

The over-reads in report 1 are invisible to ASAN on their own, because they
leave the packet but stay inside the 16 KB `net->buff` allocation. They were
found by poisoning the unused tail of that buffer for the duration of each
parse (`../NOTES.md` §4.24, §4.26); the same instrumentation is what makes them
reproducible. Report 2 came from a ThreadSanitizer build, which needs the fix
in report 4 before it will start at all.

## The research build

[`research-build.patch`](research-build.patch) is everything this audit changed
in the source tree, against the `mariadb-13.0.2` tag, with a header separating
the three kinds of change: instrumentation that must never ship, the proposed
fixes one per report, and the one build workaround. Apply with `patch -p1`,
revert with `patch -R -p1`.

It matters for reproduction because the fixes are now *in* that tree. Report 1's
are gated behind `MARIADB_PREAUTH_STOCK=1`, so one binary reproduces both
states; reports 2, 3 and 5's are not gated, so reproducing those findings means
reverting their hunks.

## Reproduction harness

`../mariadb_preauth.py` speaks the handshake at byte level; the `poc_*.py`
scripts each target one finding and are named in the report that uses them.
Nothing in the harness changes server configuration.
