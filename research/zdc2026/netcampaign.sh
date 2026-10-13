#!/bin/bash
# Long network fuzz against the tail-poisoned build. Unlike the in-process
# campaign this parses from true fresh-connection state (NOTES 4.21), and
# unlike the earlier ~250k cases the slack past the packet is poisoned, so an
# over-read that stays inside net->buff is a report rather than silence.
# On a report the server is restarted and the run continues, so one finding
# does not stop the hunt; reports are kept for triage.
SP=/tmp/claude-0/-home-user-mariadb/94a096d0-b287-586b-9c9a-4bd5cfc1d7e2/scratchpad
D=/home/user/mariadb/research/zdc2026
ROUNDS=${1:-40}; ITERS=${2:-25000}
mkdir -p "$SP/net-findings"
cd "$D" || exit 1
for r in $(seq 1 "$ROUNDS"); do
  "$SP/startsrv.sh" "" "net" 0
  MP=$(cat "$SP/asan-data/m.pid" 2>/dev/null)
  if [ -z "$MP" ] || [ ! -d "/proc/$MP" ]; then echo "round $r: no server"; continue; fi
  SEED=$((5550000 + r)) timeout 3600 python3 -I preauth_fuzz.py 127.0.0.1 3307 "$ITERS" \
       > "$SP/net-drive-$r.log" 2>&1
  rc=$?
  n=0
  for f in "$SP"/net-asan*; do
    [ -e "$f" ] || continue
    n=$((n+1))
    sig=$(grep -m1 -E 'sql_acl\.cc:[0-9]+|net_serv\.cc:[0-9]+|ctype[^ ]*:[0-9]+' "$f" \
          | sed 's|.*/||' | cut -c1-40)
    cp "$f" "$SP/net-findings/r$r-$(basename "$f")"
    echo "round $r: REPORT  $sig"
  done
  echo "round $r rc=$rc iters=$ITERS reports=$n  $(tail -1 "$SP/net-drive-$r.log" | cut -c1-50)"
done
echo "=== distinct report signatures across the run ==="
grep -ho -E '(sql_acl|net_serv|ctype[a-z-]*|my_vsnprintf|sql_string)\.(cc|c|inl):[0-9]+' \
     "$SP"/net-findings/* 2>/dev/null | sort | uniq -c | sort -rn
