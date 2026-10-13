#!/bin/bash
# TSAN server. Address space is tight under TSAN's shadow mappings, so InnoDB's
# default 8 TB innodb_buffer_pool_size_max reservation has to be cut down; that
# is orthogonal to the pre-auth protocol path this build exists to test.
SP=/tmp/claude-0/-home-user-mariadb/94a096d0-b287-586b-9c9a-4bd5cfc1d7e2/scratchpad
[ -f "${SP:?}/asan-data/m.pid" ] && kill -9 "$(cat "${SP:?}/asan-data/m.pid")" 2>/dev/null
sleep 2
rm -f "${SP:?}/asan-data/m.sock" "${SP:?}/asan-data/m.pid"
MARIADB_FUZZ_HANDSHAKE=0 \
TSAN_OPTIONS="log_path=${SP:?}/tsan-race:history_size=7:halt_on_error=0:exitcode=0:report_signal_unsafe=0:report_thread_leaks=0:report_destroy_locked=0" \
setsid nohup "${SP:?}/build-tsan/sql/mariadbd" --no-defaults \
  --basedir="${SP:?}/build-tsan" --datadir="${SP:?}/asan-data" \
  --lc-messages-dir="${SP:?}/build-tsan/sql/share" --plugin-dir="${SP:?}/tsan-plugin" \
  --port=3307 --socket="${SP:?}/asan-data/m.sock" --pid-file="${SP:?}/asan-data/m.pid" \
  --skip-name-resolve --host-cache-size=0 --local-infile=0 \
  --innodb-buffer-pool-size=128M --innodb-buffer-pool-size-max=256M \
  --skip-grant-tables=0 --user=root --console > "${SP:?}/tsan-server.log" 2>&1 &
for i in $(seq 1 300); do python3 -I -c "
import socket,sys
s=socket.socket(); s.settimeout(2)
try: s.connect(('127.0.0.1',3307)); s.close()
except Exception: sys.exit(1)" 2>/dev/null && break; sleep 1; done
