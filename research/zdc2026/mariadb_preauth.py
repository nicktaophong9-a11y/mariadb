#!/usr/bin/env python3
"""
MariaDB pre-authentication protocol harness (ZeroDay Cloud 2026 research).

Speaks the MariaDB/MySQL client protocol at the byte level so that every field
an *unauthenticated* client can influence on port 3306 is directly controllable:

  - client capability flags (incl. the MariaDB extended caps at offset 28)
  - declared max packet size, client charset/collation id
  - username, auth-response (3 length encodings), database, auth plugin name
  - connection-attributes blob (raw, so malformed length-encodings are possible)
  - raw packet truncation (the pkt_len == 31/32/33 edge cases)
  - multi-packet (0xffffff continuation) bodies
  - the auth-switch round trip, incl. a large (>net_buffer_length) second
    packet which forces net_realloc() on the server while it is still pre-auth

Nothing here changes server configuration; it only sends bytes to 3306.
"""

import socket
import struct
import sys

# ---------------------------------------------------------------- capabilities
CLIENT_LONG_PASSWORD      = 1 << 0
CLIENT_FOUND_ROWS         = 1 << 1
CLIENT_LONG_FLAG          = 1 << 2
CLIENT_CONNECT_WITH_DB    = 1 << 3
CLIENT_NO_SCHEMA          = 1 << 4
CLIENT_COMPRESS           = 1 << 5
CLIENT_LOCAL_FILES        = 1 << 7
CLIENT_IGNORE_SPACE       = 1 << 8
CLIENT_PROTOCOL_41        = 1 << 9
CLIENT_INTERACTIVE        = 1 << 10
CLIENT_SSL                = 1 << 11
CLIENT_TRANSACTIONS       = 1 << 13
CLIENT_SECURE_CONNECTION  = 1 << 15
CLIENT_MULTI_STATEMENTS   = 1 << 16
CLIENT_MULTI_RESULTS      = 1 << 17
CLIENT_PS_MULTI_RESULTS   = 1 << 18
CLIENT_PLUGIN_AUTH        = 1 << 19
CLIENT_CONNECT_ATTRS      = 1 << 20
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   = 1 << 22
CLIENT_SESSION_TRACK      = 1 << 23
CLIENT_DEPRECATE_EOF      = 1 << 24
CLIENT_MYSQL              = 1 << 0   # in the *lower* word: MariaDB clears it

BASE_CAPS = (CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_PROTOCOL_41 |
             CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION)


def lenenc_int(n, force=None):
    """Length-encoded integer. `force` pins the encoding width (1/3/4/9)."""
    if force == 1:
        return bytes([n & 0xff])
    if force == 3:
        return b"\xfc" + struct.pack("<H", n & 0xffff)
    if force == 4:
        return b"\xfd" + struct.pack("<I", n & 0xffffffff)[:3]
    if force == 9:
        return b"\xfe" + struct.pack("<Q", n & 0xffffffffffffffff)
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfc" + struct.pack("<H", n)
    if n < 1 << 24:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


class Conn:
    """A raw MariaDB protocol connection with explicit packet-sequence control."""

    def __init__(self, host="127.0.0.1", port=3306, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.seq = 0
        self.greeting = None

    # -- framing ---------------------------------------------------------
    def send_packet(self, payload, seq=None, split_at=None):
        """Write one logical packet.

        split_at: emit the body as a multi-packet sequence of `split_at`-sized
        chunks (only 0xffffff is a true continuation marker server side, but
        smaller chunks exercise the same net_read loop).
        """
        if seq is None:
            seq = self.seq
        if split_at is None:
            hdr = struct.pack("<I", len(payload))[:3] + bytes([seq & 0xff])
            self.sock.sendall(hdr + payload)
            self.seq = (seq + 1) & 0xff
            return
        off = 0
        while True:
            chunk = payload[off:off + split_at]
            hdr = struct.pack("<I", len(chunk))[:3] + bytes([seq & 0xff])
            self.sock.sendall(hdr + chunk)
            seq = (seq + 1) & 0xff
            off += len(chunk)
            if len(chunk) < split_at:
                break
        self.seq = seq & 0xff

    def send_raw(self, data):
        self.sock.sendall(data)

    def start_tls(self, caps=None):
        """Send a 32-byte SSLRequest and upgrade the socket to TLS.

        The SSLRequest packet is just the fixed 32-byte prefix of a handshake
        response; the real response is then sent inside the TLS session, which
        is the packet parse_client_handshake_packet() re-reads after
        sslaccept().
        """
        import ssl
        if caps is None:
            caps = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
                    CLIENT_SECURE_CONNECTION | CLIENT_SSL)
        req = (struct.pack("<I", caps & 0xffffffff) +
               struct.pack("<I", 0x01000000) + bytes([45]) +
               b"\x00" * 19 + struct.pack("<I", 0))
        assert len(req) == 32
        self.send_packet(req)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        self.sock = ctx.wrap_socket(self.sock, do_handshake_on_connect=True)
        return caps

    def read_packet(self):
        hdr = self._recv_exact(4)
        if hdr is None:
            return None
        plen = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
        self.seq = (hdr[3] + 1) & 0xff
        body = self._recv_exact(plen) if plen else b""
        return body

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    # -- handshake -------------------------------------------------------
    def read_greeting(self):
        body = self.read_packet()
        if not body or body[0] == 0xff:
            self.greeting = None
            return None
        i = 1
        end = body.index(b"\x00", i)
        server_version = body[i:end].decode("latin1")
        i = end + 1
        thread_id = struct.unpack("<I", body[i:i + 4])[0]
        i += 4
        scramble1 = body[i:i + 8]
        i += 8 + 1
        cap_low = struct.unpack("<H", body[i:i + 2])[0]
        i += 2
        charset = body[i]
        i += 1
        status = struct.unpack("<H", body[i:i + 2])[0]
        i += 2
        cap_high = struct.unpack("<H", body[i:i + 2])[0]
        i += 2
        scramble_len = body[i]
        i += 1
        i += 6
        cap_ext = struct.unpack("<I", body[i:i + 4])[0]
        i += 4
        rest = body[i:]
        n2 = max(0, scramble_len - 9)
        scramble2 = rest[:n2]
        plugin = rest[n2 + 1:].split(b"\x00")[0].decode("latin1")
        self.greeting = {
            "server_version": server_version,
            "thread_id": thread_id,
            "scramble": scramble1 + scramble2,
            "capabilities": cap_low | (cap_high << 16),
            "ext_capabilities": cap_ext,
            "charset": charset,
            "status": status,
            "auth_plugin": plugin,
        }
        return self.greeting

    # -- the packet under test -------------------------------------------
    def build_handshake_response(self, caps=BASE_CAPS, ext_caps=0,
                                 max_packet=0x01000000, charset=45,
                                 user=b"demo", auth_data=b"",
                                 auth_len_encoding=None, db=None,
                                 plugin=None, attrs=None,
                                 reserved=None, truncate=None,
                                 raw_tail=None):
        """Assemble a HandshakeResponse41 with every field independently set."""
        pkt = struct.pack("<I", caps & 0xffffffff)
        pkt += struct.pack("<I", max_packet)
        pkt += bytes([charset & 0xff])
        if reserved is None:
            # 19 filler bytes + 4 bytes MariaDB extended capabilities
            reserved = b"\x00" * 19
        pkt += reserved
        pkt += struct.pack("<I", ext_caps & 0xffffffff)
        # offset 32 from here on
        pkt += user + b"\x00"
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            pkt += lenenc_int(len(auth_data), force=auth_len_encoding) + auth_data
        elif caps & CLIENT_SECURE_CONNECTION:
            pkt += bytes([len(auth_data) & 0xff]) + auth_data
        else:
            pkt += auth_data + b"\x00"
        if caps & CLIENT_CONNECT_WITH_DB:
            pkt += (db if db is not None else b"demo") + b"\x00"
        if caps & CLIENT_PLUGIN_AUTH:
            pkt += (plugin if plugin is not None else b"mysql_native_password") + b"\x00"
        if caps & CLIENT_CONNECT_ATTRS:
            pkt += attrs if attrs is not None else lenenc_int(0)
        if raw_tail:
            pkt += raw_tail
        if truncate is not None:
            pkt = pkt[:truncate]
        return pkt

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def server_alive(host="127.0.0.1", port=3306, timeout=5.0):
    """True if the server still answers with a greeting (crash detector)."""
    try:
        c = Conn(host, port, timeout)
    except OSError:
        return False
    try:
        return c.read_greeting() is not None
    finally:
        c.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3306
    c = Conn(host, port)
    g = c.read_greeting()
    if not g:
        print("no greeting")
        sys.exit(1)
    print(f"server      : {g['server_version']}")
    print(f"thread id   : {g['thread_id']}")
    print(f"auth plugin : {g['auth_plugin']}")
    print(f"charset id  : {g['charset']}")
    print(f"caps        : 0x{g['capabilities']:08x}  ext 0x{g['ext_capabilities']:08x}")
    print(f"CLIENT_SSL advertised: {bool(g['capabilities'] & CLIENT_SSL)}")
    c.close()
