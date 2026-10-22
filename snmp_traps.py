#!/usr/bin/env python3
"""PSCyber collector - SNMP trap receiver (1.3.1+). Started by the responder, beside snmp_poller.py.

Replaces snmptrapd: on Ubuntu 26.04 (net-snmp 5.9.4+dfsg-2ubuntu3) it accepts trap packets on UDP 162
and processes none of them - not even an INFORM is answered, with authorization switched off. Found
in the 1.3.0 live test; no trap had ever reached the log on that collector. So the collector
receives them itself:

  v1 / v2c traps      community checked against the credentials set in Agentic
  v2c INFORMs         checked, then answered (the device stops resending)
  v3 traps            user, authentication (MD5 / SHA-1 / SHA-2) and privacy (DES / AES-128 / AES-192 /
                      AES-256) checked against Agentic's v3 credentials. The keys are localised with the
                      SENDER's engine ID, which the trap carries - nothing per device to configure.

Each accepted trap is appended to /var/log/pscyber/snmptraps.log in the line format snmptrapd wrote
(the Wazuh agent reads that file, as before) and the responder forwards it to the platform.
Anything not accepted is dropped and only counted. Standard library; v3 privacy uses `cryptography`
(already on the box - paramiko needs it).
"""
import hashlib
import hmac
import os
import socket
import threading
import time
from datetime import datetime

TRAP_LOG = "/var/log/pscyber/snmptraps.log"
TRAPD_CONF = "/etc/snmp/snmptrapd.conf"     # the community chosen at install, used until Agentic manages traps
PORT = 162
MAX_PACKET = 65535
MAX_PER_SECOND = 200

# ------------------------------------------------------------------ BER, with absolute offsets


class BerError(ValueError):
    pass


def tlv(buf: bytes, i: int, end: int | None = None) -> tuple[int, int, int]:
    """(tag, value start, value end) of the TLV at offset i."""
    end = len(buf) if end is None else end
    if i + 2 > end:
        raise BerError("truncated")
    tag, n = buf[i], buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or i + k > end:
            raise BerError("bad length")
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + n > end:
        raise BerError("truncated value")
    return tag, i, i + n


def children(buf: bytes, start: int, end: int) -> list:
    out, i = [], start
    while i < end:
        t, s, e = tlv(buf, i, end)
        out.append((t, s, e))
        i = e
    return out


def as_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=True) if b else 0


def as_oid(b: bytes) -> str:
    if not b:
        return ""
    first = b[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return "." + ".".join(map(str, parts))


def enc(tag: int, payload: bytes) -> bytes:
    n = len(payload)
    if n < 0x80:
        return bytes([tag, n]) + payload
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + payload


def enc_int(v: int) -> bytes:
    return enc(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def render(tag: int, v: bytes) -> str:
    """A value the way net-snmp prints it with -On (what the platform and Wazuh already read)."""
    if tag == 0x02:
        return f"INTEGER: {as_int(v)}"
    if tag == 0x04:
        try:
            s = v.decode("utf-8")
            if s.isprintable():
                return f'STRING: "{s}"'
        except UnicodeDecodeError:
            pass
        return "Hex-STRING: " + " ".join(f"{x:02X}" for x in v)
    if tag == 0x05:
        return "NULL"
    if tag == 0x06:
        return f"OID: {as_oid(v)}"
    if tag == 0x40 and len(v) == 4:
        return "IpAddress: " + ".".join(map(str, v))
    names = {0x41: "Counter32", 0x42: "Gauge32", 0x46: "Counter64"}
    if tag in names:
        return f"{names[tag]}: {int.from_bytes(v, 'big')}"
    if tag == 0x43:
        return f"Timeticks: ({int.from_bytes(v, 'big')})"
    return {0x80: "No Such Object", 0x81: "No Such Instance", 0x82: "End of MIB View"}.get(tag, "Hex-STRING: " + v.hex(" ").upper())


def varbinds(buf: bytes, s: int, e: int) -> list:
    out = []
    for _, vs, ve in children(buf, s, e)[:200]:
        items = children(buf, vs, ve)
        if len(items) >= 2 and items[0][0] == 0x06:
            (ot, os_, oe), (vt, vs2, ve2) = items[0], items[1]
            out.append((as_oid(buf[os_:oe]), render(vt, buf[vs2:ve2])))
    return out


# ------------------------------------------------------------------ SNMPv3 (RFC 3414, 3826, 7860; AES-192/256 per Blumenthal)

AUTH = {"MD5": ("md5", 12), "SHA": ("sha1", 12), "SHA-224": ("sha224", 16), "SHA-256": ("sha256", 24),
        "SHA-384": ("sha384", 32), "SHA-512": ("sha512", 48)}
_ku: dict = {}


def password_to_key(password: str, hname: str) -> bytes:
    k = (password, hname)
    if k not in _ku:
        pw = password.encode()
        data = (pw * (1048576 // len(pw) + 1))[:1048576]
        _ku[k] = hashlib.new(hname, data).digest()
    return _ku[k]


def localize(password: str, hname: str, engine_id: bytes) -> bytes:
    ku = password_to_key(password, hname)
    return hashlib.new(hname, ku + engine_id + ku).digest()


def decrypt(priv_proto: str, key: bytes, boots: int, etime: int, salt: bytes, data: bytes, hname: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    if priv_proto == "DES":
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # older cryptography
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        des, pre_iv = key[:8], key[8:16]
        iv = bytes(a ^ b for a, b in zip(pre_iv, salt))
        d = Cipher(TripleDES(des * 3), modes.CBC(iv)).decryptor()
        return d.update(data[: len(data) - len(data) % 8]) + d.finalize()
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    try:                                       # cryptography 46+ moved CFB (gone from `modes` in 49)
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        CFB = modes.CFB
    size = {"AES": 16, "AES-192": 24, "AES-256": 32}.get(priv_proto, 16)
    k = key
    while len(k) < size:                       # Blumenthal key extension (net-snmp's AES-192/256)
        k += hashlib.new(hname, k).digest()
    iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + salt
    d = Cipher(AES(k[:size]), CFB(iv)).decryptor()
    return d.update(data) + d.finalize()


# ------------------------------------------------------------------ the receiver

class TrapReceiver:
    def __init__(self, log_path: str = TRAP_LOG):
        self.log_path = log_path
        self.lock = threading.Lock()
        self.communities: set = set()
        self.users: dict = {}              # user name -> [credential, ...]
        self.managed = False
        self.stats = {"accepted": 0, "dropped": 0, "bad_auth": 0, "malformed": 0}
        self._window, self._count = 0, 0
        self.host = socket.gethostname()
        self._install_communities()

    def _install_communities(self) -> None:
        """Until Agentic manages SNMP for this customer: the community typed at install."""
        try:
            for line in open(TRAPD_CONF):
                p = line.split()
                if len(p) >= 3 and p[0] == "authCommunity":
                    self.communities.add(p[-1])
        except OSError:
            pass

    def set_credentials(self, traps: list) -> None:
        comm, users = set(), {}
        for c in traps or []:
            if c.get("version") == "2c" and c.get("community"):
                comm.add(c["community"])
            elif c.get("version") == "3" and c.get("user"):
                users.setdefault(c["user"], []).append(c)
        with self.lock:
            self.communities, self.users, self.managed = comm, users, True

    # -------------------------------------------------- one datagram

    def handle(self, data: bytes, src: tuple, sock=None) -> str | None:
        """The log line for an accepted trap (None when dropped). Answers an INFORM on `sock`."""
        try:
            t, s, e = tlv(data, 0)
            if t != 0x30:
                raise BerError("not a sequence")
            top = children(data, s, e)
            version = as_int(data[top[0][1]:top[0][2]])
            if version in (0, 1):
                return self._community(data, top, version, src, sock)
            if version == 3:
                return self._v3(data, top, src)
            raise BerError("version")
        except (BerError, IndexError, ValueError):
            self.stats["malformed"] += 1
            return None

    def _community(self, data, top, version, src, sock):
        community = data[top[1][1]:top[1][2]].decode("latin-1")
        with self.lock:
            ok = community in self.communities
        if not ok:
            self.stats["bad_auth"] += 1
            return None
        pt, ps, pe = top[2]
        if version == 0 and pt == 0xA4:                       # SNMPv1 Trap-PDU -> v2 form (RFC 3584)
            f = children(data, ps, pe)
            enterprise = as_oid(data[f[0][1]:f[0][2]])
            agent = ".".join(map(str, data[f[1][1]:f[1][2]]))
            generic, specific = as_int(data[f[2][1]:f[2][2]]), as_int(data[f[3][1]:f[3][2]])
            ticks = int.from_bytes(data[f[4][1]:f[4][2]], "big")
            oid = f".1.3.6.1.6.3.1.1.5.{generic + 1}" if generic < 6 else f"{enterprise}.0.{specific}"
            vbs = [(".1.3.6.1.2.1.1.3.0", f"Timeticks: ({ticks})"), (".1.3.6.1.6.3.1.1.4.1.0", f"OID: {oid}"),
                   (".1.3.6.1.6.3.18.1.3.0", f"IpAddress: {agent}")] + varbinds(data, f[5][1], f[5][2])
            return self._line(src, vbs, "v1")
        if pt in (0xA7, 0xA6):                                  # v2c trap / inform
            f = children(data, ps, pe)
            vbs = varbinds(data, f[3][1], f[3][2])
            if pt == 0xA6 and sock is not None:                 # INFORM: answer with the same request-id
                rid = data[f[0][1]:f[0][2]]
                vbl = enc(0x30, data[f[3][1]:f[3][2]])          # the same variable bindings, sent back
                reply = enc(0x30, enc_int(1) + enc(0x04, community.encode("latin-1")) +
                            enc(0xA2, enc(0x02, rid) + enc_int(0) + enc_int(0) + vbl))
                try:
                    sock.sendto(reply, src)
                except OSError:
                    pass
            return self._line(src, vbs, "v2c inform" if pt == 0xA6 else "v2c")
        raise BerError("pdu")

    def _v3(self, data, top, src):
        g = children(data, top[1][1], top[1][2])
        flags = data[g[2][1]] if g[2][2] > g[2][1] else 0
        if as_int(data[g[3][1]:g[3][2]]) != 3:
            raise BerError("not USM")
        st, ss, se = tlv(data, top[2][1], top[2][2])           # msgSecurityParameters -> USM sequence
        u = children(data, ss, se)
        engine = data[u[0][1]:u[0][2]]
        boots, etime = as_int(data[u[1][1]:u[1][2]]), as_int(data[u[2][1]:u[2][2]])
        user = data[u[3][1]:u[3][2]].decode("utf-8", "replace")
        a_s, a_e = u[4][1], u[4][2]
        salt = data[u[5][1]:u[5][2]]
        with self.lock:
            cands = list(self.users.get(user, []))
        if not cands:
            self.stats["bad_auth"] += 1
            return None
        for c in cands:
            need_auth = c.get("level") in ("authNoPriv", "authPriv")
            need_priv = c.get("level") == "authPriv"
            if bool(flags & 1) != need_auth or bool(flags & 2) != need_priv:
                continue
            hname, maclen = AUTH.get(c.get("auth_proto", "SHA"), ("sha1", 12))
            if need_auth:
                key = localize(c.get("auth", ""), hname, engine)
                zeroed = data[:a_s] + b"\x00" * (a_e - a_s) + data[a_e:]
                mac = hmac.new(key, zeroed, hname).digest()[:maclen]
                if not hmac.compare_digest(mac, data[a_s:a_e]):
                    continue
            body_t, bs, be = top[3]
            if need_priv:
                if body_t != 0x04:
                    continue
                pkey = localize(c.get("priv", ""), hname, engine)
                try:
                    plain = decrypt(c.get("priv_proto", "AES"), pkey, boots, etime, salt, data[bs:be], hname)
                    pt, ps, pe = tlv(plain, 0)
                except (BerError, ImportError, ValueError):
                    continue
                scoped, base = plain, (ps, pe)
            else:
                scoped, base = data, (bs, be)
            sc = children(scoped, *base)
            pdu_t, pdu_s, pdu_e = sc[2]
            if pdu_t not in (0xA7, 0xA6):
                return None
            f = children(scoped, pdu_s, pdu_e)
            return self._line(src, varbinds(scoped, f[3][1], f[3][2]), f"v3 {user}")
        self.stats["bad_auth"] += 1
        return None

    # -------------------------------------------------- output

    def _line(self, src, vbs, how) -> str:
        body = "\t".join(f"{o} = {v}" for o, v in vbs)[:8000]
        return f"TRAP from <{src[0]}> [UDP: [{src[0]}]:{src[1]}->[0.0.0.0]:{PORT}] ({how}): {body}"

    def write(self, line: str) -> None:
        stamp = datetime.now().strftime("%b %d %H:%M:%S")
        with self.lock, open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"{stamp} {self.host} pscyber-trapd: {line}\n")
            f.flush()

    def _allowed(self) -> bool:
        now = int(time.monotonic())
        if now != self._window:
            self._window, self._count = now, 0
        self._count += 1
        return self._count <= MAX_PER_SECOND

    def serve(self, sock) -> None:
        while True:
            try:
                data, src = sock.recvfrom(MAX_PACKET)
            except OSError:
                time.sleep(1)
                continue
            if not self._allowed():
                self.stats["dropped"] += 1
                continue
            line = self.handle(data, src[:2], sock)
            if line:
                self.stats["accepted"] += 1
                try:
                    self.write(line)
                except OSError:
                    pass

    def start(self) -> None:
        threading.Thread(target=self._bind_loop, name="snmp-traps", daemon=True).start()

    def _bind_loop(self) -> None:
        """Bind UDP 162 (IPv4 and IPv6); while something else holds it (snmptrapd not yet stopped), retry."""
        bound = set()
        while len(bound) < 2:
            for fam, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
                if fam in bound:
                    continue
                try:
                    s = socket.socket(fam, socket.SOCK_DGRAM)
                    if fam == socket.AF_INET6:
                        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    s.bind((addr, PORT))
                except OSError:
                    continue
                bound.add(fam)
                threading.Thread(target=self.serve, args=(s,), name=f"snmp-traps-{fam}", daemon=True).start()
            if len(bound) < 2:
                if socket.AF_INET in bound and not socket.has_ipv6:
                    break
                time.sleep(30)
