"""
Enigma Relay - a post box on the internet.

This is the only part that lives anywhere other than your own
machines, and it is deliberately the dumbest part. It takes locked
messages, holds them briefly, and hands them back. That is all it
does and all it can do.

It cannot read anything. It is never told a frequency or a code
word, and it has no way to work either out from what it holds. What
it stores is exactly what somebody tapping the wire would get, which
is why it does not matter very much who runs it.

It refuses outright to carry anything that is not already locked, so
a mistake in the app cannot turn into a leak here.

Runs on anything with Python 3 and nothing else - no packages, no
database. Free tiers at Render, Railway, Fly and similar will all
take it as it stands.

    python3 relay.py                 (port 8080, or $PORT)
"""

import http.server
import json
import os
import socketserver
import sys
import time

PORT = int(os.environ.get("PORT", "8080"))

# How much to hold, and for how long. A post box, not an archive:
# whatever nobody has collected within the hour is forgotten, because
# the relay keeping a record of a conversation is the thing the whole
# arrangement exists to avoid.
# Capped by size, not by count. Two thousand typed messages is half
# a megabyte; two thousand full-size photos is two hundred and fifty,
# which is most of a free tier's memory for something that is meant
# to be a post box. Counting bytes is the only cap that means the
# same thing for both.
KEEP_BYTES = 40 * 1024 * 1024
KEEP_MOST = 4000
KEEP_FOR = 60 * 60

SAID = []
NEXT = [1]

# How long a waiting request is held before being answered empty.
# Long enough to be worth it, short enough that nothing in between
# decides the connection is dead.
WAIT_UP_TO = 25.0

# Which relay this is.
#
# There was no way to tell a freshly deployed relay from the one it
# replaced: /alive said the same words either way, so "did my deploy
# actually take?" had no answer short of guessing. The app shows this
# when you press Test.
RELAY_VERSION = "3.0"

# The most one message may weigh on the wire. Generous for typed
# words, and about a photo's worth.
TOO_LONG = 1200000

def held_bytes():
    return sum(len(r["body"]) for r in SAID)


def tidy():
    now = time.time()
    while SAID and (now - SAID[0]["at"] > KEEP_FOR
                    or len(SAID) > KEEP_MOST
                    or held_bytes() > KEEP_BYTES):
        SAID.pop(0)


# ===========================================================================
# ROOMS  (shared, word for word, by relay.py and server.py)
# ===========================================================================
#
# A room is a conversation only certain people can reach. The relay
# keeps NO list of rooms and NO list of members. That is deliberate:
# a free host restarts whenever it likes and forgets everything in
# memory, and a relay that had to remember who belongs to which room
# would lock everybody out after every restart.
#
# Instead every request proves itself. A room's code is made from its
# owner's public key, so the code itself says whose room it is. To get
# in, a device shows a short chain of signatures leading back to that
# owner, and signs a fresh challenge from this relay. Everything needed
# to check that travels with the request, so nothing needs remembering.
#
# The relay still cannot read anything. Signatures prove membership;
# the words are locked with secrets the relay never sees.

import base64 as _b64
import hashlib as _hashlib
import hmac as _hmac
import json as _json
import secrets as _secrets
import threading as _threading
import time as _time

_LOCK = _threading.Lock()

# --- P-256 signature checking, in plain Python --------------------------------
#
# The relay must run with nothing installed, and Python has no
# elliptic curves of its own, so the arithmetic is here. It only ever
# CHECKS signatures; it never makes one and never holds a private key,
# so there is no secret here to leak through timing.

_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_A = _P - 3
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _on_curve(pt):
    x, y = pt
    return 0 <= x < _P and 0 <= y < _P and (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _two_mul(u1, p1, u2, p2):
    # u1*p1 + u2*p2 in one pass (Shamir's trick).
    both = _add(p1, p2)
    out = None
    for i in range(max(u1.bit_length(), u2.bit_length()) - 1, -1, -1):
        out = _add(out, out)
        b1, b2 = (u1 >> i) & 1, (u2 >> i) & 1
        if b1 and b2:
            out = _add(out, both)
        elif b1:
            out = _add(out, p1)
        elif b2:
            out = _add(out, p2)
    return out


def p256_verify(pub_raw, sig, msg):
    """pub_raw: 65 bytes 04|X|Y. sig: 64 bytes r|s. msg: bytes. SHA-256."""
    try:
        if len(pub_raw) != 65 or pub_raw[0] != 4 or len(sig) != 64:
            return False
        q = (int.from_bytes(pub_raw[1:33], "big"),
             int.from_bytes(pub_raw[33:], "big"))
        if not _on_curve(q):
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if not (1 <= r < _N and 1 <= s < _N):
            return False
        e = int.from_bytes(_hashlib.sha256(msg).digest(), "big")
        w = pow(s, -1, _N)
        pt = _two_mul(e * w % _N, _G, r * w % _N, q)
        return pt is not None and pt[0] % _N == r
    except Exception:
        return False


# --- room codes and chains ------------------------------------------------

ROOM_ALPHA = "abcdefghijkmnpqrstuvwxyz23456789"   # no l, o, 0, 1


def room_code(opk_raw):
    """Sixteen characters from the owner's public key: 80 bits."""
    bits = int.from_bytes(_hashlib.sha256(opk_raw).digest()[:10], "big")
    out = ""
    for _ in range(16):
        out = ROOM_ALPHA[bits & 31] + out
        bits >>= 5
    return out


def _unb64(text, most=4096):
    if not isinstance(text, str) or len(text) > most:
        raise ValueError("bad")
    return _b64.b64decode(text, validate=True)


def check_chain(rid, opk_b64, chain):
    """
    Walk from the owner's key to the device's key. Returns the device's
    public key (raw bytes) or None. Rules, the same as the app's:
      - the room code must be the owner key's code
      - each link is signed by the key before it
      - only the owner, or a key the owner made an 'issuer', may sign
        a link; a plain member cannot vouch for anybody
      - at most two links
    """
    try:
        key = _unb64(opk_b64)
        if room_code(key) != rid or not isinstance(chain, list) or len(chain) > 2:
            return None
        may_sign = True
        for link in chain:
            if not may_sign or not isinstance(link, dict):
                return None
            body = _unb64(link.get("b"))
            sig = _unb64(link.get("s"))
            if not p256_verify(key, sig, body):
                return None
            info = _json.loads(body.decode("utf-8"))
            if info.get("v") != 1 or info.get("rid") != rid:
                return None
            role = info.get("role")
            if role not in ("issuer", "member"):
                return None
            key = _unb64(info.get("pk"))
            may_sign = (role == "issuer")
        # A chain that ends on an issuer is a signing key, not a person.
        if chain and may_sign:
            return None
        return key
    except Exception:
        return None


# --- challenges and passes ---------------------------------------------------
#
# The secret below is made fresh every time this program starts and
# is never written down. A restart therefore cancels every pass, and
# the app simply proves itself again - which is the whole point of
# keeping nothing.

_ROOM_SECRET = _secrets.token_bytes(32)
NONCE_LIFE = 300
PASS_LIFE = 3600


def _mac(text):
    return _hmac.new(_ROOM_SECRET, text.encode(), _hashlib.sha256).hexdigest()


# Each challenge is random and is accepted once. The list of used
# ones lives only as long as the secret above, so losing it on a
# restart loses nothing: every older challenge dies with the secret.
_USED = {}


def room_nonce():
    ts = str(int(_time.time()))
    fresh = _secrets.token_hex(12)
    return ts + "." + fresh + "." + _mac("nonce|" + ts + "|" + fresh)


def _nonce_ok(nonce):
    try:
        ts, fresh, tag = nonce.split(".")
        if not _hmac.compare_digest(tag, _mac("nonce|" + ts + "|" + fresh)):
            return False
        if not 0 <= _time.time() - int(ts) <= NONCE_LIFE:
            return False
        with _LOCK:
            now = _time.time()
            for k in [k for k, t in _USED.items() if t < now]:
                del _USED[k]
            if nonce in _USED:
                return False
            _USED[nonce] = now + NONCE_LIFE + 5
        return True
    except Exception:
        return False


def room_pass(rid, who):
    exp = str(int(_time.time()) + PASS_LIFE)
    base = rid + "." + who + "." + exp
    return base + "." + _mac("pass|" + base)


def pass_room(token):
    """The room a pass is good for, or None."""
    try:
        rid, who, exp, tag = token.split(".")
        base = rid + "." + who + "." + exp
        if not _hmac.compare_digest(tag, _mac("pass|" + base)):
            return None
        if _time.time() > int(exp):
            return None
        return rid
    except Exception:
        return None


def room_auth(row):
    """Returns (reply, code)."""
    rid = str(row.get("rid") or "")[:20]
    nonce = str(row.get("nonce") or "")[:200]
    if not _nonce_ok(nonce):
        return {"error": "stale", "why": "That challenge has expired. Try again."}, 401
    leaf = check_chain(rid, row.get("opk"), row.get("chain"))
    if leaf is None:
        return {"error": "refused", "why": "Not a member of this room."}, 403
    try:
        sig = _unb64(row.get("sig"))
    except Exception:
        return {"error": "refused", "why": "Not a member of this room."}, 403
    if not p256_verify(leaf, sig, ("enigma/relay/auth/v1|" + rid + "|" + nonce).encode()):
        return {"error": "refused", "why": "Not a member of this room."}, 403
    who = _hashlib.sha256(leaf).hexdigest()[:16]
    return {"ok": True, "pass": room_pass(rid, who), "life": PASS_LIFE}, 200


# --- what rooms hold -----------------------------------------------------------

ROOM_SAID = {}            # rid -> list of {"n", "body", "at"}
ROOM_NEXT = {}            # rid -> next number
ROOM_KEEP_FOR = 60 * 60
ROOM_KEEP_BYTES = 40 * 1024 * 1024
ROOM_TOO_LONG = 1200000
ROOM_MARK = "-----ENIGMA ROOM-----"


def room_tidy():
    now = _time.time()
    total = 0
    for rid in list(ROOM_SAID):
        rows = [r for r in ROOM_SAID[rid] if now - r["at"] <= ROOM_KEEP_FOR]
        if rows:
            ROOM_SAID[rid] = rows
            total += sum(len(r["body"]) for r in rows)
        else:
            del ROOM_SAID[rid]
    # Over the byte cap: drop the oldest rows anywhere until under it.
    while total > ROOM_KEEP_BYTES:
        oldest = min(ROOM_SAID, key=lambda k: ROOM_SAID[k][0]["at"])
        gone = ROOM_SAID[oldest].pop(0)
        total -= len(gone["body"])
        if not ROOM_SAID[oldest]:
            del ROOM_SAID[oldest]


def room_say(token, row):
    rid = pass_room(token or "")
    if not rid:
        return {"error": "pass", "why": "Prove membership again."}, 401
    if row.get("rid") != rid:
        return {"error": "refused", "why": "That pass is for another room."}, 403
    body = row.get("body")
    if not isinstance(body, str) or not body.startswith(ROOM_MARK):
        return {"error": "Not a locked room message. Nothing was sent."}, 400
    if len(body) > ROOM_TOO_LONG:
        return {"error": "Too long to pass on."}, 413
    with _LOCK:
        room_tidy()
        n = ROOM_NEXT.get(rid, 1)
        ROOM_NEXT[rid] = n + 1
        ROOM_SAID.setdefault(rid, []).append(
            {"n": n, "body": body, "at": _time.time()})
    return {"ok": True, "n": n}, 200


def room_poll(token, rid, since, wait_up_to):
    if pass_room(token or "") != rid or not rid:
        return {"error": "pass", "why": "Prove membership again."}, 401
    waited = 0.0
    while True:
        with _LOCK:
            room_tidy()
            out = [r for r in ROOM_SAID.get(rid, []) if r["n"] > since]
            nxt = ROOM_NEXT.get(rid, 1)
        if out or waited >= wait_up_to:
            # "next" lets a device that missed a restart notice the
            # numbering began again, and start counting from zero.
            return {"said": out, "next": nxt}, 200
        _time.sleep(0.4)
        waited += 0.4


def room_get(path, token, wait_up_to):
    """Handles GET /r/... Returns (reply, code) or None if not ours."""
    if path.startswith("/r/nonce"):
        return {"nonce": room_nonce()}, 200
    if path.startswith("/r/poll"):
        q = path.split("?", 1)[1] if "?" in path else ""
        args = dict(p.split("=", 1) for p in q.split("&") if "=" in p)
        try:
            since = int(args.get("since", "0"))
        except ValueError:
            since = 0
        return room_poll(token, args.get("rid", "")[:20], since, wait_up_to)
    return None


def room_post(path, token, row):
    """Handles POST /r/... Returns (reply, code) or None if not ours."""
    if path == "/r/auth":
        return room_auth(row)
    if path == "/r/say":
        return room_say(token, row)
    return None
# ===========================================================================
# END ROOMS
# ===========================================================================


class Relay(http.server.BaseHTTPRequestHandler):

    def log_message(self, *args):
        # No record of who said how much to whom, or when. A log is a
        # transcript with the words taken out, and that is still a
        # transcript.
        pass

    def cors(self):
        # The app runs from each person's own machine and talks to
        # this from there, so the browser needs telling that is
        # allowed. Nothing here is worth protecting by origin - it is
        # locked text either way.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Access")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def reply(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The listener closed Enigma while its request was still
            # being held. That is the ordinary way a conversation
            # ends, not a fault, and there is nobody left to tell.
            pass

    def room_post_here(self):
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            size = 0
        if size > ROOM_TOO_LONG + 4096:
            left = size
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)
            self.reply({"error": "Too long to pass on."}, 413)
            return
        try:
            row = json.loads(self.rfile.read(size) or b"{}")
            if not isinstance(row, dict):
                raise ValueError
        except Exception:
            self.reply({"error": "That made no sense."}, 400)
            return
        got = room_post(self.path, self.headers.get("X-Access"), row)
        if got is None:
            self.reply({"error": "No such thing here."}, 404)
        else:
            self.reply(*got)

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.end_headers()

    def do_GET(self):
        tidy()
        if self.path.startswith("/r/"):
            got = room_get(self.path, self.headers.get("X-Access"), WAIT_UP_TO)
            if got is None:
                self.reply({"error": "No such thing here."}, 404)
            else:
                self.reply(*got)
            return
        if self.path.startswith("/room"):
            try:
                since = int(self.path.split("since=")[1].split("&")[0])
            except Exception:
                since = 0
            mark = ""
            if "mark=" in self.path:
                mark = self.path.split("mark=")[1].split("&")[0][:40]

            # Wait for something rather than asking over and over.
            #
            # Asking every second looks harmless until you count it:
            # ten people idling is twenty-nine million requests a
            # month and ten gigabytes of nothing. Holding the request
            # open until there is news costs one request every half
            # minute instead, and delivers the moment a message lands
            # rather than up to a second later.
            waited = 0.0
            while waited < WAIT_UP_TO:
                out = [r for r in SAID if r["n"] > since
                       and (not mark or r.get("mark") == mark)]
                if out:
                    self.reply({"said": out, "next": NEXT[0]})
                    return
                time.sleep(0.4)
                waited += 0.4
            self.reply({"said": [], "next": NEXT[0]})
        elif self.path in ("/", "/alive"):
            self.reply({"ok": True, "relay": True, "version": RELAY_VERSION,
                        "holding": len(SAID), "held_bytes": held_bytes(),
                        "rooms": True,
                        "says": "A post box. It cannot read what it holds."})
        else:
            self.reply({"error": "No such thing here."}, 404)

    def do_POST(self):
        tidy()
        if self.path.startswith("/r/"):
            self.room_post_here()
            return
        if self.path != "/say":
            self.reply({"error": "No such thing here."}, 404)
            return
        try:
            size = int(self.headers.get("Content-Length") or 0)
            if size > TOO_LONG:
                # Refusing is not enough: the sender is still pushing
                # bytes, and replying without taking them snaps the
                # connection. What reaches the app then is a broken
                # pipe, not the sentence below, so a message that was
                # merely too long looks like the relay falling over.
                # Take the bytes, throw them away, then say no.
                left = size
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                self.reply({"error": "Too long to pass on. Send it in "
                                     "smaller pieces."}, 413)
                return
            row = json.loads(self.rfile.read(size) or b"{}")
        except Exception:
            self.reply({"error": "That made no sense."}, 400)
            return

        body = row.get("body") or ""
        # Locked or nothing. This is the one rule the relay enforces,
        # and it is here so that a bug in the app cannot put plain
        # words on somebody else's computer.
        if not body.lstrip().startswith("-----ENIGMA"):
            self.reply({"error": "Not a locked message. Nothing was sent."})
            return

        name = (row.get("from") or "").strip()[:40]
        device = (row.get("device") or "").strip()[:64]
        mark = (row.get("mark") or "").strip()[:40]
        if not (name and device and mark):
            self.reply({"error": "Tune in and pick a name first."})
            return

        # Names are no longer the relay's business.
        #
        # This used to refuse a name already in use, because the name
        # beside a message was all anyone had to go on. It is not any
        # more: the sender's name is sealed inside the encryption,
        # where this relay cannot see it or change it, and the app
        # shows that one.
        #
        # Meanwhile the check could be turned around. Anyone holding
        # this address - no frequency, no code word - could post once
        # under your name and lock you out of it for fifteen minutes.
        # A rule that no longer protects anything, and can be used
        # against the people it was meant to help, is worth deleting.

        SAID.append({"n": NEXT[0], "from": name, "mark": mark,
                     "body": body, "at": time.time()})
        NEXT[0] += 1
        self.reply({"ok": True, "n": NEXT[0] - 1})


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # Someone closing the app mid-request printed a full traceback
        # every time. Over a day that buries anything that matters in
        # a log nobody can then read. Expected partings stay quiet;
        # everything else is still reported.
        kind = sys.exc_info()[0]
        if kind is not None and issubclass(
                kind, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            return
        super().handle_error(request, client_address)


if __name__ == "__main__":
    print("Enigma relay v%s listening on %d" % (RELAY_VERSION, PORT))
    print("It holds locked messages for an hour and cannot read any of them.")
    Threaded(("0.0.0.0", PORT), Relay).serve_forever()
