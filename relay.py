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

# A name belongs to one device within one channel. The channel is
# known only by its three-word mark, which is computed from the
# frequency and says nothing about it.
TAKEN = {}
HOLD_FOR = 15 * 60


def held_bytes():
    return sum(len(r["body"]) for r in SAID)


def tidy():
    now = time.time()
    while SAID and (now - SAID[0]["at"] > KEEP_FOR
                    or len(SAID) > KEEP_MOST
                    or held_bytes() > KEEP_BYTES):
        SAID.pop(0)
    for held, (who, when) in list(TAKEN.items()):
        if now - when > HOLD_FOR:
            del TAKEN[held]


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
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def reply(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.end_headers()

    def do_GET(self):
        tidy()
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
            self.reply({"ok": True, "relay": True, "holding": len(SAID),
                        "says": "A post box. It cannot read what it holds."})
        else:
            self.reply({"error": "No such thing here."}, 404)

    def do_POST(self):
        tidy()
        if self.path != "/say":
            self.reply({"error": "No such thing here."}, 404)
            return
        try:
            size = int(self.headers.get("Content-Length") or 0)
            if size > 1200000:
                self.reply({"error": "Too long to pass on."}, 413)
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

        held = TAKEN.get((mark, name.lower()))
        if held and held[0] != device:
            self.reply({"error": "Somebody on this frequency is already "
                                 "called " + name + ". Pick another name."})
            return
        TAKEN[(mark, name.lower())] = (device, time.time())

        SAID.append({"n": NEXT[0], "from": name, "mark": mark,
                     "body": body, "at": time.time()})
        NEXT[0] += 1
        self.reply({"ok": True, "n": NEXT[0] - 1})


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print("Enigma relay listening on %d" % PORT)
    print("It holds locked messages for an hour and cannot read any of them.")
    Threaded(("0.0.0.0", PORT), Relay).serve_forever()
