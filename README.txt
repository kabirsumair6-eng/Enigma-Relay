ENIGMA RELAY
============

A post box on the internet. It takes locked messages, holds them for
an hour, and hands them back. That is the whole job.

It cannot read anything it holds. It is never told a frequency or a
code word and has no way to work either out, so what it stores is
exactly what somebody tapping the wire would get. That is why it
does not much matter who runs it.

It also serves no part of the app. Enigma itself stays on your own
machine, where nobody can change it. A relay that turned hostile
could drop your messages or count them; it could not read them and
could not hand you different code.


Putting it somewhere
--------------------

It is one file, it needs Python 3, and it needs nothing else. No
packages, no database, no configuration. Anywhere that runs Python
will take it:

  Render        new Web Service, start command: python3 relay.py
  Railway       new project from a repo, same command
  Fly.io        fly launch, it will notice the Python
  A small VPS   python3 relay.py, behind nginx or not

All of those have free tiers that are plenty for this. See
LAUNCH.txt for the steps on one of them, click by click.

The free tiers are plenty for this - it holds a
few hundred short messages at a time and forgets them within the
hour.

It listens on $PORT if that is set, which all of the above set for
you, and 8080 otherwise.


Pointing Enigma at it
---------------------

In Enigma: Settings, Post box, put the address in - for example

    https://your-thing.onrender.com

Press Test. It should say "reachable". Everyone you talk to puts in
the same address, and from then on the frequency works between
cities rather than between rooms.

Leave the box empty and everything stays as it was: this machine and
whatever wifi it is sharing with.


What it keeps, and for how long
-------------------------------

Locked messages, for one hour, up to forty megabytes of them -
counted in bytes, not in messages, because two thousand typed lines
and two thousand photographs are not the same weight. Then they are
gone. It writes nothing to disk and keeps no log - a log of who sent
how much to whom is a transcript with the words removed, and that is
still a transcript.

It holds a name against a device for fifteen minutes so that two
people on one frequency cannot both be Masood. The name is in the
clear; use one you do not mind a stranger seeing.


What it refuses
---------------

Anything that is not already locked. If something that is not an
Enigma message arrives, it is rejected rather than passed on, so a
mistake in the app cannot put plain words on somebody else's screen.
