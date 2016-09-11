#!/usr/bin/env python3
#
# extract and fix frames from buggy apng animation
#

# https://github.com/eight04/pyAPNG
import apng

from struct import pack, unpack

# patch the buggy picture sizes
def fix(w, h, i):
    if w == 1280:
        w, h = 180, 75
    if w > 200:
        w //= 10
    if h > 100:
        h //= 10
    if i == 17:
        w, h = 180, 73
    return w, h

im = apng.APNG.open("p1ng")
i = 0
for png, control in im.frames:
    w, h = unpack(">I", png.chunks[0][1][8:12])[0], unpack(">I", png.chunks[0][1][12:16])[0]
    w, h = fix(w, h, i)
    png.chunks[0] = ('IHDR', apng.make_chunk("IHDR", pack(">I", w) + pack(">I", h) + b'\x08\x06\x00\x00\x00'))
    png.save("%02d.png" % i)
    i += 1
