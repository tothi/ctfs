# [ASIS CTF Final 2016](https://asis-ctf.ir): p1ng

**Category:** Forensic
**Points:** 121
**Solves:** 38
**Description:**

> [p1ng](http://asis-ctf.ir/tasks/p1ng.txz_76eca77720a65d95557a3850929abd0a8a18c636) is ASIS hand-drawn PNG.

## writeup

This challenge is a simple PNG disassemble -> fix -> assemble workflow.

The challenge [txz archive](./p1ng.txz_76eca77720a65d95557a3850929abd0a8a18c63)
contains only the file [p1ng](./p1ng).
Identifying it with the command `file` gives this info:
```
p1ng: PNG image data, 180 x 76, 8-bit/color RGBA, non-interlaced
```
Displaying it we can read just the text "ASIS" in that 180x76 image:

![p1ng](./p1ng)

However, the image surely contains much more data, its size
is 152521 bytes. So observing the binary structure of the
file should be the next step. Using the common tool
[pngtools](http://www.stillhq.com/pngtools/) is obvious.
With `pngchunks`:
```
Chunk: Data Length 13 (max 2147483647), Type 1380206665 [IHDR]
  Critical, public, PNG 1.2 compliant, unsafe to copy
  IHDR Width: 180
  IHDR Height: 76
  IHDR Bitdepth: 8
  IHDR Colortype: 6
  IHDR Compression: 0
  IHDR Filter: 0
  IHDR Interlace: 0
  IHDR Compression algorithm is Deflate
  IHDR Filter method is type zero (None, Sub, Up, Average, Paeth)
  IHDR Interlacing is disabled
  Chunk CRC: -1005806266
Chunk: Data Length 8 (max 2147483647), Type 1280598881 [acTL]
  Ancillary, private, PNG 1.2 compliant, unsafe to copy
  ... Unknown chunk type
  Chunk CRC: -1272059488
Chunk: Data Length 26 (max 2147483647), Type 1280598886 [fcTL]
  Ancillary, private, PNG 1.2 compliant, unsafe to copy
  ... Unknown chunk type
  Chunk CRC: 974435056
Chunk: Data Length 4834 (max 2147483647), Type 1413563465 [IDAT]
  Critical, public, PNG 1.2 compliant, unsafe to copy
  IDAT contains image data
  Chunk CRC: 43362484
Chunk: Data Length 26 (max 2147483647), Type 1280598886 [fcTL]
  Ancillary, private, PNG 1.2 compliant, unsafe to copy
  ... Unknown chunk type
  Chunk CRC: 2075814227
Chunk: Data Length 4447 (max 2147483647), Type 1413571686 [fdAT]
  Ancillary, private, PNG 1.2 compliant, unsafe to copy
  ... Unknown chunk type
  Chunk CRC: -1209790397
  ...
  ...
  ...
```
(`[fcTL]` and `[fdAT]` repeats several times until the chunk [IEND].)

According to this chunk structure, this is not a simple PNG
file but an [APNG (Animated PNG)](https://en.wikipedia.org/wiki/APNG).
But if we want to display it using an appropriate viewer, there
is no animation, just the basic image above with the text "ASIS".
Therefore, (if it is really an APNG) it may be corrupted.

So there are two methods to read the information in that APNG:

* fix the APNG structure in place
* extract the frames from the APNG (and bundle the data into simple PNG files)

We choose the latter.

To get it work, we should be familiar with PNG and APNG chunk structures.
The best resources to read are the official specifiations:

* [PNG (Portable Network Graphics) Specification, Version 1.2](http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html)
* [APNG 1.0 Specification](https://wiki.mozilla.org/APNG_Specification)

These documents describe the chunks in detail. The most important for us
is that `[fdAT]` contains the frame data, and it is the same as `[IDAT]`
in static PNG files, except it is preceded by a sequence number.

Another important thing is that `[fcTL]` contains the width and height
of the frame `[fdAT]` (like `[IHDR]` for `[IDAT]`.

Splitting the PNG chunks is easy by using `pngsplit` from the tool
[pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html). This
way it is possible to extract the frames and build a PNG from
a frame manually using the above informations from the specifications.

Note, that the image sizes in the `[fcTL]` chunks are corrupted in some cases
(e.g. it is `1800x76` in `[fcTL]` and the correct size is `180x76`).
The size should be corrected, otherwise the image can not be displayed.

Also note, that we need to care about the CRC values in the modified header
chunks. Calculating the CRC values is trivial by using `pngcheck`,
unfortunately it is needed to update the values manually.

Displaying the fixed and assembled PNG file reveals some
letters of the flag, so the above method has been confirmed.

Of course what we have done manually should be scripted.
And of course the best scripting language for this (and every ;) )
hacking task is Python. Owing to a developer called
[eight04](https://github.com/eight04), there is a nice
python module called [pyAPNG](https://github.com/eight04/pyAPNG)
to deal with APNG files.

Using this module, scripting the APNG disassembling, fixing the
sizes and assembling each frame to a separate PNG file is
a cake-walk (we should know only some minimal about the
PNG structures, e.g. we do not need to care about CRC, etc.).

[Here](./xtract_frames.py) is the magic:
```python
#!/usr/bin/env python3
#
# xtract_frames.py:
#
# extract and fix frames from the corrupted apng animation
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
```

This script takes `p1ng` and produces the `xx.png` files which are
the extracted frames in order. Displaying the output PNG files in
order gives the flag. Of course the graceful method is not displaying
the images one by one (or using some GUI tool to get thumbnails quickly),
but montaging them using [ImageMagick](http://www.imagemagick.org/):
```
montage *.png -tile 23x1 flag.png
```

Here is the output [flag.png](./flag.png):

![flag.png](flag.png)

In ascii text:
```
ASIS{As_l0n9_4s_CTF_3x1sts_th3r3_w1ll_b3_ASIS_4nd_4s_l0n9_4s_ASIS_3x1sts_th3r3_w1ll_b3_PNG!}
```

The challenge has been solved with [metiu07](https://github.com/metiu07)
in the great CTF team [OpenToAll](https://ctftime.org/team/9135).

