#!/usr/bin/env python2
#
# rescue data from RAID5 manually
# on a 3-disk array with 1 drive failure
#

import os

# stripe size in bytes
STRIPE = 512

# get size and calc num of stripes (rounds)
s = os.path.getsize("./deadnas/disk0")
rounds = s/STRIPE/3

# the two undamaged disks
d0 = open("./deadnas/disk0", "r")
d2 = open("./deadnas/disk2", "r")

# output disk
out = open("./disk_rescue", "w")

# xor strings (bytearrays)
def sxor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))
    
n = 0
while n <= rounds:

    # parity on disk2
    block = d0.read(STRIPE)
    out.write(block)
    out.write(sxor(block, d2.read(STRIPE)))

    # parity on disk1
    out.write(d0.read(STRIPE))
    out.write(d2.read(STRIPE))

    # parity on disk0
    block = d2.read(STRIPE)
    out.write(sxor(block, d0.read(STRIPE)))
    out.write(block)

    n += 1

d0.close()
d2.close()
out.close()
