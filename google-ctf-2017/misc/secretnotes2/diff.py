#!/usr/bin/python
#

import sqlite3

conn = sqlite3.connect('./notes.db')
c = conn.cursor()

s = ""

# diffs of flag.txt is in ID range 98..267
for i in range(98, 267+1):
    c.execute('SELECT Insertion, IDX, Diff FROM Diff WHERE ID=%d' % i)
    (b, idx, diff) = c.fetchone()
    if b == 1:
        s = s[:idx] + diff + s[idx:]
    if b == 0:
        s = s[:idx] + s[idx+len(diff):]
    print "---=== ID: %d ===---\n%s" % (i, s)
    
