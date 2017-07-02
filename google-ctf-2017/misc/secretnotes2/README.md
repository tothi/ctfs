# [Google CTF 2017](https://capturetheflag.withgoogle.com) : Secret Notes 2

**Category:** Miscellaneous
**Points:** 189 (dynamic)
**Solves:** 56
**Difficulty:** Medium
**Description:**

> There is a DIFFerent flag, can you find it?

## writeup

The challenge is a sequel to `Secret Notes`.
We have obtained a private db file [notes.db](./notes.db)
there which contained a simple flag in a table
called `FLAG`. The challenge description here says
that there should be another flag there, probably in
the same SQLite db.

The challenge had been solved in the great team
[OpenToAll](https://ctftime.org/team/9135).
The team finished 30th in the competition.

### browsing the db

Exploring the SQLite db `notes.db`:

```
$ sqlite3 notes.db 
SQLite version 3.17.0 2017-02-13 16:02:40
Enter ".help" for usage hints.
sqlite> .tables
Diff              FLAG              Notes           
DiffSet           NoteSet           android_metadata
sqlite> .schema Diff
CREATE TABLE Diff (ID INTEGER PRIMARY KEY, Insertion BOOLEAN, IDX INTEGER, Diff STRING(255), DiffSet ID);
sqlite> .schema DiffSet
CREATE TABLE DiffSet (ID INTEGER PRIMARY KEY, Note STRING(255));
```

The challenge description ("DIFFerent") hints us to search
the flag somewhere near the Diff table.

### understanding Diff

To get familiar with the Diff (and DiffSet) table structure,
we may have a look at the client app [NotesApp.apk](./NotesApp.apk),
but it is not necessary. The Diff structure can be guessed easily.

The point is that not just the notes get stored, but all the
diffs in every editing step. According to the schema, every Diff
entry has an ID, an Insertion flag (0 in case of removal, 1
in case of addition), an IDX index value (position in the edited string),
a Diff string and a DiffSet ID.

DiffSets are described in the DiffSet table with the DiffSet ID and
a Note title.

### locating the flag

Looking at the DiffSets:

```
sqlite> select * from DiffSet;
1|Groceries
2|Groceries
3|Groceries
...
36|flag.txt
37|flag.txt
38|flag.txt
...
72|flag.txt
73|flag.txt
74|flag.txt
```

So DiffSet IDs `36..74` refer to `flag.txt`. We should
get the full editing history of note `flag.txt` from
table `Diff`.

### diff entries

Selecting the Diff entries related to `flag.txt`:

```
sqlite> select * from Diff where DiffSet>=36 and DiffSet<=74;
98|1|0|cat flag|36
99|1|8| one flag two flag|37
100|1|26|
red flag blue flag|38
101|1|45| blue flag|39
102|0|36|blue |39
103|1|35|s
red|39
104|1|34|re son|39
105|0|31|fl|39
106|0|29|d|39
...
264|1|69| Your flag is not here. |72
265|1|87|longer |73
266|0|85|t|73
267|0|0|And so thus ends the story we have told together. This is the finale. |74
```

Quick (manual) intro of the diff mechanism:

Diff ID | operation | position | diff string | note string
------- | --------- | -------- | ----------- | -----------
98 | addition | 0  | "cat flag" | "cat flag"
99 | addition | 8  | " one flag two flag" | "cat flag one flag two flag"
100| addition | 26 | "\nred flag blue flag" | "cat flag one flag two flag\nred flag blue flag"
101| addition | 45 | " blue flag" | "cat flag one flag two flag\nred flag blue flag blue flag"
102| removal | 36 | "blue " | "cat flag one flag two flag\nred flag flag blue flag"
103| addition | 35 | "s\nred" | "cat flag one flag two flag\nred flags\nred flag blue flag"
104| addition | 34 | "re son" | "cat flag one flag two flag\nred flare songs\nred flag blue flag"
105| removal | 31 | "fl" | "cat flag one flag two flag\nred are songs\nred flag blue flag"
106| removal | 29 | "d" | "cat flag one flag two flag\nre are songs\nred flag blue flag"

### scripting the diffs

Let us script the Diff reconstruction in order to see
the full history of the `flag.txt` note.

```python
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
    
```

Executing [diff.py](./diff.py) shows the full history of
`flag.txt`:

```
---=== ID: 98 ===---
cat flag
---=== ID: 99 ===---
cat flag one flag two flag
---=== ID: 100 ===---
cat flag one flag two flag
red flag blue flag
---=== ID: 101 ===---
cat flag one flag two flag
red flag blue flag blue flag
---=== ID: 102 ===---
cat flag one flag two flag
red flag flag blue flag

...

---=== ID: 244 ===---
ctfighters, {puZZ1e_As_old_as_t. Ime}
---=== ID: 245 ===---
ctfighters, {puZZ1e_As_old_as_tIme}
---=== ID: 246 ===---
ctf{puZZ1e_As_old_as_tIme}
---=== ID: 247 ===---
ctf{puZZ1e_As_old_as_The finale.tIme}
---=== ID: 248 ===---
ctf{puZZ1e_As_old_as_inale.tIme}
---=== ID: 249 ===---
ctf{puZZ1e_As_o thusf{puZZ1e_As_old_as_inale.tIme}

...

---=== ID: 266 ===---
And so thuslends the story we have le.1old_As_old_This is the finale} Your flag is no longer here. 
---=== ID: 267 ===---
Your flag is no longer here. 
```

Taking a look at the history, it can be seen that
the `flag.txt` note at `ID:246` matches the flag format:

```
ctf{puZZ1e_As_old_as_tIme}
```

