#!/usr/bin/env python3
#
# Hungarian Cyber Security Challenge 2020 Qualifiers
#
# Challenge "Baseline test" solution
#

import sqlite3
import time
from pwn import *

# for local testing (make sure /srv/flag.txt is available locally for flawless experience)
# c = process("./test")

# for remote action
CHALLENGE_HOST = "0123456789abcde0123456789abcde0123456789"
CHALLENGE_PASS = "0123456789abcdef"
h = CHALLENGE_HOST + ".platform-next-alt.avatao-challenge.com"
s = ssh(host=h, user="user", password=CHALLENGE_PASS, proxy_command="openssl s_client -connect {}:443 -servername {}".format(h, h))
c = s.process("./test")

pre = c.recvuntil('played.\n\n')
log.info(pre.decode())
m = c.recvuntil("little box?\n")
st = time.time()
a = "Cells."
c.sendline(a)
log.success("Q: {}, sent A: {} in {:.5f} secs".format(' '.join(m.decode().strip().split(' ')[2:]), a, time.time()-st))

a = "Interlinked."
for i in range(6):
    m = c.recvuntil("?\n")
    st = time.time()
    c.sendline(a)
    log.success("Q: {}, sent A: {} in {:.5f} secs".format(' '.join(m.decode().strip().split(' ')[2:]), a, time.time()-st))
    
dbconn = sqlite3.connect("./rainbow.db")
db = dbconn.cursor()

for i in range(7):
    c.recvuntil(' ')
    c.recvuntil(' ')
    m = c.recvline().strip().decode()
    st = time.time()
    db.execute("SELECT text FROM hashes WHERE hash=?", (m,))
    a = db.fetchone()[0]
    c.sendline(a)
    log.success("Q: {}, sent A: {} in {:.5f} secs".format(m, a, time.time()-st))

flag = c.recvline().decode().strip().split(' ')[2]
log.success("the FLAG is: {}".format(flag))
