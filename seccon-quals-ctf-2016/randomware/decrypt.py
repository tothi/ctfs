#!/usr/bin/python3
#

key = [b'\x00']*0x400
enc = open('./home/tc/h1dd3n_s3cr3t_f14g.jpg', 'rb').read()
dec = b''

f2 = 'blocklist.xml'
c2 = open('./home/tc/.mozilla/firefox/wir5mrmb.default/' + f2, 'rb').read()
p2 = open('./firefox/browser/' + f2, 'rb').read()

for i in range(len(key)):
    key[i] = bytes([p2[i] ^ c2[i]])

for i in range(len(enc)):
    dec += bytes([enc[i] ^ ord(key[i%len(key)])])

open('./f14g_decrypted.jpg', 'wb').write(dec)
