#!/usr/bin/env python3

from pwn import *
from hashlib import *
import itertools as it
from base64 import b64encode, b64decode

#r = remote('localhost', 8282)
r = remote('srpp.asis-ctf.ir', 22778)

### brute forcing entry challenge
print()
log.info('##### brute forcing entry challenge started')

r.recvuntil('SHA512(X + "')
plain = r.recvuntil('"')[:-1].decode('ascii')
log.info('plain is "????%s"' % plain)
r.recvuntil('"')
digest = r.recvuntil('...')[:-3].decode('ascii')
log.info('sha512 digest starts with %s' % digest)
r.recvuntil('Enter X: ')

with log.progress('brute forcing sha512 hash') as logp:
    for prefix in it.product(string.ascii_letters + string.digits, repeat=4):
        prefix = ''.join(prefix)
        m = sha512()
        m.update((prefix + plain).encode('ascii'))
        if m.hexdigest().startswith(digest):
            logp.success('plain prefix is %s' % prefix)
            break

r.sendline(prefix)
if r.recvline().decode('ascii').startswith('Good work'):
    log.success('anti-bot challenge bypassed')

### srpp part
print()
log.info('##### SRPP challenge started')

# read email address
r.recvuntil('"')
email = r.recvuntil('"')[:-1].decode('ascii')
log.info('email is "%s"' % email)

# read params (N, g, k)
r.recvuntil('params = (N, g, k) = (')
N = int(r.recvuntil('L,')[:-2].decode('ascii'))
r.recvuntil(' ')
g = int(r.recvuntil(',')[:-1].decode('ascii'))
r.recvuntil(' ')
k = int(r.recvuntil('L)')[:-2].decode('ascii'))
r.recvline()
r.recvline()
log.info('(N = %d, g = %d, k = %d)' % (N, g, k))

# send email and A param
A = 2*N
r.sendline('%s, %d' % (email, A))
log.info('sent email = "%s" and A = 2*N = %d' % (email, A))

# get (salt, public_ephemeral)
r.recvuntil('(salt,  public_ephemeral) = (')
salt = b64decode(r.recvuntil(',')[:-1].decode('ascii')).decode('latin_1')
r.recvuntil(' ')
B = int(r.recvuntil(')')[:-1])
log.info('(salt = %s, B = %d)' % (b64encode(salt.encode('latin_1')).decode('ascii'), B))
r.recvline()
r.recvline()

def Hash(*args):
    a = ':'.join(str(a) for a in args).encode('latin_1')
    return int(sha256(a).hexdigest(), 16)

K_client = Hash(0)
log.info('sending K_client = H(0) = %d' % K_client)
r.sendline(str(K_client))

r.recvline()
M_client = Hash(Hash(N) ^ Hash(g), Hash(email), salt, A, B, K_client)
log.info('sending M_client = %d' % M_client)
r.sendline(str(M_client))

resp = r.recvall().decode('ascii')
r.close()

print()
print(resp)

# Great, you got the flag: ASIS{7bdb4b540699ef341f4a3b32469cd3f6}
