#!/usr/bin/python
#
# des decryptor for sans2019 elfscrow
#

# date: December 6, 2019, between 7pm and 9pm UTC.

from Crypto.Cipher import DES
from tqdm import tqdm
import binascii
from datetime import datetime

ENCFILE = "ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf.enc"
PLAINFILE = "ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf"

def unpad(p):
    pad = p[-1]
    for i in range(pad):
        assert p[-1-i] == pad
    return p[:-pad]

def generate_key(seed):
    key = []
    rnd = seed
    for i in range(8):
        rnd = rnd * 0x343fd + 0x269ec3
        key.append((rnd >> 0x10 & 0x7ffff) & 0xff)
    return bytes(key)

def get_seed_range():
    a = (datetime(2019,12,6,19,0,0) - datetime(1970, 1, 1)).total_seconds()
    b = (datetime(2019,12,6,21,0,0) - datetime(1970, 1, 1)).total_seconds()
    return range(int(a), int(b))

if __name__ == "__main__":
    encdata = open(ENCFILE, "rb").read()
    for seed in tqdm(get_seed_range()):
        key = generate_key(seed)
        cipher = DES.new(key, DES.MODE_CBC, b'\x00'*8)
        plain = cipher.decrypt(encdata)
        try:
            plain = unpad(plain)
            assert plain.startswith(b'%PDF')
            open(PLAINFILE, "wb").write(plain)
            break
        except:
            pass

    
