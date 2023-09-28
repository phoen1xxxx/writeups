## Rop
In this task we have a common stack overflow and no one useful gadjets to prepare registers
=)

All source code:
```
void main() {
  char buf[0x10];
  system("echo Enter something:");
  gets(buf);
}
```
Main idea is overwrite rbp to bss and then write /bin/sh to it and call jump to system.Main trouble we have that leave instruction makes stack pivoting with our rbp and after just writing string to bss we have stack pointer near our string payload and push intruction ar start of system function overwrites payload :( So after writing our string we must use stack pivoting gadjets such as pop rbp ret; leave ret; to move stack pointer at another adress. After this we get shell.

