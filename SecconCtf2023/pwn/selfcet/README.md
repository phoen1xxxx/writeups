##  Selfcet 
In this task we have common stack overflow vulnerability in the read_member function:

```
read_member(&ctx, offsetof(ctx_t, key), sizeof(ctx));

void read_member(ctx_t *ctx, off_t offset, size_t size) {

  if (read(STDIN_FILENO, (void*)ctx + offset, size) <= 0) {

    ctx->status = EXIT_FAILURE;

    ctx->error = "I/O Error";
  }

  ctx->buf[strcspn(ctx->buf, "\n")] = '\0';

  if (ctx->status != 0)
    CFI(ctx->throw)(ctx->status, ctx->error);
}

#define KEY_SIZE 0x20
typedef struct {
  char key[KEY_SIZE];
  char buf[KEY_SIZE];
  const char *error;
  int status;
  void (*throw)(int, const char*, ...);
} ctx_t;



```
We can read sizeof(ctx)(88 bytes) into the char array of 0x20 size. And we have function pointer throw in the ctx structure which we can overwrite. But there are one issue: CFI check. It checks first 4 bytes of function and if it's not endebr64 it breaks. So we cant use one gadjets. But at start we have throw pointer to the err libc function. So we can overwrite3 low bytes of the function to another libc function and in some cases it will works (part-aslr bruteforce). So we can call gets function and put bss section adress as the argument and then write /bin/sh to it/ Then we can call system with this adress. This bruteforce will be so fast because we need brute just part of three bytes.
