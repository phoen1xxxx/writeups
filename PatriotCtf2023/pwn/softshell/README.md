## Softshell [expert]
In this task we have a some different vulnerabilities which we should find using reverse engineering.
First is:
```
cmdStruct* add_cmd(cmdStruct* cmd){
    ...
    cmdStruct* buf;

    for (i = 0; command[i] != '\0'; i += 1) {
        if (command[i] == ' ') {
            buf->words_num = buf->words_num + 1;
        }
    }


    word = strtok(command," ");
    ppcVar3 = (char **)malloc(8);
    buf->args = ppcVar3;
    while (word != (char *)0x0) {
        ppcVar3 = (char **)realloc(buf->args,(long)(i + 1) * 8);
        buf->args = ppcVar3;
        len = strlen(word);
        ppcVar3 = buf->args;
        pcVar2 = (char *)malloc(len + 1);
        ppcVar3[i] = pcVar2;
        strcpy(buf->args[i],word);
        i += 1;
        word = strtok((char *)0x0," ");
    }
    ...
}
```
words_num is a field in cmdStruct structure which count words in command. Code we see uses ' ' as delim to count number of words, allocate chunks and put words there using strtok. Vulnerability is that strtok ignores lot of space symbols, but words count part of code doesn't ingore it. So we can get value words_num bigger, than amount of words.
We can use it in function del args.

```
void del_arg(int index,structX *cmd)

{
  structX *cmd_x;
  
  cmd_x = cmd->next;
  if (currIndex < index) {
    puts("\nInvalid index!");
  }
  else {
    for (; (cmd_x != (structX *)0x0 && (index != cmd_x->index)); cmd_x = cmd_x->next) {
    }
    free(cmd_x->args[(long)cmd_x->words_num + -1]);
    cmd_x->words_num = cmd_x->words_num + -1;
  }
  return;
}
```
This function frees arg at index words_num-1. So we can get oob free. In the debugger I ve found that in heap at index 15 there are chunk for command tag, that we can change using edit_tag function.
```
void run_cmd(cmdStruct* cmd){
    ...
    iVar2 = strcmp(current_cmd->command,allowed);
    if (iVar2 == 0) {
      __pid = fork();
      if (__pid == 0) {
        execvp(*current_cmd->args,current_cmd->args);
        perror("execvp");
      }
      else if (__pid != -1) {
        waitpid(__pid,(int *)0x0,0);
      }
    }
}
```
run_cmd function execute commands with args (in args buffef) if the command==/usr/games/cowsay. So we can use arbitrary free to free tag chunks and put there parsed arguments. Then we rewrites it to /bin/sh -, using UAF(edit_tag function) but command buffer wont change. 
