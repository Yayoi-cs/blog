# Libc-got-overwrite
<primary-label ref="pwn"/>

楽してshellを取りたい.

glibc-2.35でgot-overwriteをしてrdi,rsiが制御できそうな関数をまとめる.

また,後日one-gadgetが刺さりそうな関数についてもまとめたい.

### strtok
```c
char buf[] = "/bin/sh";
strtok(buf, "/");
```

rdiがwritableでなければならない.
```c
[*] testcase 9: strspn                  
[+] Overwrite [0x7db47321a058] 0x7db473198800 -> 0x56452dc3e31e
[*] callBack Executed.
RDI: 0x7fffa38e6b96 HEX: 3168732f6e69622f STR: "/bin/sh1" 
RSI: 0x56452dc3f0bb HEX: 4f475b5b5b5b002f STR: "/" 

[*] testcase 31: strcspn                 
[+] Overwrite [0x7db47321a108] 0x7db4731985a0 -> 0x56452dc3e31e
[*] callBack Executed.
RDI: 0x7fffa38e6ad7 HEX: 3168732f6e6962 STR: "bin/sh1" 
RSI: 0x56452dc3f0bb HEX: 4f475b5b5b5b002f STR: "/" 
```

| .got    | register |
|---------|----------|
| strspn  | rdi, rsi |
| strcspn | rdi, rsi |

### puts
```c
puts("/bin/sh");
```
`memmove`は直前のstdoutの内容がrdiに入る.
また,`printf("/bin/sh")`,及び`printf("%s","/bin/sh");"`でも同じ

```C
[*] testcase 6: __mempcpy               
[+] Overwrite [0x7360e081a040] 0x7360e07a0710 -> 0x5c53777902de
[*] callBack Executed.
RDI: 0x5c53b2dbf2a0 HEX: 357830203a494452 STR: "RDI: 0x5c53b2dbf2a0 HEX: 357830203a494452 STR: " 0x5c53777902de
" 
RSI: 0x5c53777910bb HEX: 68732f6e69622f STR: "/bin/sh"

[*] testcase 17: strlen                  
[+] Overwrite [0x7360e081a098] 0x7360e079d7e0 -> 0x5c53777902de
[*] callBack Executed.
RDI: 0x5c53777910bb HEX: 68732f6e69622f STR: "/bin/sh"
```

|.got| register  |
|-|-----------|
|memmove| rsi (rdi) |
|strlen| rdi       |

### getenv

```c
getenv("/bin/sh");
```

rdiに素直に入る.
```c
[*] testcase 17: strlen                  
[+] Overwrite [0x71762261a098] 0x71762259d7e0 -> 0x63a855bb631e
[*] callBack Executed.
RDI: 0x63a855bb70bb HEX: 68732f6e69622f STR: "/bin/sh"
```

|.got| register  |
|-|-----------|
|strlen| rdi       |

### calloc

```C
calloc(0x50, 1);
```

**0x50以上をアロケートすると**memmoveが呼ばれる.
rdiにはbinsのnextが入るのでrdiを完全に操作するにはnextフィールドに対してUAFが必要.

ログではsafe-linkingされたnextの値が入った.
```c
[*] testcase 47: memset                  
[+] Overwrite [0x7a0ac501a188] 0x7a0ac4fa0f00 -> 0x64ee89cd131e
[*] callBack Executed.
RDI: 0x64ee8d169a90 HEX: 64ee8d169 STR: "i��N" 
```

## Fuzz code
```c
#include <assert.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char got_list[54][25] = {
    "strnlen                 ",
    "__rawmemchr             ",
    "__libc_realloc          ",
    "strncasecmp             ",
    "_dl_exception_create    ",
    "__mempcpy               ",
    "wmemset                 ",
    "__libc_calloc           ",
    "strspn                  ",
    "memchr                  ",
    "memmove                 ",
    "wmemchr                 ",
    "__stpcpy                ",
    "wmemcmp                 ",
    "_dl_find_dso_for_object ",
    "strncpy                 ",
    "strlen                  ",
    "__strcasecmp_l          ",
    "strcpy                  ",
    "wcschr                  ",
    "strchrnul               ",
    "memrchr                 ",
    "_dl_deallocate_tls      ",
    "__tls_get_addr          ",
    "wmemset                 ",
    "bcmp                    ",
    "__strncasecmp_l         ",
    "_dl_fatal_printf        ",
    "strcat                  ",
    "wcscpy                  ",
    "strcspn                 ",
    "__strcasecmp            ",
    "strncmp                 ",
    "wmemchr                 ",
    "__stpncpy               ",
    "wcscmp                  ",
    "_dl_audit_symbind_alt   ",
    "memmove                 ",
    "rindex                  ",
    "index                   ",
    "wcschr                  ",
    "memcpy                  ",
    "_dl_rtld_di_serinfo     ",
    "_dl_allocate_tls        ",
    "__tunable_get_val       ",
    "wcslen                  ",
    "memset                  ",
    "wcsnlen                 ",
    "strcmp                  ",
    "_dl_allocate_tls_init   ",
    "__nptl_change_stack_perm",
    "strpbrk                 ",
    "_dl_audit_preinit       ",
    "strnlen                 ",
};

unsigned long *got_plt_start;
unsigned long *got_plt_end;

unsigned long globalPtr;
int globalIdx;

static jmp_buf context;

void fuzzer(int arg);

void sigsegvHandler(int sig) {
    puts("[-]SIGSEGV ***INVALID ADDRESS***");
    longjmp(context, 1);
}

void restore(int idx,unsigned long ptr) {
    got_plt_start[idx] = ptr;
}

void tryAccess(void *ptr) {
    if (setjmp(context) == 0) {
        fflush(stdout);
        printf("HEX: %lx ",*(unsigned long *)ptr);
        printf("STR: \"%s\" ",(char *)ptr);
        puts("");
    } else {
        signal(SIGSEGV, sigsegvHandler);
        fuzzer(globalIdx+1);
    }
}


void callBack(void *rdi, void *rsi, void *rdx, void *rcx) {
    restore(globalIdx, globalPtr);
    puts("[*] callBack Executed.");
    printf("RDI: %p ",rdi);
    tryAccess(rdi);
    printf("RSI: %p ",rsi);
    tryAccess(rsi);
    printf("RDX: %p ", rdx);
    tryAccess(rdx);
    printf("RCX: %p ", rcx);
    tryAccess(rcx);
}

unsigned long overWrite(int idx) {
    unsigned long res = got_plt_start[idx];
    printf("[+] Overwrite [0x%lx] 0x%lx -> 0x%lx\n",(unsigned long)&got_plt_start[idx],res,(unsigned long)callBack);
    got_plt_start[idx] = (unsigned long)callBack;
    return res;
}


void fuzzer(int arg) {
    for (int i= arg;i < 54;i++) {
        printf("[*] testcase %d: %s\n",i+1,got_list[i]);
        globalPtr = overWrite(i);
        globalIdx = i;
        
        puts("/bin/sh");

        restore(i, globalPtr);
    }
}

int main(void) {
    signal(SIGSEGV, sigsegvHandler);
    puts("[[[[GOT-FUZZER]]]]");
    got_plt_start = (unsigned long *)((0x7ffff7c00000+0x00000000021a018)-0x7ffff7c80e50+puts);
    got_plt_end = (unsigned long *)((0x7ffff7c00000+0x00000000021a1c0)-0x7ffff7c80e50+puts);
    fuzzer(0);
}
```

## 検証した関数
```C
strlen
strcpy
strcat
strcmp
strchr
strstr
strtok

atoi
printf
puts
fopen
memchr
memcmp
memcpy
memmove
memset

getenv
```