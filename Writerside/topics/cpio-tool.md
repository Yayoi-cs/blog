# kernel exploit tool

## cpio tools
I created a tool to simplify the process when solving kernel exploits.
It automatically launches a shell with root privileges via cpio for testing purposes, and it also automatically adjusts file permissions after extraction, which is useful since cpio files are extracted with root privileges but can be cumbersome to edit.
You can use it when working on kernel exploits.

### extract
```sh
#!/bin/bash

# detect cpio
cpios=(*.cpio)
if [ ${#cpios[@]} -eq 0 ]; then
    echo "No cpio files found"
    exit 1
fi
echo "available cpio files:"
for i in ${!cpios[@]}; do
    echo "$i) ${cpios[$i]}"
done
echo "Select cpio file to extract:"
read -r cpio_index
cpio_file=${cpios[$cpio_index]}
echo "[*]Extracting $cpio_file ........"

# Extract the cpio archive
mkdir out
cd out
sudo cpio -idv < ../$cpio_file
sudo getfacl -R . > ../perm.acl
user=$(whoami)
sudo chown -R $user:$user .
cd ..

echo "[*]Extraction complete"
echo "Start to PWN!!!"
```

### archive

```sh
#!/bin/bash

cp -r out tmp
cd out
sudo setfacl --restore ../perm.acl
sudo find . -print0 | sudo cpio -o --format=newc --null > ../archive.cpio
cd ..
sudo rm -rf out
mv tmp out

echo "[*]Archive created -> archive.cpio"
```

## exploit sender

```py
#!/usr/bin/env python3

from pwn import *
import base64
import os
import random
import sys
import tqdm

s   = lambda b: io.send(b)
sa  = lambda a,b: io.sendafter(a,b)
sl  = lambda b: io.sendline(b)
sla = lambda a,b: io.sendlineafter(a,b)
r   = lambda : io.recv()
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
shell = lambda : io.interactive()
cmd = lambda x : sla(b"#",str(x).encode()) if root else sla(b"$",str(x).encode())

expdir = os.getcwd()
if len(sys.argv) <= 1:
    print("Usage: python3 exploit-sender [exploit]")
    exit()
if len(sys.argv) >= 2:
    chall = os.path.join(expdir,sys.argv[1])
if len(sys.argv) == 3 and sys.argv[2] == "root":
    root = True
else:
    root = False

if not os.path.exists(chall):
    print("File not found")
    exit()

instance = input("nc: ")
HOST = "127.0.0.1"
PORT = 9999

if len(instance) == 0:
    pass
elif "nc" not in instance:
    HOST = instance.split(" ")[0]
    PORT = int(instance.split(" ")[1])
else:
    HOST = instance.split(" ")[1]
    PORT = int(instance.split(" ")[2])

with open(chall, "rb") as f:
    content = f.read()
    encoded = base64.b64encode(content).decode()

io = remote(HOST, PORT)

sl(b"uname -a")
sleep(1)
print(rl().decode())
cmd("cd /tmp")
log.progress("Sending exploit")
randstr = "".join(random.choices(string.ascii_letters + string.digits, k=4))
for i in tqdm.tqdm(range(0, len(encoded), 256)):
    cmd(f"echo {encoded[i:i+256]} >> exploit{randstr}.b64")

cmd(f"base64 -d exploit{randstr}.b64 > exploit")
cmd("chmod +x exploit")
#cmd("rm exploit.b64")

shell()
```

## common qemu run.sh
```sh
#!/bin/sh
qemu-system-x86_64 \
    -serial tcp:127.0.0.1:9999,server,nowait \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1" \
    -no-reboot \
    -cpu qemu64 \
    -gdb tcp::12345 \
    -smp 1 \
    -monitor /dev/null \
    -initrd archive.cpio \
    -net nic,model=virtio \
    -net user
```
