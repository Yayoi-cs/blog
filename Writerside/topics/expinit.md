# expinit

expinit is one of my original tool to initialize environment for binary exploit.

> [](https://github.com/Yayoi-cs/expinit)

```bash
[~/dc/ctf/tools] >>>tree expinit/
expinit/
├── e.py
└── expinit.py

0 directories, 2 files
```

```py
#!/usr/bin/env python3

from pwn import *
import os
import subprocess
import termios
import tty

libc = "/usr/lib/x86_64-linux-gnu/libc.so.6"
ld = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"

def isElf(fp):
    try:
        result = subprocess.run(["file", fp], capture_output=True, text=True)
        return "ELF" in result.stdout
    except Exception as e:
        log.error(e)
        return False

def executable(fp):
    return os.access(fp, os.X_OK) and not os.path.isdir(fp)

def listelf(directory):
    challs = []
    libcs = []
    lds = []

    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        
        if os.path.isfile(file_path) and isElf(file_path):
            if executable(file_path) and '.' not in file:
                challs.append(file_path)
            elif "libc" in file:
                libcs.append(file_path)
            elif "ld" in file:
                lds.append(file_path)

    return {
        "chall": challs,
        "libc": libcs,
        "ld": lds
    }

def gc(message:str)->str:
    print(f"[?]{message}",end=" (y/n)")
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ret = sys.stdin.read(1).strip()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        print("")
    return ret

if __name__ == "__main__":
    chaldir = os.getcwd()
    elfs = listelf(chaldir)

    elf = ""
    for e in elfs["chall"]:
        match gc(f"chall candidate:{e}"):
            case "y":
                elf = e
                break
            case "n":
                continue

    if len(elfs["libc"]) == 0:
        match gc(f"using default libc:{libc}"):
            case "y":
                libc = libc
            case "n":
                libc = ""
    else:
        for l in elfs["libc"]:
            match gc(f"libc candidate:{l}"):
                case "y":
                    libc = l
                    break
                case "n":
                    continue

    if len(elfs["ld"]) == 0:
        match gc(f"using default ld:{ld}"):
            case "y":
                ld = ld 
            case "n":
                ld = ""
    else:
        for l in elfs["ld"]:
            match gc(f"ld candidate:{l}"):
                case "y":
                    ld = l
                    break
                case "n":
                    continue

    nc = input("[?]remote server:")
    HOST:str = "127.0.0.1"
    PORT:int = 9999
    if nc == "":
        pass
    elif len(nc)!=0:
        if "nc" in nc:
            HOST = nc.split(" ")[1]
            PORT = int(nc.split(" ")[2])
        else:
            HOST = nc.split(" ")[0]
            PORT = int(nc.split(" ")[1])
    else:
        print(f"✅ using default config (127.0.0.1:9999)")
    
    swaplist = {
        "__ELFPATH":elf.replace(chaldir+"/",""),
        "__LIBCPATH":libc.replace(chaldir+"/",""),
        "__LDPATH":ld.replace(chaldir+"/",""),
        "__HOST":HOST,
        "__PORT":str(PORT)
    }

    selfdir = os.path.dirname(os.path.abspath(__file__))
    source = os.path.join(selfdir, "e.py")
    dest = os.path.join(chaldir, "e.py")
    with open(source, "r") as fd, open(dest, "w") as exp:
        for l in fd:
            for k,v in swaplist.items():
                l = l.replace(k, v)
            exp.write(l)
    tools = {
        "VScode":"/usr/share/code/code",
        "BinaryNinja":"~/dc/ctf/tools/binaryninja/binaryninja",
        "IDA":"~/idafree-8.4/ida64"
    }
    for k,v in tools.items():
        if gc(f"Open {k}?") == "y":
            if k == "VScode":
                os.system(f"{v} e.py &")
            else:
                os.system(f"{v} {elf} &")

    print("✅ finish!")
```

## exploit outline
```py
from pwn import *
import sys

e = ELF("__ELFPATH",checksec=False)
libc = ELF("__LIBCPATH",checksec=False)
ld = ELF("__LDPATH",checksec=False)

nc = "nc __HOST __PORT"
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
```
